// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <thread>

// APSU
#include "apsu/log.h"
#include "apsu/oprf/oprf_receiver.h"
#include "apsu/requests.h"
#include "apsu/zmq/receiver_dispatcher_osn.h"

// SEAL
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsu {
    using namespace network;
    using namespace oprf;

    namespace receiver {
        ZMQReceiverDispatcher::ZMQReceiverDispatcher(shared_ptr<ReceiverDB> receiver_db, OPRFKey oprf_key,Receiver receiver)
            : receiver_db_(move(receiver_db)), oprf_key_(move(oprf_key)), receiver_()
        {
            
            
            if (!receiver_db_) {
                throw invalid_argument("receiver_db is not set");
            }

            // If ReceiverDB is not stripped, the OPRF key it holds must be equal to the provided
            // oprf_key
            if (!receiver_db_->is_stripped() && oprf_key_ != receiver_db->get_oprf_key()) {
                APSU_LOG_ERROR("Failed to create ZMQReceiverDispatcher: ReceiverDB OPRF key differs "
                               "from the given OPRF key");
                throw logic_error("mismatching OPRF keys");
            }
        }
        ZMQReceiverDispatcher::ZMQReceiverDispatcher(shared_ptr<ReceiverDB> receiver_db,Receiver receiver)
            : receiver_db_(move(receiver_db)), receiver_()
        {
#if ARBITARY == 0
            
#else
            receiver_.set_item_len(receiver.get_item_len()*16);
#endif
            
            if (!receiver_db_) {
                throw invalid_argument("receiver_db is not set");
            }
     
        }
        ZMQReceiverDispatcher::ZMQReceiverDispatcher(shared_ptr<ReceiverDB> receiver_db)
            : receiver_db_(move(receiver_db))
        {

            
            if (!receiver_db_) {
                throw invalid_argument("receiver_db is not set");
            }

            try {
                oprf_key_ = receiver_db_->get_oprf_key();
            } catch (const logic_error &ex) {
                APSU_LOG_ERROR("Failed to create ZMQReceiverDispatcher: missing OPRF key");
                throw;
            }
        }

        void ZMQReceiverDispatcher::run(const atomic<bool> &stop, int port)
        {
            ZMQReceiverChannel chl;

            stringstream ss;
            ss << "tcp://*:" << port;
           
            APSU_LOG_INFO("ZMQReceiverDispatcher listening on port " << port);
            chl.bind(ss.str());
         
            auto seal_context = receiver_db_->get_seal_context();

            // Run until stopped
            bool logged_waiting = false;
            while (!stop) {
                unique_ptr<ZMQReceiverOperation> rop;
                if (!(rop = chl.receive_network_operation(seal_context))) {
                    if (!logged_waiting) {
                        // We want to log 'Waiting' only once, even if we have to wait
                        // for several sleeps. And only once after processing a request as well.
                        logged_waiting = true;
                        APSU_LOG_INFO("Waiting for request from Sender");
                    }
                   
                    this_thread::sleep_for(50ms);
                    continue;
                }

                switch (rop->rop->type()) {
                    
                case ReceiverOperationType::rop_parms:
                    APSU_LOG_INFO("Received parameter request");
                    dispatch_parms(move(rop), chl);
                    break;

     

                case ReceiverOperationType::rop_query:
                    APSU_LOG_INFO("Received query");
                    dispatch_query(move(rop), chl);
                    return ;
                    break;
                case ReceiverOperationType::rop_response:
                    APSU_LOG_INFO("Received response");
                    dispatch_re(move(rop), chl);
                    break;
                default:
                    // We should never reach this point
                    //std::cout << (int)(rop->rop->type()) << endl;
                    throw runtime_error("invalid operation");
                }

                logged_waiting = false;
            }
        }

        void ZMQReceiverDispatcher::dispatch_parms(
            unique_ptr<ZMQReceiverOperation> rop, ZMQReceiverChannel &chl)
        {
            STOPWATCH(recv_stopwatch, "ZMQReceiverDispatcher::dispatch_params");

            try {
                // Extract the parameter request
                ParamsRequest params_request = to_params_request(move(rop->rop));

                receiver_.RunParams(
                    params_request,
                    receiver_db_,
                    chl,
                    [&rop](Channel &c, unique_ptr<ReceiverOperationResponse> rop_response) {
                        auto nrop_response = make_unique<ZMQReceiverOperationResponse>();
                        nrop_response->rop_response = move(rop_response);
                        nrop_response->client_id = move(rop->client_id);

                        // We know for sure that the channel is a ReceiverChannel so use static_cast
                        static_cast<ZMQReceiverChannel &>(c).send(move(nrop_response));
                    });
            } catch (const exception &ex) {
                APSU_LOG_ERROR(
                    "Receiver threw an exception while processing parameter request: " << ex.what());
            }
        }


        void ZMQReceiverDispatcher::dispatch_query(
            unique_ptr<ZMQReceiverOperation> rop, ZMQReceiverChannel &chl)
        {
            STOPWATCH(recv_stopwatch, "ZMQReceiverDispatcher::dispatch_query");

            try {
                // Create the Query object
                Query query(to_query_request(move(rop->rop)), receiver_db_);

                // Query will send result to client in a stream of ResultPackages (ResultParts)
                receiver_.RunQuery(
                    query,
                    chl,
                    // Lambda function for sending the query response
                    [&rop](Channel &c, Response response) {
                        auto nrop_response = make_unique<ZMQReceiverOperationResponse>();
                        nrop_response->rop_response = move(response);
                        nrop_response->client_id = rop->client_id;

                        // We know for sure that the channel is a ReceiverChannel so use static_cast
                        static_cast<ZMQReceiverChannel &>(c).send(move(nrop_response));

                    },
                    // Lambda function for sending the result parts
                    [&rop](Channel &c, ResultPart rp) {
                        auto nrp = make_unique<ZMQResultPackage>();
                        nrp->rp = move(rp);
                        nrp->client_id = rop->client_id;

                        // We know for sure that the channel is a ReceiverChannel so use static_cast
                        static_cast<ZMQReceiverChannel &>(c).send(move(nrp));
                    } 
                    );
            } catch (const exception &ex) {
                APSU_LOG_ERROR("Receiver threw an exception while processing query: " << ex.what());
            }
        }
        void ZMQReceiverDispatcher::dispatch_re(
            unique_ptr<ZMQReceiverOperation> rop, ZMQReceiverChannel& chl)
        {
            try {
                plainRequest response = to_plain_request(move(rop->rop));
                
                PSUParams params_ = receiver_db_->get_params();
                receiver_.RunResponse(response, chl, move(params_));

            } catch (const exception &ex) {
                APSU_LOG_ERROR("Receiver threw an exception while processing response: " << ex.what());
            }
        }


    } // namespace receiver
} // namespace apsu
