// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <memory>
#include <utility>

// APSU
#include "apsu/network/receiver_operation.h"
#include "apsu/network/zmq/zmq_channel.h"
#include "apsu/oprf/oprf_receiver.h"
#include "apsu/receiver_ddh.h"
#include "apsu/receiver_db.h"

namespace apsu {
    namespace receiver {
        /**
        The ZMQReceiverDispatcher is in charge of handling incoming requests through the network.
        */
        class ZMQReceiverDispatcher {
        public:
            ZMQReceiverDispatcher() = delete;

            /**
            Creates a new ZMQReceiverDispatcher object. This constructor accepts both a ReceiverDB
            object, as well as a separately provided OPRF key. It uses the provided OPRF key to
            respond to OPRF requests, instead of attempting to retrieve a key from the ReceiverDB.
            This is necessary, for example, when the ReceiverDB is stripped, in which case it no
            longer carries a valid OPRF key.
            */
            ZMQReceiverDispatcher(std::shared_ptr<ReceiverDB> receiver_db, oprf::OPRFKey oprf_key,Receiver receiver);
            ZMQReceiverDispatcher(std::shared_ptr<ReceiverDB> receiver_db,Receiver receiver);
            /**
            Creates a new ZMQReceiverDispatcher object. This constructor accepts a ReceiverDB object. It
            attempts to retrieve an OPRF key from the ReceiverDB and uses it to serve OPRF requests.
            This constructor cannot be used if the ReceiverDB is stripped, because the OPRF key is no
            longer available through the ReceiverDB.
            */
            ZMQReceiverDispatcher(std::shared_ptr<ReceiverDB> receiver_db);

            /**
            Run the dispatcher on the given port.
            */
            void run(const std::atomic<bool> &stop, int port);

        private:
            std::shared_ptr<receiver::ReceiverDB> receiver_db_;

            oprf::OPRFKey oprf_key_;

            Receiver receiver_;
            
            /**
            Dispatch a Get Parameters request to the Receiver.
            */
            void dispatch_parms(
                std::unique_ptr<network::ZMQReceiverOperation> rop,
                network::ZMQReceiverChannel &channel);

  

            /**
            Dispatch a Query request to the Receiver.
            */
            void dispatch_query(
                std::unique_ptr<network::ZMQReceiverOperation> rop,
                network::ZMQReceiverChannel &channel);

            void dispatch_re(
                std::unique_ptr<network::ZMQReceiverOperation> rop,
                network::ZMQReceiverChannel &channel);

        }; // class ZMQReceiverDispatcher
    }      // namespace receiver
} // namespace apsu
