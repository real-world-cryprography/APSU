// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

// APSU
#include "apsu/network/channel.h"
#include "apsu/network/receiver_operation.h"
#include "apsu/oprf/oprf_sender.h"
#include "apsu/query.h"
#include "apsu/requests.h"
#include "apsu/responses.h"
#include "apsu/receiver_db.h"
#include "apsu/permute/apsu_OSNReceiver.h"

#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Timer.h>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/Base/BaseOT.h"

#include "coproto/Socket/AsioSocket.h"

namespace apsu {
    namespace receiver {
        // An alias to denote the powers of a receiver's ciphertext. At index i, holds Cⁱ, where C
        // is the ciphertext. The 0th index is always a dummy value.
        using CiphertextPowers = std::vector<seal::Ciphertext>;

        namespace {
            template <typename T>
            inline void hash_combine(std::size_t &seed, const T &val)
            {
                seed ^= std::hash<T>()(val) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            }
            // auxiliary generic functions to create a hash value using a seed
            template <typename T>
            inline void hash_val(std::size_t &seed, const T &val)
            {
                hash_combine(seed, val);
            }
            template <typename T, typename... Types>
            inline void hash_val(std::size_t &seed, const T &val, const Types &...args)
            {
                hash_combine(seed, val);
                hash_val(seed, args...);
            }

            template <typename... Types>
            inline std::size_t hash_val(const Types &...args)
            {
                std::size_t seed = 0;
                hash_val(seed, args...);
                return seed;
            }

            struct pair_hash {
                template <class T1, class T2>
                std::size_t operator()(const std::pair<T1, T2> &p) const
                {
                    return hash_val(p.first, p.second);
                }
            };

        }
        /**
        The Receiver class implements all necessary functions to process and respond to parameter,
        OPRF, and PSU or labeled PSU queries (depending on the receiver). Unlike the Receiver class,
        Receiver also takes care of actually sending data back to the receiver. Receiver is a static
        class and cannot be instantiated.

        Like the Receiver, there are two ways of using the Receiver. The "simple" approach supports
        network::ZMQChannel and is implemented in the ZMQReceiverDispatcher class in
        zmq/receiver_dispatcher.h. The ZMQReceiverDispatcher provides a very fast way of deploying an
        APSU Receiver: it automatically binds to a ZeroMQ socket, starts listening to requests, and
        acts on them as appropriate.

        The advanced Receiver API consisting of three functions: RunParams, RunOPRF, and RunQuery. Of
        these, RunParams and RunOPRF take the request object (ParamsRequest or OPRFRequest) as
        input. RunQuery requires the QueryRequest to be "unpacked" into a Query object first.

        The full process for the receiver is as follows:

        (1) Create a PSUParams object that is appropriate for the kinds of queries the receiver is
        expecting to serve. Create a ReceiverDB object from the PSUParams. The ReceiverDB constructor
        optionally accepts an existing oprf::OPRFKey object and samples a random one otherwise. It
        is recommended to construct the ReceiverDB directly into a std::shared_ptr, as the Query
        constructor (see below) expects it to be passed as a std::shared_ptr<ReceiverDB>.

        (2) The receiver's data must be loaded into the ReceiverDB with ReceiverDB::set_data. More data
        can always be added later with ReceiverDB::insert_or_assign, or removed with ReceiverDB::remove,
        as long as the ReceiverDB has not been stripped (see ReceiverDB::strip).

        (3 -- optional) Receive a parameter request with network::Channel::receive_operation. The
        received Request object must be converted to the right type (ParamsRequest) with the
        to_params_request function. This function will return nullptr if the received request was
        not of the right type. Once the request has been obtained, the RunParams function can be
        called with the ParamsRequest, the ReceiverDB, the network::Channel, and optionally a lambda
        function that implements custom logic for sending the ParamsResponse object on the channel.

        (4) Receive an OPRF request with network::Channel::receive_operation. The received Request
        object must be converted to the right type (OPRFRequest) with the to_oprf_request function.
        This function will return nullptr if the received request was not of the right type. Once
        the request has been obtained, the RunOPRF function can be called with the OPRFRequest, the
        oprf::OPRFKey, the network::Channel, and optionally a lambda function that implements custom
        logic for sending the OPRFResponse object on the channel.

        (5) Receive a query request with network::Channel::receive_operation. The received Request
        object must be converted to the right type (QueryRequest) with the to_query_request
        function. This function will return nullptr if the received request was not of the correct
        type. Once the request has been obtained, a Query object must be created from it. The
        constructor of the Query class verifies that the QueryRequest is valid for the given
        ReceiverDB, and if it is not the constructor still returns successfully but the Query is
        marked as invalid (Query::is_valid() returns false) and cannot be used in the next step.
        Once a valid Query object is created, the RunQuery function can be used to perform the query
        and respond on the given channel. Optionally, two lambda functions can be given to RunQuery
        to provide custom logic for sending the QueryResponse and the ResultPart objects on the
        channel.
        */
        class Receiver {
        private:
            /**
            The most basic kind of function for sending an APSU message on a given channel. This
            function can be used unless the channel requires encapsulating the raw APSU messages,
            e.g., for including routing information or a digital signature. For example,
            network::ZMQChannel cannot use BasicSend; see zmq/receiver_dispatcher.cpp for another
            example of a send function that works with the ZMQChannel.
            */
            template <typename T>
            static void BasicSend(network::Channel &chl, std::unique_ptr<T> pkg)
            {
                chl.send(std::move(pkg));
            }

        public:
            Receiver(){
                ans.clear();
                pack_cnt = 0;
                item_cnt = 0;
                random_map.clear();
                random_after_permute_map.clear();
                random_plain_list.clear();
                
            };


            void setSocket(oc::Socket& chls_in){
                ReceiverChl = chls_in;
            }
#if ARBITARY == 0

#else
            void set_item_len(size_t in){
                item_len = (in+15)/16;
            }
            size_t get_item_len(){
                return item_len;
            }
#endif

            /**
            Generate and send a response to a parameter request.
            */
            void RunParams(
                const ParamsRequest &params_request,
                std::shared_ptr<ReceiverDB> receiver_db,
                network::Channel &chl,
                std::function<void(network::Channel &, Response)> send_fun =
                    BasicSend<Response::element_type>);


            /**
            Generate and send a response to a query.
            */
            void RunQuery(
                const Query &query,
                network::Channel &chl,
                std::function<void(network::Channel &, Response)> send_fun =
                    BasicSend<Response::element_type>,
                std::function<void(network::Channel &, ResultPart)> send_rp_fun =
                    BasicSend<ResultPart::element_type>
                );


            
            
            void RunResponse(
                const plainRequest &params_request, network::Channel &chl,const PSUParams &params_);
        
            void RunOT();
#if CARDSUM == 1
            void Cardsum_receiver();
#endif
        private:
            /**
            Method that handles computing powers for a given bundle index
            */
             void ComputePowers(
                const std::shared_ptr<ReceiverDB> &receiver_db,
                const CryptoContext &crypto_context,
                std::vector<std::vector<seal::Ciphertext>> &powers,
                const PowersDag &pd,
                std::uint32_t bundle_idx,
                seal::MemoryPoolHandle &pool);

            /**
            Method that processes a single Bin Bundle cache.
            Sends a result package through the given channel.
            */
            void ProcessBinBundleCache(
                const std::shared_ptr<ReceiverDB> &receiver_db,
                const CryptoContext &crypto_context,
                std::reference_wrapper<const BinBundleCache> cache,
                std::vector<CiphertextPowers> &all_powers,
                network::Channel &chl,
                std::function<void(network::Channel &, ResultPart)> send_rp_fun,
                std::uint32_t bundle_idx,
                seal::compr_mode_type compr_mode,
                seal::MemoryPoolHandle &pool,
                std::uint32_t cache_idx,
                std::uint32_t pack_idx
                );
            //static std::unordered_map<std::pair<std::uint32_t, std::uint32_t>, std::vector<uint64_t>, pair_hash > random_map;
            std::uint32_t pack_cnt;
            std::vector<uint64_t> ans;
            std::uint64_t item_cnt;
            int send_size,recv_size;
           
            std::vector<std::vector<uint64_t> > random_map;
            std::vector<seal::Plaintext> random_plain_list;
            std::vector<uint64_t > random_after_permute_map;

            oc::Socket ReceiverChl;
#if ARBITARY == 0

#else
            size_t item_len;
#endif

            //static std::vector<uint64_t> match_record;
        }; // class Receiver
       
        //std::unordered_map<std::pair<std::uint32_t, std::uint32_t>, std::vector<uint64_t>, pair_hash > Receiver::random_map = {};
    }      // namespace receiver
} // namespace apsu
