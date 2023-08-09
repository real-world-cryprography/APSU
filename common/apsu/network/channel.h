// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

// APSU
#include "apsu/network/result_package.h"
#include "apsu/network/receiver_operation.h"
#include "apsu/network/receiver_operation_response.h"

// SEAL
#include "seal/util/defines.h"

namespace apsu {
    namespace network {
        /**
        Channel is an interfacate to implement a communication channel between a sender and a
        receiver. It keeps track of the number of bytes sent and received.
        */
        class Channel {
        public:
            /**
            Create an instance of a Channel.
            */
            Channel() : bytes_sent_(0), bytes_received_(0)
            {}

            /**
            Destroy an instance of a Channel.
            */
            virtual ~Channel()
            {}

            /**
            Send a ReceiverOperation from a receiver to a sender. These operations represent either a
            parameter request, an OPRF request, or a query request. The function throws an exception
            on failure.
            */
            virtual void send(std::unique_ptr<ReceiverOperation> rop) = 0;

            /**
            Receive a ReceiverOperation from a receiver. Operations of type rop_query and rop_unknown
            require a valid seal::SEALContext to be provided. For operations of type rop_parms and
            rop_oprf the context can be set as nullptr. The function returns nullptr on failure.
            */
            virtual std::unique_ptr<ReceiverOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                ReceiverOperationType expected = ReceiverOperationType::rop_unknown) = 0;

            /**
            Send a ReceiverOperationResponse from a sender to a receiver. These operations represent a
            response to either a parameter request, an OPRF request, or a query request. The
            function throws and exception on failure.
            */
            virtual void send(std::unique_ptr<ReceiverOperationResponse> rop_response) = 0;

            /**
            Receive a ReceiverOperationResponse from a sender. The function returns nullptr on
            failure.
            */
            virtual std::unique_ptr<ReceiverOperationResponse> receive_response(
                ReceiverOperationType expected = ReceiverOperationType::rop_unknown) = 0;

            /**
            Send a ResultPackage to a receiver. The function throws and exception on failure.
            */
            virtual void send(std::unique_ptr<ResultPackage> rp) = 0;

            /**
            Receive a ResultPackage from a sender. A valid seal::SEALContext must be provided. The
            function returns nullptr on failure.
            */
            virtual std::unique_ptr<ResultPackage> receive_result(
                std::shared_ptr<seal::SEALContext> context) = 0;

            /**
            Returns the number of bytes sent on the channel.
            */
            std::uint64_t bytes_sent() const
            {
                return bytes_sent_;
            }

            /**
            Returns the number of bytes received on the channel.
            */
            std::uint64_t bytes_received() const
            {
                return bytes_received_;
            }

        protected:
            std::atomic<std::uint64_t> bytes_sent_;

            std::atomic<std::uint64_t> bytes_received_;
        }; // class Channel
    }      // namespace network
} // namespace apsu
