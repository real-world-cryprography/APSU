// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <iostream>
#include <memory>
#include <mutex>

// APSU
#include "apsu/network/channel.h"
#include "apsu/network/result_package.h"
#include "apsu/network/receiver_operation.h"
#include "apsu/network/receiver_operation_response.h"

namespace apsu {
    namespace network {
        /**
        StreamChannel is a communication channel between a sender and a receiver through a C++
        stream. No data is actually sent, but instead saved to a std::stringstream that can be
        accessed to get the data. This allows downstream applications to use any custom networking
        solution.
        */
        class StreamChannel : public Channel {
        public:
            StreamChannel() = delete;

            /**
            Create an instance of a StreamChannel using the given input and output streams.
            */
            StreamChannel(std::istream &in, std::ostream &out) : in_(in), out_(out)
            {}

            /**
            Create an instance of a StreamChannel using the given stream for input and output.
            */
            StreamChannel(std::iostream &stream) : StreamChannel(stream, stream)
            {}

            /**
            Destroy an instance of a StreamChannel.
            */
            ~StreamChannel()
            {}

            /**
            Send a ReceiverOperation from a receiver to a sender. These operations represent either a
            parameter request, an OPRF request, or a query request. The function throws an exception
            on failure.
            */
            void send(std::unique_ptr<ReceiverOperation> rop) override;

            /**
            Receive a ReceiverOperation from a receiver. Operations of type rop_query and rop_unknown
            require a valid seal::SEALContext to be provided. For operations of type rop_parms and
            rop_oprf the context can be set as nullptr. The function returns nullptr on failure.
            */
            std::unique_ptr<ReceiverOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                ReceiverOperationType expected = ReceiverOperationType::rop_unknown) override;

            /**
            Send a ReceiverOperationResponse from a sender to a receiver. These operations represent a
            response to either a parameter request, an OPRF request, or a query request. The
            function throws and exception on failure.
            */
            void send(std::unique_ptr<ReceiverOperationResponse> rop_response) override;

            /**
            Receive a ReceiverOperationResponse from a sender. The function returns nullptr on
            failure.
            */
            std::unique_ptr<ReceiverOperationResponse> receive_response(
                ReceiverOperationType expected = ReceiverOperationType::rop_unknown) override;

            /**
            Send a ResultPackage to a receiver. The function throws and exception on failure.
            */
            void send(std::unique_ptr<ResultPackage> rp) override;

            /**
            Receive a ResultPackage from a sender. A valid seal::SEALContext must be provided. The
            function returns nullptr on failure.
            */
            std::unique_ptr<ResultPackage> receive_result(
                std::shared_ptr<seal::SEALContext> context) override;

        protected:
            std::istream &in_;

            std::ostream &out_;

        private:
            std::mutex receive_mutex_;

            std::mutex send_mutex_;
        }; // class StreamChannel
    }      // namespace network
} // namespace apsu
