// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>
#include <vector>

// APSU
#include "apsu/network/network_channel.h"
#include "apsu/network/result_package.h"
#include "apsu/network/receiver_operation.h"
#include "apsu/network/receiver_operation_response.h"

namespace zmq {
    class socket_t;
    class multipart_t;
    class context_t;
    enum class socket_type;
} // namespace zmq

enum class socket_type;

namespace apsu {
    namespace network {
        /**
        Encapsulates a ReceiverOperation and a client identifier used internally by ZeroMQ.
        */
        struct ZMQReceiverOperation {
            std::unique_ptr<ReceiverOperation> rop;

            std::vector<unsigned char> client_id;
        };

        /**
        Encapsulates a ReceiverOperationResponse and a client identifier used internally by ZeroMQ.
        */
        struct ZMQReceiverOperationResponse {
            std::unique_ptr<ReceiverOperationResponse> rop_response;

            std::vector<unsigned char> client_id;
        };

        /**
        Encapsulates a ResultPackage and a client identifier used internally by ZeroMQ.
        */
        struct ZMQResultPackage {
            std::unique_ptr<ResultPackage> rp;

            std::vector<unsigned char> client_id;
        };

        /**
        ZMQChannel is a communication channel between a sender and a receiver implemented using
        ZeroMQ. All receives are synchronous, except for receiving a ReceiverOperation. All sends are
        asynchronous.

        ZeroMQ uses an identifier number for internal package routing, which is why the ZMQChannel
        operates on custom ZMQReceiverOperation, ZMQReceiverOperationResponse, and ZMQResultPackage
        objects rather than the underlying ReceiverOperation, ReceiverOperationResponse, and
        ResultPackage.

        ZMQChannel is an interface class and is implemented by the ZMQSenderChannel and
        ZMQReceiverChannel.
        */
        class ZMQChannel : public NetworkChannel {
        public:
            /**
            Create an instance of a ZMQChannel.
            */
            ZMQChannel();

            /**
            Destroy an instance of a ZMQChannel.
            */
            virtual ~ZMQChannel();

            /**
            Bind the channel to the given connection point.
            */
            void bind(const std::string &connection_point);

            /**
            Connect the channel to the given connection point.
            */
            void connect(const std::string &connection_point);

            /**
            Disconnect the channel from the connection point.
            */
           std::string get_end_point(){
            return end_point_;

           }


            void disconnect();

            /**
            Returns whether the channel is in a connected state.
            */
            bool is_connected() const
            {
                return !end_point_.empty();
            }

            /**
            Send a ReceiverOperation from a receiver to a sender. These operations represent either a
            parameter request, an OPRF request, or a query request. The function throws an exception
            on failure.
            */
            void send(std::unique_ptr<ReceiverOperation> rop) override;

            /**
            Receive a ZMQReceiverOperation from a receiver. Operations of type rop_query and
            rop_unknown require a valid seal::SEALContext to be provided. For operations of type
            rop_parms and rop_oprf the context can be set as nullptr. The function returns nullptr
            on failure. This call does not block if wait_for_message is false: if there is no
            operation pending, it will immediately return nullptr.
            */
            virtual std::unique_ptr<ZMQReceiverOperation> receive_network_operation(
                std::shared_ptr<seal::SEALContext> context,
                bool wait_for_message,
                ReceiverOperationType expected = ReceiverOperationType::rop_unknown);

            /**
            Receive a ZMQReceiverOperation from a receiver. Operations of type rop_query and
            rop_unknown require a valid seal::SEALContext to be provided. For operations of type
            rop_parms and rop_oprf the context can be set as nullptr. The function returns nullptr
            on failure. This call does not block: if there is no operation pending, it will
            immediately return nullptr.
            */
            virtual std::unique_ptr<ZMQReceiverOperation> receive_network_operation(
                std::shared_ptr<seal::SEALContext> context,
                ReceiverOperationType expected = ReceiverOperationType::rop_unknown)
            {
                return receive_network_operation(std::move(context), false, expected);
            }

            /**
            Send a ZMQReceiverOperationResponse from a sender to a receiver. These operations
            represent a response to either a parameter request, an OPRF request, or a query request.
            The function throws and exception on failure. The sender is expected to manually read
            the client identifier from the received ZMQReceiverOperation and use the same client
            identifier in the ZMQReceiverOperationResponse.
            */
            virtual void send(std::unique_ptr<ZMQReceiverOperationResponse> rop_response);

            /**
            Receive a ReceiverOperationResponse from a sender. The function returns nullptr on
            failure.
            */
            std::unique_ptr<ReceiverOperationResponse> receive_response(
                ReceiverOperationType expected = ReceiverOperationType::rop_unknown) override;

            /**
            Send a ZMQResultPackage to a receiver. The function throws and exception on failure. The
            sender is expected to manually read the client identifier from the received
            ZMQReceiverOperation and use the same client identifier in the ZMQResultPackage.
            */
            virtual void send(std::unique_ptr<ZMQResultPackage> rp);

            /**
            Receive a ResultPackage from a sender. A valid seal::SEALContext must be provided. The
            function returns nullptr on failure.
            */
            std::unique_ptr<ResultPackage> receive_result(
                std::shared_ptr<seal::SEALContext> context) override;

            /**
            Do not use this function. Use ZMQChannel::receive_network_operation instead.
            */
            std::unique_ptr<ReceiverOperation> receive_operation(
                std::shared_ptr<seal::SEALContext> context,
                ReceiverOperationType expected = ReceiverOperationType::rop_unknown) override;

            /**
            Do not use this function. Use
            ZMQChannel::send(std::unique_ptr<ZMQReceiverOperationResponse>) instead.
            */
            void send(std::unique_ptr<ReceiverOperationResponse> rop_response) override;

            /**
            Do not use this function. Use ZMQChannel::send(std::unique_ptr<ZMQResultPackage>)
            instead.
            */
            void send(std::unique_ptr<ResultPackage> rp) override;

        protected:
            /**
            Get socket type for this channel.
            */
            virtual zmq::socket_type get_socket_type() = 0;

            /**
            Add any needed options for the socket. Called just after socket creation.
            */
            virtual void set_socket_options(zmq::socket_t *socket) = 0;

        private:
            std::unique_ptr<zmq::socket_t> socket_;

            std::string end_point_;

            std::mutex receive_mutex_;

            std::mutex send_mutex_;

            std::unique_ptr<zmq::context_t> context_;

            std::unique_ptr<zmq::socket_t> &get_socket();

            void throw_if_not_connected() const;

            void throw_if_connected() const;

            bool receive_message(zmq::multipart_t &msg, bool wait_for_message = true);

            void send_message(zmq::multipart_t &msg);
        }; // class ZMQChannel

        /**
        Implements a ZMQChannel for a sender.
        */
        class ZMQSenderChannel : public ZMQChannel {
        public:
            /**
            Create an instance of a ZMQSenderChannel.
            */
            ZMQSenderChannel() = default;

            /**
            Destroy an instance of a ZMQSenderChannel.
            */
            ~ZMQSenderChannel()
            {}

        protected:
            /**
            The only difference from a receiver is the socket type.
            */
            zmq::socket_type get_socket_type() override;

            /**
            The sender needs to set a couple of socket options to ensure messages are not dropped.
            */
            void set_socket_options(zmq::socket_t *socket) override;
        };

        /**
        Implements a ZMQChannel for a receiver.
        */
        class ZMQReceiverChannel : public ZMQChannel {
        public:
            /**
            Create an instance of a ZMQReceiverChannel.
            */
            ZMQReceiverChannel() = default;

            /**
            Destroy an instance of a ZMQReceiverChannel.
            */
            ~ZMQReceiverChannel()
            {}

        protected:
            /**
            The only difference from a sender is the socket type.
            */
            zmq::socket_type get_socket_type() override;

            /**
            The receiver needs to set a couple of socket options to ensure messages are not dropped.
            */
            void set_socket_options(zmq::socket_t *socket) override;
        };
    } // namespace network
} // namespace apsu
