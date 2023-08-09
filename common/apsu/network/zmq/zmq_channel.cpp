// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <iterator>
#include <sstream>
#include <stdexcept>

// APSU
#include "apsu/fourq/random.h"
#include "apsu/log.h"
#include "apsu/network/result_package_generated.h"
#include "apsu/network/rop_generated.h"
#include "apsu/network/rop_header_generated.h"
#include "apsu/network/zmq/zmq_channel.h"
#include "apsu/util/utils.h"

// SEAL
#include "seal/randomgen.h"
#include "seal/util/streambuf.h"

// ZeroMQ
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include "zmq.hpp"
#include "zmq_addon.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace zmq;

namespace apsu {
    using namespace util;

    namespace network {
        namespace {
            template <typename T>
            size_t load_from_string(string data, T &obj)
            {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(data.data()),
                    static_cast<streamsize>(data.size()));
                istream stream(&agbuf);
                return obj.load(stream);
            }

            template <typename T>
            size_t load_from_string(string data, shared_ptr<SEALContext> context, T &obj)
            {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(data.data()),
                    static_cast<streamsize>(data.size()));
                istream stream(&agbuf);
                return obj.load(stream, move(context));
            }

            template <typename T>
            size_t save_to_message(const T &obj, multipart_t &msg)
            {
                stringstream ss;
                size_t size = obj.save(ss);
                msg.addstr(ss.str());
                return size;
            }

            template <>
            size_t save_to_message(const vector<unsigned char> &obj, multipart_t &msg)
            {
                msg.addmem(obj.data(), obj.size());
                return obj.size();
            }

            vector<unsigned char> get_client_id(const multipart_t &msg)
            {
                size_t client_id_size = msg[0].size();
                vector<unsigned char> client_id(client_id_size);
                copy_bytes(msg[0].data(), client_id_size, client_id.data());
                return client_id;
            }
        } // namespace

        ZMQChannel::ZMQChannel() : end_point_(""), context_(make_unique<context_t>())
        {}

        ZMQChannel::~ZMQChannel()
        {
            if (is_connected()) {
                disconnect();
            }
        }

        void ZMQChannel::bind(const string &end_point)
        {
            throw_if_connected();

            try {
                end_point_ = end_point;
                get_socket()->bind(end_point);
            } catch (const zmq::error_t &) {
                APSU_LOG_ERROR("ZeroMQ failed to bind socket to endpoint " << end_point);
                throw;
            }
        }

        void ZMQChannel::connect(const string &end_point)
        {
            throw_if_connected();

            try {
                end_point_ = end_point;
                get_socket()->connect(end_point);
            } catch (const zmq::error_t &) {
                APSU_LOG_ERROR("ZeroMQ failed to connect socket to endpoint " << end_point);
                throw;
            }
        }

        void ZMQChannel::disconnect()
        {
            throw_if_not_connected();

            // Cannot use get_socket() in disconnect(): this function is called by the destructor
            // and get_socket() is virtual. Instead just do this.
            if (nullptr != socket_) {
                socket_->close();
            }
            if (context_) {
                context_->shutdown();
                context_->close();
            }

            end_point_ = "";
            socket_.reset();
            context_.reset();
        }

        void ZMQChannel::throw_if_not_connected() const
        {
            if (!is_connected()) {
                APSU_LOG_ERROR("Socket is not connected");
                throw runtime_error("socket is not connected");
            }
        }

        void ZMQChannel::throw_if_connected() const
        {
            if (is_connected()) {
                APSU_LOG_ERROR("Socket is already connected");
                throw runtime_error("socket is already connected");
            }
        }

        void ZMQChannel::send(unique_ptr<ReceiverOperation> rop)
        {
            throw_if_not_connected();

            // Need to have the ReceiverOperation package
            if (!rop) {
                APSU_LOG_ERROR("Failed to send operation: operation data is missing");
                throw invalid_argument("operation data is missing");
            }

            // Construct the header
            ReceiverOperationHeader rop_header;
            rop_header.type = rop->type();
            APSU_LOG_DEBUG(
                "Sending operation of type " << receiver_operation_type_str(rop_header.type));

            size_t bytes_sent = 0;

            multipart_t msg;
           
            bytes_sent += save_to_message(rop_header, msg);
            

            bytes_sent += save_to_message(*rop, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;

            APSU_LOG_DEBUG(
                "Sent an operation of type " << receiver_operation_type_str(rop_header.type) << " ("
                                             << bytes_sent << " bytes)");
        }

        unique_ptr<ZMQReceiverOperation> ZMQChannel::receive_network_operation(
            shared_ptr<SEALContext> context, bool wait_for_message, ReceiverOperationType expected)
        {
            throw_if_not_connected();

            bool valid_context = context && context->parameters_set();
            if (!valid_context && (expected == ReceiverOperationType::rop_unknown ||
                                   expected == ReceiverOperationType::rop_query)) {
                // Cannot receive unknown or query operations without a valid SEALContext
                APSU_LOG_ERROR(
                    "Cannot receive an operation of type "
                    << receiver_operation_type_str(expected)
                    << "; SEALContext is missing or invalid");
                return nullptr;
            }

            size_t old_bytes_received = bytes_received_;

            multipart_t msg;
            if (!receive_message(msg, wait_for_message)) {
                // No message yet. Don't log anything.
                return nullptr;
            }
            // Should have client_id, ReceiverOperationHeader, and ReceiverOperation.
            if (msg.size() != 3) {
                APSU_LOG_ERROR(
                    "ZeroMQ received a message with " << msg.size()
                                                      << " parts but expected 3 parts");
                throw runtime_error("invalid message received");
            }

            // First extract the client_id; this is the first part of the message
            vector<unsigned char> client_id = get_client_id(msg);

            // Second part is the ReceiverOperationHeader
            ReceiverOperationHeader rop_header;
            try {
                bytes_received_ += load_from_string(msg[1].to_string(), rop_header);
            } catch (const runtime_error &) {
                // Invalid header
                APSU_LOG_ERROR("Failed to receive a valid header");
                return nullptr;
            }

            if (!same_serialization_version(rop_header.version)) {
                // Check that the serialization version numbers match
                APSU_LOG_ERROR(
                    "Received header indicates a serialization version number ("
                    << rop_header.version
                    << ") incompatible with the current serialization version number ("
                    << apsu_serialization_version << ")");
                return nullptr;
            }

            if (expected != ReceiverOperationType::rop_unknown && expected != rop_header.type) {
                // Unexpected operation
                APSU_LOG_ERROR(
                    "Received header indicates an unexpected operation type "
                    << receiver_operation_type_str(rop_header.type));
                return nullptr;
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<ReceiverOperation> rop = nullptr;

            try {
                switch (static_cast<ReceiverOperationType>(rop_header.type)) {
                case ReceiverOperationType::rop_parms:
                    rop = make_unique<ReceiverOperationParms>();
                    bytes_received = load_from_string(msg[2].to_string(), *rop);
                    bytes_received_ += bytes_received;
                    break;
                case ReceiverOperationType::rop_oprf:
                    rop = make_unique<ReceiverOperationOPRF>();
                    bytes_received = load_from_string(msg[2].to_string(), *rop);
                    bytes_received_ += bytes_received;
                    break;
                case ReceiverOperationType::rop_query:
                    rop = make_unique<ReceiverOperationQuery>();
                    bytes_received = load_from_string(msg[2].to_string(), move(context), *rop);
                    bytes_received_ += bytes_received;
                    break;
                case ReceiverOperationType::rop_response:
                    rop = make_unique<plainResponse>();
                    bytes_received = load_from_string(msg[2].to_string(), *rop);
                    bytes_received_ += bytes_received;
                    break;
                default:
                    // Invalid operation
                    APSU_LOG_ERROR(
                        "Received header indicates an invalid operation type "
                        << receiver_operation_type_str(rop_header.type));
                    return nullptr;
                }
            } catch (const invalid_argument &ex) {
                APSU_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                return nullptr;
            } catch (const runtime_error &ex) {
                APSU_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                return nullptr;
            }

            // Loaded successfully; set up ZMQReceiverOperation package
            auto n_rop = make_unique<ZMQReceiverOperation>();
            n_rop->client_id = move(client_id);
            n_rop->rop = move(rop);

            APSU_LOG_DEBUG(
                "Received an operation of type " << receiver_operation_type_str(rop_header.type)
                                                 << " (" << bytes_received_ - old_bytes_received
                                                 << " bytes)");

            return n_rop;
        }

        unique_ptr<ReceiverOperation> ZMQChannel::receive_operation(
            shared_ptr<SEALContext> context, ReceiverOperationType expected)
        {
            // Ignore the client_id
            return move(receive_network_operation(move(context), expected)->rop);
        }

        void ZMQChannel::send(unique_ptr<ZMQReceiverOperationResponse> rop_response)
        {
            throw_if_not_connected();

            // Need to have the ReceiverOperationResponse package
            if (!rop_response) {
                APSU_LOG_ERROR("Failed to send response: response data is missing");
                throw invalid_argument("response data is missing");
            }

            // Construct the header
            ReceiverOperationHeader rop_header;
            rop_header.type = rop_response->rop_response->type();
            APSU_LOG_DEBUG(
                "Sending response of type " << receiver_operation_type_str(rop_header.type));

            size_t bytes_sent = 0;

            multipart_t msg;

            // Add the client_id as the first part
            save_to_message(rop_response->client_id, msg);

            bytes_sent += save_to_message(rop_header, msg);
            bytes_sent += save_to_message(*rop_response->rop_response, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;

            APSU_LOG_DEBUG(
                "Sent an operation of type " << receiver_operation_type_str(rop_header.type) << " ("
                                             << bytes_sent << " bytes)");
        }

        void ZMQChannel::send(unique_ptr<ReceiverOperationResponse> rop_response)
        {
            // Leave the client_id empty
            auto n_rop_response = make_unique<ZMQReceiverOperationResponse>();
            n_rop_response->rop_response = move(rop_response);

            send(move(n_rop_response));
        }

        unique_ptr<ReceiverOperationResponse> ZMQChannel::receive_response(
            ReceiverOperationType expected)
        {
            throw_if_not_connected();

            size_t old_bytes_received = bytes_received_;

            multipart_t msg;
            if (!receive_message(msg)) {
                // No message yet. Don't log anything.
                return nullptr;
            }

            // Should have ReceiverOperationHeader and ReceiverOperationResponse.
            if (msg.size() != 2) {
                APSU_LOG_ERROR(
                    "ZeroMQ received a message with " << msg.size()
                                                      << " parts but expected 2 parts");
                throw runtime_error("invalid message received");
            }

            // First part is the ReceiverOperationHeader
            ReceiverOperationHeader rop_header;
            try {
                bytes_received_ += load_from_string(msg[0].to_string(), rop_header);
            } catch (const runtime_error &) {
                // Invalid header
                APSU_LOG_ERROR("Failed to receive a valid header");
                return nullptr;
            }

            if (!same_serialization_version(rop_header.version)) {
                // Check that the serialization version numbers match
                APSU_LOG_ERROR(
                    "Received header indicates a serialization version number "
                    << rop_header.version
                    << " incompatible with the current serialization version number "
                    << apsu_serialization_version);
                return nullptr;
            }

            if (expected != ReceiverOperationType::rop_unknown && expected != rop_header.type) {
                // Unexpected operation
                APSU_LOG_ERROR(
                    "Received header indicates an unexpected operation type "
                    << receiver_operation_type_str(rop_header.type));
                return nullptr;
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<ReceiverOperationResponse> rop_response = nullptr;

            try {
                switch (static_cast<ReceiverOperationType>(rop_header.type)) {
                case ReceiverOperationType::rop_parms:
                    rop_response = make_unique<ReceiverOperationResponseParms>();
                    bytes_received = load_from_string(msg[1].to_string(), *rop_response);
                    bytes_received_ += bytes_received;
                    break;
                case ReceiverOperationType::rop_oprf:
                    rop_response = make_unique<ReceiverOperationResponseOPRF>();
                    bytes_received = load_from_string(msg[1].to_string(), *rop_response);
                    bytes_received_ += bytes_received;
                    break;
                case ReceiverOperationType::rop_query:
                    rop_response = make_unique<ReceiverOperationResponseQuery>();
                    bytes_received = load_from_string(msg[1].to_string(), *rop_response);
                    bytes_received_ += bytes_received;
                    break;
                default:
                    // Invalid operation
                    APSU_LOG_ERROR(
                        "Received header indicates an invalid operation type "
                        << receiver_operation_type_str(rop_header.type));
                    return nullptr;
                }
            } catch (const runtime_error &ex) {
                APSU_LOG_ERROR("An exception was thrown loading response data: " << ex.what());
                return nullptr;
            }

            // Loaded successfully
            APSU_LOG_DEBUG(
                "Received a response of type " << receiver_operation_type_str(rop_header.type) << " ("
                                               << bytes_received_ - old_bytes_received
                                               << " bytes)");

            return rop_response;
        }

        void ZMQChannel::send(unique_ptr<ZMQResultPackage> rp)
        {
            throw_if_not_connected();

            // Need to have the ResultPackage
            if (!rp) {
                APSU_LOG_ERROR("Failed to send result package: result package data is missing");
                throw invalid_argument("result package data is missing");
            }

            APSU_LOG_DEBUG(
                "Sending result package ("
                << "has matching data: " << (rp->rp->psu_result ? "yes" : "no") << "; "
                << "label byte count: " << rp->rp->label_byte_count << "; "
                << "nonce byte count: " << rp->rp->nonce_byte_count << "; "
                << "has label data: " << (rp->rp->label_result.size() ? "yes" : "no") << ")");

            multipart_t msg;

            // Add the client_id as the first part
            save_to_message(rp->client_id, msg);

            size_t bytes_sent = save_to_message(*rp->rp, msg);

            send_message(msg);
            bytes_sent_ += bytes_sent;

            APSU_LOG_DEBUG("Sent a result package (" << bytes_sent << " bytes)");
        }

        void ZMQChannel::send(unique_ptr<ResultPackage> rp)
        {
            // Leave the client_id empty
            auto n_rp = make_unique<ZMQResultPackage>();
            n_rp->rp = move(rp);

            send(move(n_rp));
        }

        unique_ptr<ResultPackage> ZMQChannel::receive_result(shared_ptr<SEALContext> context)
        {
            throw_if_not_connected();

            bool valid_context = context && context->parameters_set();
            if (!valid_context) {
                // Cannot receive a result package without a valid SEALContext
                APSU_LOG_ERROR(
                    "Cannot receive a result package; SEALContext is missing or invalid");
                return nullptr;
            }

            multipart_t msg;
            if (!receive_message(msg)) {
                // No message yet. Don't log anything.
                return nullptr;
            }

            // Should have only one part: ResultPackage.
            if (msg.size() != 1) {
                APSU_LOG_ERROR(
                    "ZeroMQ received a message with " << msg.size()
                                                      << " parts but expected 1 part");
                throw runtime_error("invalid message received");
            }

            // Number of bytes received now
            size_t bytes_received = 0;

            // Return value
            unique_ptr<ResultPackage> rp(make_unique<ResultPackage>());

            try {
                bytes_received = load_from_string(msg[0].to_string(), move(context), *rp);
                bytes_received_ += bytes_received;
            } catch (const invalid_argument &ex) {
                APSU_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                return nullptr;
            } catch (const runtime_error &ex) {
                APSU_LOG_ERROR("An exception was thrown loading operation data: " << ex.what());
                return nullptr;
            }

            // Loaded successfully
            APSU_LOG_DEBUG("Received a result package (" << bytes_received << " bytes)");

            return rp;
        }

        bool ZMQChannel::receive_message(multipart_t &msg, bool wait_for_message)
        {
            lock_guard<mutex> lock(receive_mutex_);

            msg.clear();
            recv_flags receive_flags = wait_for_message ? recv_flags::none : recv_flags::dontwait;

            bool received = msg.recv(*get_socket(), static_cast<int>(receive_flags));
            if (!received && wait_for_message) {
                APSU_LOG_ERROR("ZeroMQ failed to receive a message")
                throw runtime_error("failed to receive message");
            }
            

            return received;
        }

        void ZMQChannel::send_message(multipart_t &msg)
        {
            lock_guard<mutex> lock(send_mutex_);

            send_result_t result = send_multipart(*get_socket(), msg, send_flags::none);
            bool sent = result.has_value();

            
            if (!sent) {
                throw runtime_error("failed to send message");
            }
        }

        unique_ptr<socket_t> &ZMQChannel::get_socket()
        {
            if (nullptr == socket_) {
                socket_ = make_unique<socket_t>(*context_.get(), get_socket_type());
                set_socket_options(socket_.get());
            }

            return socket_;
        }

        zmq::socket_type ZMQSenderChannel::get_socket_type()
        {
            return zmq::socket_type::dealer;
        }

        void ZMQSenderChannel::set_socket_options(socket_t *socket)
        {
            // Ensure messages are not dropped
            socket->set(sockopt::rcvhwm, 70000);

            string buf;
            buf.resize(32);
            random_bytes(
                reinterpret_cast<unsigned char *>(&buf[0]), static_cast<unsigned int>(buf.size()));
            // make sure first byte is _not_ zero, as that has a special meaning for ZeroMQ
            buf[0] = 'A';
            socket->set(sockopt::routing_id, buf);
        }

        zmq::socket_type ZMQReceiverChannel::get_socket_type()
        {
            return zmq::socket_type::router;
        }

        void ZMQReceiverChannel::set_socket_options(socket_t *socket)
        {
            // Ensure messages are not dropped
            socket->set(sockopt::sndhwm, 70000);
        }
    } // namespace network
} // namespace apsu
