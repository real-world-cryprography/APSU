// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <cstddef>
#include <stdexcept>
#include <utility>

// APSU
#include "apsu/log.h"
#include "apsu/network/result_package_generated.h"
#include "apsu/network/rop_generated.h"
#include "apsu/network/rop_header_generated.h"
#include "apsu/network/stream_channel.h"

using namespace std;
using namespace seal;

namespace apsu {
    namespace network {
        void StreamChannel::send(unique_ptr<ReceiverOperation> rop)
        {
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

            lock_guard<mutex> lock(send_mutex_);
            size_t old_bytes_sent = bytes_sent_;

            bytes_sent_ += rop_header.save(out_);
            bytes_sent_ += rop->save(out_);

            APSU_LOG_DEBUG(
                "Sent an operation of type " << receiver_operation_type_str(rop_header.type) << " ("
                                             << bytes_sent_ - old_bytes_sent << " bytes)");
        }

        unique_ptr<ReceiverOperation> StreamChannel::receive_operation(
            shared_ptr<SEALContext> context, ReceiverOperationType expected)
        {
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

            lock_guard<mutex> lock(receive_mutex_);
            size_t old_bytes_received = bytes_received_;

            ReceiverOperationHeader rop_header;
            try {
                bytes_received_ += rop_header.load(in_);
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

            // Return value
            unique_ptr<ReceiverOperation> rop = nullptr;

            try {
                switch (static_cast<ReceiverOperationType>(rop_header.type)) {
                case ReceiverOperationType::rop_parms:
                    rop = make_unique<ReceiverOperationParms>();
                    bytes_received_ += rop->load(in_);
                    break;
                case ReceiverOperationType::rop_oprf:
                    rop = make_unique<ReceiverOperationOPRF>();
                    bytes_received_ += rop->load(in_);
                    break;
                case ReceiverOperationType::rop_query:
                    rop = make_unique<ReceiverOperationQuery>();
                    bytes_received_ += rop->load(in_, move(context));
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

            // Loaded successfully
            APSU_LOG_DEBUG(
                "Received an operation of type " << receiver_operation_type_str(rop_header.type)
                                                 << " (" << bytes_received_ - old_bytes_received
                                                 << " bytes)");

            return rop;
        }

        void StreamChannel::send(unique_ptr<ReceiverOperationResponse> rop_response)
        {
            // Need to have the ReceiverOperationResponse package
            if (!rop_response) {
                APSU_LOG_ERROR("Failed to send response: response data is missing");
                throw invalid_argument("response data is missing");
            }

            // Construct the header
            ReceiverOperationHeader rop_header;
            rop_header.type = rop_response->type();
            APSU_LOG_DEBUG(
                "Sending response of type " << receiver_operation_type_str(rop_header.type));

            lock_guard<mutex> lock(send_mutex_);
            size_t old_bytes_sent = bytes_sent_;

            bytes_sent_ += rop_header.save(out_);
            bytes_sent_ += rop_response->save(out_);

            APSU_LOG_DEBUG(
                "Sent a response of type " << receiver_operation_type_str(rop_header.type) << " ("
                                           << bytes_sent_ - old_bytes_sent << " bytes)");
        }

        unique_ptr<ReceiverOperationResponse> StreamChannel::receive_response(
            ReceiverOperationType expected)
        {
            lock_guard<mutex> lock(receive_mutex_);
            size_t old_bytes_received = bytes_received_;

            ReceiverOperationHeader rop_header;
            try {
                bytes_received_ += rop_header.load(in_);
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

            // Return value
            unique_ptr<ReceiverOperationResponse> rop_response = nullptr;

            try {
                switch (static_cast<ReceiverOperationType>(rop_header.type)) {
                case ReceiverOperationType::rop_parms:
                    rop_response = make_unique<ReceiverOperationResponseParms>();
                    bytes_received_ += rop_response->load(in_);
                    break;
                case ReceiverOperationType::rop_oprf:
                    rop_response = make_unique<ReceiverOperationResponseOPRF>();
                    bytes_received_ += rop_response->load(in_);
                    break;
                case ReceiverOperationType::rop_query:
                    rop_response = make_unique<ReceiverOperationResponseQuery>();
                    bytes_received_ += rop_response->load(in_);
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

        void StreamChannel::send(unique_ptr<ResultPackage> rp)
        {
            // Need to have the ResultPackage
            if (!rp) {
                APSU_LOG_ERROR("Failed to send result package: result package data is missing");
                throw invalid_argument("result package data is missing");
            }

            APSU_LOG_DEBUG(
                "Sending result package ("
                << "has matching data: " << (rp->psu_result ? "yes" : "no") << "; "
                << "label byte count: " << rp->label_byte_count << "; "
                << "nonce byte count: " << rp->nonce_byte_count << "; "
                << "has label data: " << (rp->label_result.size() ? "yes" : "no") << ")");

            lock_guard<mutex> lock(send_mutex_);
            size_t old_bytes_sent = bytes_sent_;

            bytes_sent_ += rp->save(out_);

            APSU_LOG_DEBUG("Sent a result package (" << bytes_sent_ - old_bytes_sent << " bytes)");
        }

        unique_ptr<ResultPackage> StreamChannel::receive_result(shared_ptr<SEALContext> context)
        {
            bool valid_context = context && context->parameters_set();
            if (!valid_context) {
                // Cannot receive a result package without a valid SEALContext
                APSU_LOG_ERROR(
                    "Cannot receive a result package; SEALContext is missing or invalid");
                return nullptr;
            }

            lock_guard<mutex> lock(receive_mutex_);
            size_t old_bytes_received = bytes_received_;

            // Return value
            unique_ptr<ResultPackage> rp(make_unique<ResultPackage>());

            try {
                bytes_received_ += rp->load(in_, move(context));
            } catch (const invalid_argument &ex) {
                APSU_LOG_ERROR(
                    "An exception was thrown loading result package data: " << ex.what());
                return nullptr;
            } catch (const runtime_error &ex) {
                APSU_LOG_ERROR(
                    "An exception was thrown loading result package data: " << ex.what());
                return nullptr;
            }

            // Loaded successfully
            APSU_LOG_DEBUG(
                "Received a result package (" << bytes_received_ - old_bytes_received << " bytes)");

            return rp;
        }
    } // namespace network
} // namespace apsu
