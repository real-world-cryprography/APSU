// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <iterator>
#include <sstream>
#include <stdexcept>

// APSU
#include "apsu/network/receiver_operation_response.h"
#include "apsu/network/rop_response_generated.h"
#include "apsu/util/utils.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/streambuf.h"

using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsu {
    using namespace util;

    namespace network {
        size_t ReceiverOperationResponseParms::save(ostream &out) const
        {
            if (!params) {
                throw logic_error("parameters are not set");
            }

            flatbuffers::FlatBufferBuilder fbs_builder(128);

            // Save the parameters into a temporary string
            stringstream ss;
            params->save(ss);
            string params_str = ss.str();

            // Set up a vector to hold the parameter data
            auto params_data = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(&params_str[0]), params_str.size());

            auto resp = fbs::CreateParmsResponse(fbs_builder, params_data);

            fbs::ReceiverOperationResponseBuilder rop_response_builder(fbs_builder);
            rop_response_builder.add_response_type(fbs::Response_ParmsResponse);
            rop_response_builder.add_response(resp.Union());
            auto rop_response = rop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(rop_response);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t ReceiverOperationResponseParms::load(istream &in)
        {
            // Release the current parameters
            params.reset();

            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedReceiverOperationResponseBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load ReceiverOperationResponse: invalid buffer");
            }

            auto rop_response = fbs::GetSizePrefixedReceiverOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (rop_response->response_type() != fbs::Response_ParmsResponse) {
                throw runtime_error("unexpected operation type");
            }

            // Load the PSUParams response
            const auto &params_data = *rop_response->response_as_ParmsResponse()->data();
            ArrayGetBuffer agbuf(
                reinterpret_cast<const char *>(params_data.data()),
                static_cast<streamsize>(params_data.size()));
            istream params_stream(&agbuf);
            params = make_unique<PSUParams>(PSUParams::Load(params_stream).first);

            return in_data.size();
        }

        size_t ReceiverOperationResponseOPRF::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            // Set up a vector to hold the response data
            auto oprf_data = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(data.data()), data.size());
            auto resp = fbs::CreateOPRFResponse(fbs_builder, oprf_data);

            fbs::ReceiverOperationResponseBuilder rop_response_builder(fbs_builder);
            rop_response_builder.add_response_type(fbs::Response_OPRFResponse);
            rop_response_builder.add_response(resp.Union());
            auto rop_response = rop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(rop_response);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t ReceiverOperationResponseOPRF::load(istream &in)
        {
            // Clear the current data
            data.clear();

            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedReceiverOperationResponseBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load ReceiverOperationResponse: invalid buffer");
            }

            auto rop_response = fbs::GetSizePrefixedReceiverOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (rop_response->response_type() != fbs::Response_OPRFResponse) {
                throw runtime_error("unexpected operation type");
            }

            // This will be non-null
            auto oprf_response = rop_response->response_as_OPRFResponse();

            // Load the OPRF response; this is a required field so we can always dereference
            const auto &oprf_data = *oprf_response->data();
            data.resize(oprf_data.size());
            copy_bytes(oprf_data.data(), oprf_data.size(), data.data());

            return in_data.size();
        }

        size_t ReceiverOperationResponseQuery::save(ostream &out) const
        {
            flatbuffers::FlatBufferBuilder fbs_builder(128);

            auto resp = fbs::CreateQueryResponse(fbs_builder, package_count,alpha_max_cache_count);

            fbs::ReceiverOperationResponseBuilder rop_response_builder(fbs_builder);
            rop_response_builder.add_response_type(fbs::Response_QueryResponse);
            rop_response_builder.add_response(resp.Union());
            auto rop_response = rop_response_builder.Finish();
            fbs_builder.FinishSizePrefixed(rop_response);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));

            return fbs_builder.GetSize();
        }

        size_t ReceiverOperationResponseQuery::load(istream &in)
        {
            vector<unsigned char> in_data(util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedReceiverOperationResponseBuffer(verifier);
            if (!safe) {
                throw runtime_error("failed to load ReceiverOperationResponse: invalid buffer");
            }

            auto rop_response = fbs::GetSizePrefixedReceiverOperationResponse(in_data.data());

            // Need to check that the operation is of the right type
            if (rop_response->response_type() != fbs::Response_QueryResponse) {
                throw runtime_error("unexpected operation type");
            }

            // Load the query response
            package_count = rop_response->response_as_QueryResponse()->package_count();
            alpha_max_cache_count = rop_response->response_as_QueryResponse()->alpha_max_cache_count();
            return in_data.size();
        }
    } // namespace network
} // namespace apsu
