// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <stdexcept>

// APSU
#include "apsu/log.h"
#include "apsu/psu_params.h"
#include "apsu/query.h"

using namespace std;
using namespace seal;

namespace apsu {
    using namespace network;

    namespace receiver {
        Query Query::deep_copy() const
        {
            Query result;
            result.relin_keys_ = relin_keys_;
            result.data_ = data_;
            result.receiver_db_ = receiver_db_;
            result.compr_mode_ = compr_mode_;

            return result;
        }

        Query::Query(QueryRequest query_request, shared_ptr<ReceiverDB> receiver_db)
        {
            if (!receiver_db) {
                throw invalid_argument("receiver_db cannot be null");
            }
            if (!query_request) {
                throw invalid_argument("query_request cannot be null");
            }

            compr_mode_ = query_request->compr_mode;

            receiver_db_ = move(receiver_db);
            auto seal_context = receiver_db_->get_seal_context();

            // Extract and validate relinearization keys
            if (seal_context->using_keyswitching()) {
                relin_keys_ = query_request->relin_keys.extract(seal_context);
                if (!is_valid_for(relin_keys_, *seal_context)) {
                    APSU_LOG_ERROR("Extracted relinearization keys are invalid for SEALContext");
                    return;
                }
            }

            // Extract and validate query ciphertexts
            for (auto &q : query_request->data) {
                APSU_LOG_DEBUG(
                    "Extracting " << q.second.size() << " ciphertexts for exponent " << q.first);
                vector<Ciphertext> cts;
                for (auto &ct : q.second) {
                    cts.push_back(ct.extract(seal_context));
                    if (!is_valid_for(cts.back(), *seal_context)) {
                        APSU_LOG_ERROR("Extracted ciphertext is invalid for SEALContext");
                        return;
                    }
                }
                data_[q.first] = move(cts);
            }

            // Get the PSUParams
            PSUParams params(receiver_db_->get_params());

            uint32_t bundle_idx_count = params.bundle_idx_count();
            uint32_t max_items_per_bin = params.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params.query_params().ps_low_degree;
            const set<uint32_t> &query_powers = params.query_params().query_powers;
            set<uint32_t> target_powers = create_powers_set(ps_low_degree, max_items_per_bin);

            // Create the PowersDag
            pd_.configure(query_powers, target_powers);

            // Check that the PowersDag is valid
            if (!pd_.is_configured()) {
                APSU_LOG_ERROR(
                    "Failed to configure PowersDag ("
                    << "source_powers: " << to_string(query_powers) << ", "
                    << "up_to_power: " << to_string(target_powers) << ")");
                return;
            }
            APSU_LOG_DEBUG("Configured PowersDag with depth " << pd_.depth());

            // Check that the query data size matches the PSUParams
            if (data_.size() != query_powers.size()) {
                APSU_LOG_ERROR(
                    "Extracted query data is incompatible with PSU parameters: "
                    "query contains "
                    << data_.size()
                    << " ciphertext powers which does not match with "
                       "the size of query_powers ("
                    << query_powers.size() << ")");
                return;
            }

            for (auto &q : data_) {
                // Check that powers in the query data match source nodes in the PowersDag
                if (q.second.size() != bundle_idx_count) {
                    APSU_LOG_ERROR(
                        "Extracted query data is incompatible with PSU parameters: "
                        "query power "
                        << q.first << " contains " << q.second.size()
                        << " ciphertexts which does not "
                           "match with bundle_idx_count ("
                        << bundle_idx_count << ")");
                    return;
                }
                auto where = find_if(query_powers.cbegin(), query_powers.cend(), [&q](auto n) {
                    return n == q.first;
                });
                if (where == query_powers.cend()) {
                    APSU_LOG_ERROR(
                        "Extracted query data is incompatible with PowersDag: "
                        "query power "
                        << q.first << " does not match with a source node in PowersDag");
                    return;
                }
            }

            // The query is valid
            valid_ = true;
        }
    } // namespace receiver
} // namespace apsu
