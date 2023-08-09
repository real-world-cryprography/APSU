// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

// APSU
#include "apsu/network/receiver_operation.h"
#include "apsu/powers.h"
#include "apsu/requests.h"
#include "apsu/receiver_db.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/relinkeys.h"

namespace apsu {
    namespace receiver {
        class Query {
        public:
            Query() = default;

            Query(QueryRequest query_request, std::shared_ptr<receiver::ReceiverDB> receiver_db);

            Query deep_copy() const;

            Query(const Query &source) = delete;

            Query(Query &&source) = default;

            Query &operator=(const Query &source) = delete;

            Query &operator=(Query &&source) = default;

            bool is_valid() const noexcept
            {
                return valid_;
            }

            explicit operator bool() const noexcept
            {
                return is_valid();
            }

            const seal::RelinKeys &relin_keys() const noexcept
            {
                return relin_keys_;
            }

            auto &data() const noexcept
            {
                return data_;
            }

            const PowersDag &pd() const noexcept
            {
                return pd_;
            }

            std::shared_ptr<receiver::ReceiverDB> receiver_db() const noexcept
            {
                return receiver_db_;
            }

            seal::compr_mode_type compr_mode() const noexcept
            {
                return compr_mode_;
            }

        private:
            seal::RelinKeys relin_keys_;

            std::unordered_map<std::uint32_t, std::vector<seal::Ciphertext>> data_;

            PowersDag pd_;

            std::shared_ptr<receiver::ReceiverDB> receiver_db_;

            bool valid_ = false;

            seal::compr_mode_type compr_mode_;
        };
    } // namespace receiver
} // namespace apsu
