// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

// APSU
#include "apsu/seal_object.h"
#include "apsu/version.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/relinkeys.h"
#include "seal/util/common.h"

namespace apsu {
    namespace network {
        enum class ReceiverOperationType : std::uint32_t {
            rop_unknown = 0,

            rop_parms = 1,

            rop_oprf = 2,

            rop_query = 3,

            rop_response = 4
        };

        const char *receiver_operation_type_str(ReceiverOperationType rop_type);

        /**
        A class describing the type of a ReceiverOperation object and an optional member to identify
        the client.
        */
        class ReceiverOperationHeader {
        public:
            std::size_t save(std::ostream &out) const;

            std::size_t load(std::istream &in);

            std::uint32_t version = apsu_serialization_version;

            ReceiverOperationType type = ReceiverOperationType::rop_unknown;
        };

        /**
        An abstract base class representing a sender operation.
        */
        class ReceiverOperation {
        public:
            ReceiverOperation() = default;

            /**
            Destroys the ReceiverOperation.
            */
            virtual ~ReceiverOperation() = default;

            /**
            Writes the ReceiverOperation to a stream.
            */
            virtual std::size_t save(std::ostream &out) const = 0;

            /**
            Reads the ReceiverOperation from a stream.
            */
            virtual std::size_t load(
                std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) = 0;

            /**
            Returns the type of the ReceiverOperation.
            */
            virtual ReceiverOperationType type() const noexcept = 0;
        }; // class ReceiverOperation

        /**
        A kind of ReceiverOperation for representing a parameter request from the receiver.
        */
        class ReceiverOperationParms final : public ReceiverOperation {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(
                std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) override;

            ReceiverOperationType type() const noexcept override
            {
                return ReceiverOperationType::rop_parms;
            }
        }; // class ReceiverOperationParms

        /**
        A kind of ReceiverOperation for representing an OPRF query from the receiver.
        */
        class ReceiverOperationOPRF final : public ReceiverOperation {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(
                std::istream &in, std::shared_ptr<seal::SEALContext> context = nullptr) override;

            ReceiverOperationType type() const noexcept override
            {
                return ReceiverOperationType::rop_oprf;
            }

            /**
            Holds the OPRF query data.
            */
            std::vector<unsigned char> data;
        }; // class ReceiverOperationOPRF

        /**
        A kind of ReceiverOperation for representing a PSU or labeled PSU query from the receiver.
        */
        class ReceiverOperationQuery final : public ReceiverOperation {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;

            ReceiverOperationType type() const noexcept override
            {
                return ReceiverOperationType::rop_query;
            }

            seal::compr_mode_type compr_mode = seal::Serialization::compr_mode_default;

            SEALObject<seal::RelinKeys> relin_keys;

            /**
            Holds the encrypted query data. In the map the key labels the exponent of the query
            ciphertext and the vector holds the ciphertext data for different bundle indices.
            */
            std::unordered_map<std::uint32_t, std::vector<SEALObject<seal::Ciphertext>>> data;
        }; // class ReceiverOperationQuery

        //struct response_package {
        //    std::uint32_t bundle_idx;

        //    std::vector<std::uint64_t> psu_result;

        //    std::uint32_t label_byte_count;

        //    std::uint32_t nonce_byte_count;

        //};

        class plainResponse final : public ReceiverOperation {
        public:
            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;

            ReceiverOperationType type() const noexcept override
            {
                return ReceiverOperationType::rop_response;
            }

            std::uint32_t bundle_idx;

            std::vector<std::uint64_t> psu_result;

            std::uint32_t cache_idx;

          
           
        };


    }      // namespace network
} // namespace apsu
