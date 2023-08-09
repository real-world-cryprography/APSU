// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>
#include <vector>

// APSU
#include "apsu/network/result_package.h"
#include "apsu/network/receiver_operation.h"
#include "apsu/psu_params.h"

namespace apsu {
    namespace network {
        /**
        An abstract base class representing a response to a sender operation.
        */
        class ReceiverOperationResponse {
        public:
            ReceiverOperationResponse() = default;

            /**
            Destroys the ReceiverOperationResponse.
            */
            virtual ~ReceiverOperationResponse() = default;

            /**
            Writes the ReceiverOperationResponse to a stream.
            */
            virtual std::size_t save(std::ostream &out) const = 0;

            /**
            Reads the ReceiverOperationResponse from a stream.
            */
            virtual std::size_t load(std::istream &in) = 0;

            /**
            Returns the type of the ReceiverOperation for which this is a response.
            */
            virtual ReceiverOperationType type() const noexcept = 0;
        }; // class ReceiverOperationResponse

        /**
        A kind of ReceiverOperationResponse for representing a response to a parameter request.
        */
        class ReceiverOperationResponseParms final : public ReceiverOperationResponse {
        public:
            ReceiverOperationResponseParms() = default;

            ~ReceiverOperationResponseParms() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in) override;

            ReceiverOperationType type() const noexcept override
            {
                return ReceiverOperationType::rop_parms;
            }

            /**
            Holds the parameters returned to the receiver.
            */
            std::unique_ptr<PSUParams> params;
        }; // class ReceiverOperationResponseParms

        /**
        A kind of ReceiverOperationResponse for representing a response to an OPRF query.
        */
        class ReceiverOperationResponseOPRF final : public ReceiverOperationResponse {
        public:
            ReceiverOperationResponseOPRF() = default;

            ~ReceiverOperationResponseOPRF() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in) override;

            ReceiverOperationType type() const noexcept override
            {
                return ReceiverOperationType::rop_oprf;
            }

            /**
            Holds the OPRF query data.
            */
            std::vector<unsigned char> data;
        }; // class ReceiverOperationResponseOPRF

        /**
        A kind of ReceiverOperationResponse for representing a response to a PSU or labeled PSU query.
        */
        class ReceiverOperationResponseQuery final : public ReceiverOperationResponse {
        public:
            ReceiverOperationResponseQuery() = default;

            ~ReceiverOperationResponseQuery() = default;

            std::size_t save(std::ostream &out) const override;

            std::size_t load(std::istream &in) override;

            ReceiverOperationType type() const noexcept override
            {
                return ReceiverOperationType::rop_query;
            }

            /**
            Holds the number of ResultPackage objects the sender is expected to send back to the
            receiver.
            */
            std::uint32_t package_count;
            std::uint32_t alpha_max_cache_count;
        }; // class ReceiverOperationResponseQuery
    }      // namespace network
} // namespace apsu
