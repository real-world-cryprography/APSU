// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <utility>

// APSU
#include "apsu/network/receiver_operation.h"
#include "apsu/util/utils.h"

namespace apsu {
    /**
    A type representing a parameter, an OPRF, or a query request message to be sent.
    */
    using Request = std::unique_ptr<network::ReceiverOperation>;

    /**
    A type representing a request to a parameter request.
    */
    using ParamsRequest = std::unique_ptr<network::ReceiverOperationParms>;

    /**
    A type representing a request to an OPRF request.
    */
    using OPRFRequest = std::unique_ptr<network::ReceiverOperationOPRF>;

    /**
    A type representing a request to a query request.
    */
    using QueryRequest = std::unique_ptr<network::ReceiverOperationQuery>;

    using plainRequest = std::unique_ptr<network::plainResponse>;

    inline ParamsRequest to_params_request(Request &request)
    {
        if (request == nullptr || request->type() != apsu::network::ReceiverOperationType::rop_parms)
            return nullptr;
        return ParamsRequest(static_cast<apsu::network::ReceiverOperationParms *>(request.release()));
    }

    inline ParamsRequest to_params_request(Request &&request)
    {
        if (request == nullptr || request->type() != apsu::network::ReceiverOperationType::rop_parms)
            return nullptr;
        return ParamsRequest(static_cast<apsu::network::ReceiverOperationParms *>(request.release()));
    }

    inline OPRFRequest to_oprf_request(Request &request)
    {
        if (request == nullptr || request->type() != apsu::network::ReceiverOperationType::rop_oprf)
            return nullptr;
        return OPRFRequest(static_cast<apsu::network::ReceiverOperationOPRF *>(request.release()));
    }

    inline OPRFRequest to_oprf_request(Request &&request)
    {
        if (request == nullptr || request->type() != apsu::network::ReceiverOperationType::rop_oprf)
            return nullptr;
        return OPRFRequest(static_cast<apsu::network::ReceiverOperationOPRF *>(request.release()));
    }

    inline QueryRequest to_query_request(Request &request)
    {
        if (request == nullptr || request->type() != apsu::network::ReceiverOperationType::rop_query)
            return nullptr;
        return QueryRequest(static_cast<apsu::network::ReceiverOperationQuery *>(request.release()));
    }

    inline QueryRequest to_query_request(Request &&request)
    {
        if (request == nullptr || request->type() != apsu::network::ReceiverOperationType::rop_query)
            return nullptr;
        return QueryRequest(static_cast<apsu::network::ReceiverOperationQuery *>(request.release()));
    }


    inline plainRequest to_plain_request(Request& request)
    {
        if (request == nullptr ||
            request->type() != apsu::network::ReceiverOperationType::rop_response)
            return nullptr;
        return plainRequest(static_cast<apsu::network::plainResponse *>(request.release()));

    }

    inline plainRequest to_plain_request(Request &&request)
    {
        if (request == nullptr ||
            request->type() != apsu::network::ReceiverOperationType::rop_response)
            return nullptr;
        return plainRequest(static_cast<apsu::network::plainResponse *>(request.release()));
    }





    inline Request to_request(ParamsRequest &params_request)
    {
        return Request(params_request.release());
    }

    inline Request to_request(ParamsRequest &&params_request)
    {
        return Request(params_request.release());
    }

    inline Request to_request(OPRFRequest &oprf_request)
    {
        return Request(oprf_request.release());
    }

    inline Request to_request(OPRFRequest &&oprf_request)
    {
        return Request(oprf_request.release());
    }

    inline Request to_request(QueryRequest &query_request)
    {
        return Request(query_request.release());
    }

    inline Request to_request(QueryRequest &&query_request)
    {
        return Request(query_request.release());

    }

    inline Request to_request(plainRequest &plain_request)
    {
        return Request(plain_request.release());
    }

    inline Request to_request(plainRequest &&plain_request)
    {
        return Request(plain_request.release());
    }
} // namespace apsu
