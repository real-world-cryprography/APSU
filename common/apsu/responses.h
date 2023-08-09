// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>
#include <utility>

// APSU
#include "apsu/network/receiver_operation_response.h"
#include "apsu/util/utils.h"

namespace apsu {
    /**
    A type representing a response to any response.
    */
    using Response = std::unique_ptr<network::ReceiverOperationResponse>;

    /**
    A type representing a response to a parameter response.
    */
    using ParamsResponse = std::unique_ptr<network::ReceiverOperationResponseParms>;

    /**
    A type representing a response to an OPRF response.
    */
    using OPRFResponse = std::unique_ptr<network::ReceiverOperationResponseOPRF>;

    /**
    A type representing a response to a query response.
    */
    using QueryResponse = std::unique_ptr<network::ReceiverOperationResponseQuery>;

    inline ParamsResponse to_params_response(Response &response)
    {
        if (nullptr == response ||
            response->type() != apsu::network::ReceiverOperationType::rop_parms)
            return nullptr;
        return ParamsResponse(
            static_cast<apsu::network::ReceiverOperationResponseParms *>(response.release()));
    }

    inline ParamsResponse to_params_response(Response &&response)
    {
        if (nullptr == response ||
            response->type() != apsu::network::ReceiverOperationType::rop_parms)
            return nullptr;
        return ParamsResponse(
            static_cast<apsu::network::ReceiverOperationResponseParms *>(response.release()));
    }

    inline OPRFResponse to_oprf_response(Response &response)
    {
        if (nullptr == response || response->type() != apsu::network::ReceiverOperationType::rop_oprf)
            return nullptr;
        return OPRFResponse(
            static_cast<apsu::network::ReceiverOperationResponseOPRF *>(response.release()));
    }

    inline OPRFResponse to_oprf_response(Response &&response)
    {
        if (nullptr == response || response->type() != apsu::network::ReceiverOperationType::rop_oprf)
            return nullptr;
        return OPRFResponse(
            static_cast<apsu::network::ReceiverOperationResponseOPRF *>(response.release()));
    }

    inline QueryResponse to_query_response(Response &response)
    {
        if (nullptr == response ||
            response->type() != apsu::network::ReceiverOperationType::rop_query)
            return nullptr;
        return QueryResponse(
            static_cast<apsu::network::ReceiverOperationResponseQuery *>(response.release()));
    }

    inline QueryResponse to_query_response(Response &&response)
    {
        if (nullptr == response ||
            response->type() != apsu::network::ReceiverOperationType::rop_query)
            return nullptr;
        return QueryResponse(
            static_cast<apsu::network::ReceiverOperationResponseQuery *>(response.release()));
    }

    inline Response to_response(ParamsResponse &params_response)
    {
        return Response(params_response.release());
    }

    inline Response to_response(ParamsResponse &&params_response)
    {
        return Response(params_response.release());
    }

    inline Response to_response(OPRFResponse &oprf_response)
    {
        return Response(oprf_response.release());
    }

    inline Response to_response(OPRFResponse &&oprf_response)
    {
        return Response(oprf_response.release());
    }

    inline Response to_response(QueryResponse &query_response)
    {
        return Response(query_response.release());
    }

    inline Response to_response(QueryResponse &&query_response)
    {
        return Response(query_response.release());
    }

    /**
    A type representing a partial query result.
    */
    using ResultPart = std::unique_ptr<network::ResultPackage>;
} // namespace apsu
