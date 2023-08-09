// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>

// APSU
#include "apsu/psu_params.h"
#include "receiver/clp.h"

std::unique_ptr<apsu::PSUParams> build_psu_params(const CLP &cmd);
