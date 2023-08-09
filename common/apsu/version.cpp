// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// APSU
#include "apsu/config.h"
#include "apsu/version.h"

namespace apsu {
    const uint32_t apsu_version =
        (APSU_VERSION_PATCH << 20) + (APSU_VERSION_MINOR << 10) + APSU_VERSION_MAJOR;

    const uint32_t apsu_serialization_version = 1;

    bool same_serialization_version(uint32_t sv)
    {
        return sv == apsu_serialization_version;
    }
} // namespace apsu
