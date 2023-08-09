// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdint>

namespace apsu {
    extern const std::uint32_t apsu_version;

    extern const std::uint32_t apsu_serialization_version;

    bool same_serialization_version(std::uint32_t sv);
} // namespace apsu
