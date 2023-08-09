// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <fstream>
#include <utility>
#include <vector>

// APSU
#include "apsu/log.h"
#include "common/common_utils.h"
#include "receiver/receiver_utils.h"

// SEAL
#include "seal/modulus.h"

using namespace std;
using namespace seal;
using namespace apsu;

unique_ptr<PSUParams> build_psu_params(const CLP &cmd)
{
    string params_json;

    try {
        throw_if_file_invalid(cmd.params_file());
        fstream input_file(cmd.params_file(), ios_base::in);

        if (!input_file.is_open()) {
            APSU_LOG_ERROR("File " << cmd.params_file() << " could not be open for reading.");
            throw runtime_error("Could not open params file");
        }

        string line;
        while (getline(input_file, line)) {
            params_json.append(line);
            params_json.append("\n");
        }

        input_file.close();
    } catch (const exception &ex) {
        APSU_LOG_ERROR(
            "Error trying to read input file " << cmd.params_file() << ": " << ex.what());
        return nullptr;
    }

    unique_ptr<PSUParams> params;
    try {
        params = make_unique<PSUParams>(PSUParams::Load(params_json));
    } catch (const exception &ex) {
        APSU_LOG_ERROR("APSU threw an exception creating PSUParams: " << ex.what());
        return nullptr;
    }

    APSU_LOG_INFO(
        "PSUParams have false-positive probability 2^(" << params->log2_fpp()
                                                        << ") per receiver item");

    return params;
}
