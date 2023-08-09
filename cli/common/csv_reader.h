// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

// APSU
#include "apsu/item.h"
#include "apsu/psu_params.h"
#include "apsu/util/db_encoding.h"

/**
Simple CSV file parser
*/
class CSVReader {
public:
    using UnlabeledData = std::vector<apsu::Item>;

    using LabeledData = std::vector<std::pair<apsu::Item, apsu::Label>>;

    using DBData = std::variant<UnlabeledData, LabeledData>;

    CSVReader();

    CSVReader(const std::string &file_name);

    std::pair<DBData, std::vector<std::string>> read(std::istream &stream) const;

    std::pair<DBData, std::vector<std::string>> read() const;

private:
    std::string file_name_;

    std::pair<bool, bool> process_line(
        const std::string &line,
        std::string &orig_item,
        apsu::Item &item,
        apsu::Label &label) const;
}; // class CSVReader
