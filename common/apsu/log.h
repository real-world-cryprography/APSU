// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstdarg>
#include <sstream>
#include <string>

#define APSU 1
#define ARBITARY 0
#define CARD 0
#define CARDSUM 0
namespace apsu {
    /**
    Class that provides the logging interface.
    */
    class Log {
    public:
        /**
        Supported log levels
        */
        enum class Level : int { all, debug, info, warning, error, off };

        /**
        This class is only to be used through its static methods.
        */
        Log() = delete;

        static void SetLogLevel(Level level);

        static Level GetLogLevel();

        static void SetLogLevel(const std::string &level);

        static void SetLogFile(const std::string &file);

        static void SetConsoleDisabled(bool console_disabled);

        static void ConfigureIfNeeded();

        static void Terminate();

        static void DoLog(std::string msg, Level msg_level);

    private:
        static void Configure();

        static Level log_level_;
    }; // class Log
} // namespace apsu

#define APSU_INTERNAL_CHECK_LOG_LEVEL(log_level) \
    apsu::Log::ConfigureIfNeeded();              \
    if (apsu::Log::GetLogLevel() > log_level) {  \
        break;                                   \
    }

#define APSU_INTERNAL_DO_LOG(msg, msg_level) \
    std::stringstream log_ss;                \
    log_ss << msg;                           \
    std::string log_str = log_ss.str();      \
    apsu::Log::DoLog(log_str, msg_level);

#define APSU_LOG_DEBUG(msg)                                     \
    do {                                                        \
        APSU_INTERNAL_CHECK_LOG_LEVEL(apsu::Log::Level::debug); \
        APSU_INTERNAL_DO_LOG(msg, apsu::Log::Level::debug);     \
    } while (0);

#define APSU_LOG_INFO(msg)                                     \
    do {                                                       \
        APSU_INTERNAL_CHECK_LOG_LEVEL(apsu::Log::Level::info); \
        APSU_INTERNAL_DO_LOG(msg, apsu::Log::Level::info);     \
    } while (0);

#define APSU_LOG_WARNING(msg)                                     \
    do {                                                          \
        APSU_INTERNAL_CHECK_LOG_LEVEL(apsu::Log::Level::warning); \
        APSU_INTERNAL_DO_LOG(msg, apsu::Log::Level::warning);     \
    } while (0);

#define APSU_LOG_ERROR(msg)                                     \
    do {                                                        \
        APSU_INTERNAL_CHECK_LOG_LEVEL(apsu::Log::Level::error); \
        APSU_INTERNAL_DO_LOG(msg, apsu::Log::Level::error);     \
    } while (0);
