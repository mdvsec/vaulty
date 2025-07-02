#pragma once

#include <spdlog/spdlog.h>

namespace vaulty {

#ifdef DEBUG_MODE

#define LOG_DEBUG(...)  spdlog::debug(__VA_ARGS__)
#define LOG_INFO(...)   spdlog::info(__VA_ARGS__)

#else

#define LOG_DEBUG(...)
#define LOG_INFO(...)

#endif /* DEBUG_MODE */

#define LOG_WARN(...)   spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...)  spdlog::error(__VA_ARGS__)

} /* namespace vaulty */
