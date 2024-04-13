#pragma once

#ifdef __cplusplus

#include <string>
#include <string_view>
#include <utility>
#include <chrono>
#include <vector>
#include <memory>
#include <unordered_map>
#include <array>
#include <any>
#include <optional>
#include <functional>
#include <regex>

#else

#include <string.h>
#include <stdint.h>

#endif

#ifdef _WIN32
	#include <Windows.h>
#else
	#include <dlfcn.h>
	#include <link.h>
#endif