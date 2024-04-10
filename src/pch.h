#pragma once

#ifdef __cplusplus

#include <string>
#include <string_view>
#include <utility>
#include <chrono>

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