﻿#pragma once

// Precompiled headers
#include "pch.h"

#if _MSC_VER
	#define FASTCALL __fastcall
#else
	#define FASTCALL __attribute__((fastcall))
#endif

#define UV_THREADPOOL_SIZE 12

#include <fmt/core.h>
#include <fmt/color.h>
#include <fmt/chrono.h>
#include <samp-gdk/sampgdk.h>

#ifdef __clang__
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wunsequenced"
#endif
#include <RakNet/RakNet.h>
#ifdef __clang__
	#pragma clang diagnostic pop
#endif

#include <urmem/urmem.hpp>
#include <ankerl/unordered_dense.h>
#include <pqxx/pqxx>
#include <uv.h>
#include <botan_all.h>

#include "log.hpp"
#include "memory.hpp"
#include "raknet/rakserver.hpp"
#include "samp_console.hpp"

#include "server/publics.hpp"
#include "player/player.hpp"
#include "server/server.hpp"
#include "server/timers.hpp"
#include "player/auth/auth.hpp"

inline void** plugin_data{ nullptr };