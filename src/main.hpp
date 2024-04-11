#pragma once

// Precompiled headers
#include "pch.h"

#if _MSC_VER
	#define FASTCALL __fastcall
#else
	#define FASTCALL __attribute__((fastcall))
#endif

#include <fmt/core.h>
#include <fmt/color.h>
#include <fmt/chrono.h>
#include <samp-gdk/sampgdk.h>
#include <RakNet/RakNet.h>
#include <urmem/urmem.hpp>
#include <ankerl/unordered_dense.h>

#include "log.hpp"
#include "hooks.hpp"
#include "raknet/rakserver.hpp"

#include "player/player.hpp"
#include "server/server.hpp"

inline void** plugin_data{ nullptr };