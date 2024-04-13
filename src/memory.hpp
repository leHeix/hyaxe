#pragma once

#include "main.hpp"

#ifdef _WIN32	
	#define WRONG_PACKET_ID_BRANCH_ADDRESS 0x004591FC
	#define WRONG_PACKET_ID_BRANCH_SIZE 82
#else
	#define WRONG_PACKET_ID_BRANCH_ADDRESS 0x080752FC
	#define WRONG_PACKET_ID_BRANCH_SIZE 114
#endif

namespace memory
{
	bool setup();
	unsigned int find_pattern(const char* pattern, const char* mask);

	inline urmem::hook ContainsInvalidChars_hook{};
	inline std::shared_ptr<urmem::patch> WrongPacketIDBranch_patch;
}