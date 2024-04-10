#pragma once

#include "main.hpp"

namespace hooks
{
	bool install();
	unsigned int find_pattern(const char* pattern, const char* mask);

	inline urmem::hook ContainsInvalidChars_hook{};
}