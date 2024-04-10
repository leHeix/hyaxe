#pragma once

#include "main.hpp"

namespace console
{
	template<class... Args>
	void print(const std::string_view message, Args&&... args);
}