#include "main.hpp"

template<class... Args>
void console::print(const std::string_view message, Args&&... args)
{
	std::string format_str{ "[{:%Y-%m-%d %X}] " };
	format_str.append(message);
	sampgdk::logprintf(fmt::format(fmt::runtime(format_str), fmt::localtime(std::time(nullptr)), std::forward<Args>(args)...).c_str());
}