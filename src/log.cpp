#include "main.hpp"

template<class... Args>
void console::print(const std::string_view message, Args&&... args)
{
	std::string format_str{ "[{:%d-%m-%Y %X}] " };
	format_str.append(message);
	sampgdk::logprintf(fmt::format(fmt::runtime(format_str), fmt::localtime(std::time(nullptr)), std::forward<Args>(args)...).c_str());
}

void console::print_debug(const std::string& message, std::source_location src)
{
	std::string final_message = fmt::format("[{0:%d-%m-%Y %X}] {1}({2}:{3}) in function \"{4}\":\n[{0:%d-%m-%Y %X}] {5}", fmt::localtime(std::time(nullptr)), src.file_name(), src.line(), src.column(), src.function_name(), message);
	sampgdk::logprintf(final_message.c_str());
}