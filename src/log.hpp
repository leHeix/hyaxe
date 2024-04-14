#pragma once

#include "main.hpp"

namespace console
{
	struct X {};
	inline constexpr auto src = X{};

    struct source_location {
        source_location(const source_location&) = default;
        constexpr source_location(std::source_location loc = std::source_location::current()) {
            auto in = loc.file_name();
            for (auto out = str; *in++; *out++ = *in);
            line = loc.line();
        }
        constexpr source_location(X, std::source_location loc = std::source_location::current())
            : source_location(loc)
        {}
        char str[256] = {};
        int line = 0;
    };

	template<class... Args>
	void print(const std::string_view message, Args&&... args);
    void print_debug(const std::string& message, std::source_location src = std::source_location::current());
}