#pragma once

#include "main.hpp"

enum CON_VARTYPE
{
	CON_VARTYPE_FLOAT,
	CON_VARTYPE_INT,
	CON_VARTYPE_BOOL,
	CON_VARTYPE_STRING
};

constexpr auto CON_VARFLAG_DEBUG = 1;
constexpr auto CON_VARFLAG_READONLY = 2;
constexpr auto CON_VARFLAG_RULE = 4;

struct console_variable
{
	CON_VARTYPE var_type;
	std::uint32_t var_flags;
	void* var_ptr;
	void(*VARCHANGEFUNC)();
};

class samp_console
{
private:
	urmem::address_t _console{};
	urmem::address_t _AddStringVariable_fun{};
	urmem::address_t _GetStringVariable_fun{};
	urmem::address_t _SetStringVariable_fun{};
	urmem::address_t _GetIntVariable_fun{};
	urmem::address_t _SetIntVariable_fun{};
	urmem::address_t _GetBoolVariable_fun{};
	urmem::address_t _ModifyVariableFlags_fun{};
	urmem::address_t _FindVariable_fun{};
	urmem::address_t _SendRules_fun{};
	urmem::address_t _Execute_fun{};

public:
	samp_console() = default;
	bool initialize(void** plugin_data);

	void add_string_variable(const std::string_view rule, int flags, const std::string_view value, void* changefunc);

	template<class T>
	T get_variable(const std::string_view rule);

	template<class T>
	void set_variable(const std::string_view rule, T value);

	inline void modify_variable_flags(const std::string_view rule, int flags);
	inline console_variable* find_variable(const std::string_view rule);
	inline void send_rules(SOCKET s, const char* data, const sockaddr_in* to, int tolen);
	inline void execute(const std::string_view command);
};

inline std::unique_ptr<samp_console> samp_console_instance{};