#include "main.hpp"

bool samp_console::initialize(void** plugin_data)
{
	_console = reinterpret_cast<uintptr_t(*)()>(plugin_data[PLUGIN_DATA_CONSOLE])();
	urmem::address_t temp_addr{};

#ifdef _WIN32
	urmem::sig_scanner scanner;

	if (!scanner.init(reinterpret_cast<urmem::address_t>(*plugin_data)))
	{
		console::print("failed to initialize samp_console: scanner initialization failed");
		return false;
	}

#define SCAN_PATTERN(function,pattern,mask); \
		if(!scanner.find(pattern, mask, _##function##_fun)) \
		{ \
			console::print("failed to initialize samp_console: couldn't find function CConsole::"#function); \
			return false; \
		}

	SCAN_PATTERN(AddStringVariable, "\x53\x56\x57\x8B\x7C\x24\x18\x85\xFF", "xxxxxxxxx");
	SCAN_PATTERN(GetStringVariable, "\x8B\x44\x24\x04\x50\xE8\x00\x00\x00\x00\x85\xC0\x74\x0B", "xxxxxx????xxxx");
	SCAN_PATTERN(SetStringVariable, "\x8B\x44\x24\x04\x53\x50\xE8\xD5\xFE\xFF\xFF\x8B\xD8\x85\xDB", "xxxxxxx???xxxx");
	SCAN_PATTERN(GetIntVariable, "\x8B\x44\x24\x04\x50\xE8\x00\x00\x00\x00\x85\xC0\x74\x0D\x83\x38\x01\x75\x08", "xxxxxx????xxxxxxxxx");
	SCAN_PATTERN(SetIntVariable, "\x8B\x44\x24\x04\x50\xE8\xF6\xFD\xFF\xFF\x85\xC0\x74\xE0\x83\x38\x01", "xxxxxx????xx??xxx");
	_SetIntVariable_fun += 0x20;
	SCAN_PATTERN(GetBoolVariable, "\x8B\x44\x24\x04\x50\xE8\x00\x00\x00\x00\x85\xC0\x74\x0D\x83\x38\x01\x75\x08", "xxxxxx????xxxxxxxxx");
	_GetBoolVariable_fun += 0x90;
	SCAN_PATTERN(ModifyVariableFlags, "\x8B\x44\x24\x04\x50\xE8\x16\xFF\xFF\xFF\x85\xC0\x74\x07", "xxxxxx????xxxx");
	SCAN_PATTERN(FindVariable, "\x8B\x84\x24\x30\x01\x00\x00\x53\x56\x57", "xxxxxxxxxx");
	_FindVariable_fun -= 0x1B;
	SCAN_PATTERN(SendRules, "\x81\xEC\x08\x04\x00\x00\x53\x55\x56\x57\x8B\xF9\x8B\x77\x04", "xx????xxxxxxxxx");
	SCAN_PATTERN(Execute, "\x55\x8B\xEC\x83\xE4\xF8\x81\xEC\x0C\x01\x00\x00", "xxxxxxxxxxxx");
#else
	#define SCAN_PATTERN(function,pattern,mask) \
			if((temp_addr = memory::find_pattern(pattern, mask) == 0) \
			{ \
				console::print("failed to initialize samp_console: couldn't find function CConsole::"#function); \
				return false; \
			} \
			_##function##_fun = temp_addr;

	SCAN_PATTERN(AddStringVariable, "\x55\x89\xE5\x56\x53\x83\xEC\x00\x8B\x75\x00\x85\xF6\x74\x00\x89\x34\x24", "xxxxxxx?xx?xxx?xxx");
	_GetStringVariable_fun = _AddStringVariable_fun - 0x760;
	SCAN_PATTERN(SetStringVariable, "\x55\x89\xE5\x83\xEC\x00\x89\x75\x00\x8B\x45\x00\x89\x7D\x00\x8B\x7D\x00\x89\x5D\x00\x89\x44\x24\x00\x8B\x45\x00", "xxxxx?xx?xx?xx?xx?xx?xxx?xx?");
	SCAN_PATTERN(SetIntVariable, "\x83\x38\x00\x74\x00\xC9\xC3\x8B\x50\x00\x8B\x45\x00", "xx?x?xxxx?xx?");
	_SetIntVariable_fun -= 0x1C;
	_GetIntVariable_fun = _SetIntVariable_fun + 0x30;
	_GetBoolVariable_fun = _SetIntVariable_fun - 0x30;
	SCAN_PATTERN(ModifyVariableFlags, "\x89\x04\x24\xE8\x00\x00\x00\x00\x85\xC0\x89\xC2\x74\x00\x8B\x45\x00", "xxxx????xxxxx?xx?");
	_ModifyVariableFlags_fun -= 0x10;
	SCAN_PATTERN(FindVariable, "\xB9\xFF\x00\x00\x00\x89\xE5\x81\xEC\x68\x01\x00\x00", "xxxxxxxxxxxxx");
	_FindVariable_fun -= 0x1;
	SCAN_PATTERN(SendRules, "\x55\x31\xD2\x89\xE5\x57\x56\x53\x81\xEC\x4C\x04", "xxxxxxxxxxxx");
	SCAN_PATTERN(Execute, "\x55\x89\xE5\x57\x56\x53\x81\xEC\x3C\x01\x00\x00\x8B\x45\x0C", "xxxxxxxxxxxxxxx");
#endif

	#undef SCAN_PATTERN

	return true;
}

void samp_console::add_string_variable(const std::string_view rule, int flags, const std::string_view value, void* changefunc)
{
	urmem::call_function<urmem::calling_convention::thiscall>(_AddStringVariable_fun, _console, rule.data(), flags, value.data(), changefunc);
}

template<class T>
T samp_console::get_variable(const std::string_view rule)
{
	if constexpr (std::is_same_v<T, std::string>)
	{
		char* var = urmem::call_function<urmem::calling_convention::thiscall, char*>(_GetStringVariable_fun, _console, rule.data());
		return std::string{ var };
	}
	else if constexpr (std::is_same_v<T, int>)
	{
		return urmem::call_function<urmem::calling_convention::thiscall, int>(_GetIntVariable_fun, _console, rule.data());
	}
	else if constexpr (std::is_same_v<T, bool>)
	{
		return urmem::call_function<urmem::calling_convention::thiscall, bool>(_GetBoolVariable_fun, _console, rule.data());
	}
	else
		static_assert(false, "Invalid type");

	return T{};
}

template<class T>
void samp_console::set_variable(const std::string_view rule, T value)
{
	if constexpr (std::is_same_v<T, std::string>)
	{
		urmem::call_function<urmem::calling_convention::thiscall>(_SetStringVariable_fun, _console, rule.data(), value.c_str());
	}
	else if constexpr (std::is_same_v<T, char*> || std::is_same_v<T, const char*>)
	{
		urmem::call_function<urmem::calling_convention::thiscall>(_SetStringVariable_fun, _console, rule.data(), value);
	}
	else if constexpr (std::is_same_v<T, int>)
	{
		urmem::call_function<urmem::calling_convention::thiscall>(_SetIntVariable_fun, _console, rule.data(), value);
	}
	else
		static_assert(false, "Invalid type");
}

inline void samp_console::modify_variable_flags(const std::string_view rule, int flags)
{
	urmem::call_function<urmem::calling_convention::thiscall>(_ModifyVariableFlags_fun, _console, rule.data(), flags);
}

inline console_variable* samp_console::find_variable(const std::string_view rule)
{
	return urmem::call_function<urmem::calling_convention::thiscall, console_variable*>(_FindVariable_fun, _console, rule.data());
}

inline void samp_console::send_rules(SOCKET s, const char* data, const sockaddr_in* to, int tolen)
{
	urmem::call_function<urmem::calling_convention::thiscall>(_SendRules_fun, _console, s, data, to, tolen);
}

inline void samp_console::execute(const std::string_view command)
{
	urmem::call_function<urmem::calling_convention::thiscall>(_Execute_fun, _console, command.data());
}