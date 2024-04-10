#include "main.hpp"

static bool ContainsInvalidChars(char* name)
{
	return true;
}

bool hooks::install()
{
#ifdef _WIN32
	urmem::sig_scanner scanner{};
	urmem::address_t base_address{};
	base_address = (urmem::address_t)GetModuleHandle(NULL);

	if (!scanner.init(base_address))
	{
		console::print("failed to install hooks: scanner initialization failed");
		return false;
	}
#endif

	urmem::address_t ContainsInvalidChars_addr{};

#ifdef _WIN32
	if (scanner.find("\x8B\x4C\x24\x04\x8A\x01\x84\xC0", "xxxxxxxx", ContainsInvalidChars_addr))
	{
#else
	if ((ContainsInvalidChars_addr = find_pattern("\x53\x8B\x5D\x00\x0F\xB6\x0B\x84\xC9\x74\x00\x66\x90", "xxx?xxxxxx?xx")) != 0)
	{
		ContainsInvalidChars_addr -= 0x3;
#endif

		ContainsInvalidChars_hook.install(ContainsInvalidChars_addr, urmem::get_func_addr(&ContainsInvalidChars));
		console::print("installed hook: ContainsInvalidChars");
	}
	else
	{
		console::print("failed to install hook: ContainsInvalidChars");
		return false;
	}

	console::print("all hooks installed successfully");
	return true;
}

// Taken from https://github.com/IS4Code/YSF/blob/master/src/Memory.cpp

#ifdef __linux__

static bool memory_compare(const char* data, const char* pattern, const char* mask)
{
	for (; *mask; ++mask, ++data, ++pattern)
	{
		if (*mask == 'x' && *data != *pattern)
			return false;
	}
	return (*mask) == NULL;
}
#endif

unsigned int hooks::find_pattern(const char* pattern, const char* mask)
{
#ifdef __linux__
	struct {
		unsigned int result;
		const char* pattern;
		const char* mask;
	} info{ 0, pattern, mask };
	dl_iterate_phdr([](struct dl_phdr_info* sym_info, size_t, void* data) {
		auto search_info = reinterpret_cast<decltype(info)*>(data);

		for (int s = 0; s < sym_info->dlpi_phnum; ++s)
		{
			unsigned int address = sym_info->dlpi_addr + sym_info->dlpi_phdr[s].p_vaddr;
			unsigned int size = sym_info->dlpi_phdr[s].p_memsz;
			for (unsigned int i = 0; i < size; ++i)
			{
				if (memory_compare((char*)(address + i), search_info->pattern, search_info->mask))
				{
					search_info->result = (address + i);
					return 1;
				}
			}
		}

		return 1;
	}, reinterpret_cast<void*>(&info));

	return info.result;
#else
	return 0;
#endif
}
