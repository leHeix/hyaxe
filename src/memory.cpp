#include "main.hpp"

static bool ContainsInvalidChars(char* name)
{
#ifdef __clang__
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Winvalid-source-encoding"
#endif

	static const std::vector<short> valid_chars{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'_',
		'ï', 'ò', 'ù', 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ', '÷', 'ø', 'ö',
		'Š', 'Œ', 'Ž', 'š', 'ž', 'Ÿ', 'õ', 'À', 'Á', 'Â', 'Ã', 'Ä',
		'Å', 'Æ', 'Ç', 'ñ', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï',
		'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ø', 'Ù', 'Ú', 'Û', 'Ü',
		'Ý', 'Þ', 'ß', 'à', 'á', 'â', 'ã', 'ä', 'å', 'î', 'ç', 'è',
		'é', 'ê', 'ë', 'ì', 'í', ' '
	};

#ifdef __clang__
	#pragma clang diagnostic pop
#endif

	while (*name)
	{
		if (std::find(valid_chars.begin(), valid_chars.end(), *name++) == valid_chars.end())
			return true;
	}

	return false;
}

bool memory::setup()
{
#ifdef _WIN32
	urmem::sig_scanner scanner{};
	urmem::address_t base_address = (urmem::address_t)GetModuleHandle(NULL);

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

	//urmem::bytearray_t empty_mem{ WRONG_PACKET_ID_BRANCH_SIZE, 0x90 };
	//WrongPacketIDBranch_patch = urmem::patch::make(WRONG_PACKET_ID_BRANCH_ADDRESS, empty_mem);
	//WrongPacketIDBranch_patch->enable();
	console::print("nopped WrongPacketIDBranch");

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

unsigned int memory::find_pattern(const char* pattern, const char* mask)
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
