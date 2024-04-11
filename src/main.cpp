#include "main.hpp"

PLUGIN_EXPORT bool PLUGIN_CALL Load(void** ppData)
{
	plugin_data = ppData;

	bool result = sampgdk::Load(ppData);
	if (result)
	{
		console::print("sampgdk loaded");
		hooks::install();
	}
	
	return result;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	sampgdk::Unload();
}

PLUGIN_EXPORT unsigned PLUGIN_CALL Supports()
{
	return sampgdk::Supports() | SUPPORTS_PROCESS_TICK;
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	return;
}