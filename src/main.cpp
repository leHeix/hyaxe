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

PLUGIN_EXPORT bool PLUGIN_CALL OnGameModeInit()
{
	rakserver_instance = std::make_unique<rakserver>();
	if (!rakserver_instance->initialize(plugin_data))
	{
		console::print("failed to initialize rakserver");
		sampgdk::Unload();
		return false;
	}

	console::print("rakserver initialized successfully");
	
	hyaxe::server_instance = std::make_unique<hyaxe::server>();
	console::print("load finished");
	return true;
}