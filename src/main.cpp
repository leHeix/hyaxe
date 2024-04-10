// hyaxe.cpp : Defines the entry point for the application.
//

#include "main.hpp"

PLUGIN_EXPORT bool PLUGIN_CALL Load(void** ppData)
{
	return sampgdk::Load(ppData);
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