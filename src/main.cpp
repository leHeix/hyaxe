#include "main.hpp"

PLUGIN_EXPORT bool PLUGIN_CALL Load(void** ppData)
{
	plugin_data = ppData;

	bool result = sampgdk::Load(ppData);
	if (result)
	{
		console::print("sampgdk loaded");
		memory::setup();
	}
	
	return result;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	if (uv_loop_close(uv_default_loop()) == UV_EBUSY)
	{
		uv_walk(uv_default_loop(), [](uv_handle_t* h, void* /*arg*/) {
			uv_close(h, [](uv_handle_t* h) {
				if (!h || !h->loop || uv_is_closing(h))
					return;
			});
		}, nullptr);
		uv_run(uv_default_loop(), UV_RUN_DEFAULT);
		uv_loop_close(uv_default_loop());
	}

	sampgdk::Unload();
}

PLUGIN_EXPORT unsigned PLUGIN_CALL Supports()
{
	return sampgdk::Supports() | SUPPORTS_PROCESS_TICK;
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	uv_run(uv_default_loop(), UV_RUN_NOWAIT);
}