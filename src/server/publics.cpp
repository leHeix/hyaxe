#include "../main.hpp"

PLUGIN_EXPORT bool PLUGIN_CALL OnPublicCall(AMX* amx, const char* name, cell* params, cell* retval)
{
	const std::string_view name_sv{ name };
	auto func_hooks_iter = callbacks::get_public_hooks().find(name_sv);
	if (func_hooks_iter != callbacks::get_public_hooks().end())
	{
		auto func_hooks = func_hooks_iter->second;
		for (auto&& hook : func_hooks)
		{
			cell ret = hook.call(amx, params);
			if (ret == ~0 || ret == ~1)
			{
				if (retval)
					*retval = ~ret;
				break;
			}
			else
			{
				if (retval)
					*retval = ret;
			}
		}
	}

	return true;
}