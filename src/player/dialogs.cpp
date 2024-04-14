#include "../main.hpp"

static public_hook _dialogs_odr("OnDialogResponse", [](unsigned short playerid, short dialogid, bool response, int listitem, std::string inputtext) -> cell 
{
		auto& player = hyaxe::server_instance->get_player(playerid);
		if (!player)
			return ~1;

		if (dialogid != 422 || !player->dialog_cb())
			return 1;

		player->dialog_cb()(response, listitem, std::move(inputtext));
		return 1;
});