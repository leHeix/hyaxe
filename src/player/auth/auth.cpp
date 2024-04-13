#include "../../main.hpp"

static public_hook _auth_opc("OnPlayerConnect", [](unsigned short playerid) -> cell {
	auto& player = hyaxe::server_instance->get_player(playerid);

	static std::regex name_regex{ "[A-Z][a-zA-Z]+[ _][A-Z][a-zA-Z]+$", std::regex::optimize };
	if (!std::regex_match(player->name(), name_regex))
	{
		player->kicked() = true;
		player->set_dialog_cb(nullptr);
		player->show_dialog(DIALOG_STYLE_MSGBOX, "{CB3126}Hyaxe", 
			"{DADADA}Tu nombre no es adecuado, usa: {CB3126}N{DADADA}ombre_{CB3126}A{DADADA}pellido.\n\
            Recuerda que los nombres como {CB3126}Miguel_Gamer{DADADA} o que contengan insultos\n\
            no están permitidos, procura ponerte un nombre que parezca real.",
		"Entendido");

		return ~1;
	}

	return 1;
});