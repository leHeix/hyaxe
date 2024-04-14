#include "../../main.hpp"

static public_hook _auth_ogmi("OnGameModeInit", []() {
	hyaxe::server_instance->db().prepare("check_bans", R"(
			SELECT 
				BANS.*,
				ACCOUNT.NAME AS ADMIN_NAME,
				CURRENT_TIMESTAMP AS CURRENT_TIME,
				(EXPIRATION_DATE > CURRENT_TIMESTAMP) AS STILL_VALID
			FROM BANS
				LEFT JOIN ACCOUNT
					ON BANS.ADMIN_ID = ACCOUNT.ID
				WHERE BANS.BANNED_USER = $1 OR BANS.BANNED_IP = $2
			LIMIT 1;
		)");

	return 1;
});

static public_hook _auth_opc("OnPlayerConnect", [](unsigned short playerid) -> cell {
	auto& player = hyaxe::server_instance->get_player(playerid);

	console::print("player connected with name {}", player->name());

	static std::regex name_regex{ R"(^([A-Z][a-zA-Z]+)[ _]([A-Z][a-zA-Z]+)$)", std::regex::ECMAScript | std::regex::optimize };
	bool match = std::regex_match(player->name(), name_regex);
	if (!match)
	{
		player->kicked() = true;
		player->dialog_cb() = nullptr;
		player->show_dialog(DIALOG_STYLE_MSGBOX, "{CB3126}Hyaxe", 
			"{DADADA}Tu nombre no es adecuado, usa: {CB3126}N{DADADA}ombre_{CB3126}A{DADADA}pellido.\nRecuerda que los nombres como {CB3126}Miguel_Gamer{DADADA} o que contengan insultos\nno están permitidos, procura ponerte un nombre que parezca real.",
		"Entendido");
		
		std::function<void(unsigned short)> timer_cb = [](unsigned short playerid) {
			Kick(playerid);
		};

		timer::create(timer_cb, playerid)->start(300);
		return ~1;
	}

	pqxx::read_transaction w{ hyaxe::server_instance->db() };

	try
	{
		pqxx::row res = w.exec_prepared1("check_bans", player->name(), player->ip_as_string());

		std::string dialog_str = fmt::format(
			fmt::runtime("{{DADADA}}Esta {} está expulsada {} del servidor.\n\n"
				"{{CB3126}}{}\n\t{{DADADA}}{}\n\n"
				"{{CB3126}}Administrador\n\t{{DADADA}}{}\n\n"
				"{{CB3126}}Razón de la expulsión\n\t{{DADADA}}{}\n\n"
				"{{CB3126}}Fecha de la expulsión\n\t{{DADADA}}{}\n\n"
				"{{CB3126}}Fecha de expiración\n\t{{DADADA}}{}"),
			res["banned_user"].is_null() ? "dirección IP" : "cuenta", res["expiration_date"].is_null() ? "permanentemente" : "temporalmente",
			res["banned_user"].is_null() ? "Dirección IP" : "Nombre", res["banned_user"].is_null() ? res["banned_ip"].get<std::string>().value() : res["banned_user"].get<std::string>().value(),
			res["admin_id"].is_null() ? "Servidor" : fmt::format("{} ({})", res["admin_name"].get<std::string>().value(), res["admin_id"].as<int>()),
			res["reason"].get<std::string>().value_or("No especificada"),
			res["issued_date"].get<std::string>().value(),
			res["expiration_date"].is_null() ? "Indefinida" : res["expiration_date"].get<std::string>().value()
		);

		player->kicked() = true;
		player->dialog_cb() = nullptr;
		player->show_dialog(DIALOG_STYLE_MSGBOX, "{CB3126}Hyaxe {DADADA}- Expulsión", dialog_str, "Salir");

		std::function<void(unsigned short)> timer_cb = [](unsigned short playerid) {
			Kick(playerid);
		};

		timer::create(timer_cb, playerid)->start(300);
		return ~1;
	}
	catch (const pqxx::unexpected_rows& e){}


	EnablePlayerCameraTarget(playerid, true);

	return 1;
});