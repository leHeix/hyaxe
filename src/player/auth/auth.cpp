#include "../../main.hpp"

static void email_dialog_callback(std::reference_wrapper<std::unique_ptr<player>> player, bool response, int listitem, std::string inputtext);
static void sex_dialog_callback(std::reference_wrapper<std::unique_ptr<player>> player, bool response, int listitem, std::string inputtext);

static void password_dialog_callback(std::reference_wrapper<std::unique_ptr<player>> player_ref, bool response, int listitem, std::string inputtext)
{
	auto& player = player_ref.get();

	player->play_sound(sounds::button);

	if (!response)
	{
		player->kicked() = true;
		Kick(player->id());
		return;
	}

	if (inputtext.length() < 6 || inputtext.length() > 18)
	{
		player->show_dialog(DIALOG_STYLE_PASSWORD, "{CB3126}Hyaxe{DADADA} - Registrar una cuenta",
			fmt::format(
				"{{DADADA}}Hola, {{CB3126}}{}{{DADADA}}. Esta cuenta no está registrada.\n\n"
				"\t{{E3E3E3}}1. Contraseña\n"
				"\t{{5C5C5C}}2. Correo\n"
				"\t{{5C5C5C}}3. Sexo del personaje\n\n"
				"{{DADADA}}Ingrese una contraseña de entre 6 y 18 caracteres de longitud.",
				player->name()
			),
			"Continuar", "Cancelar");
		return;
	}

	player->set_data("auth:password", inputtext);

	player->dialog_cb() = std::bind(&email_dialog_callback, player_ref, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
	player->show_dialog(DIALOG_STYLE_INPUT, "{CB3126}Hyaxe{DADADA} - Registrar una cuenta",
		fmt::format(
			"{{DADADA}}Hola, {{CB3126}}{}{{DADADA}}. Esta cuenta no está registrada.\n\n"
			"\t{{5C5C5C}}1. Contraseña\n"
			"\t{{E3E3E3}}2. Correo\n"
			"\t{{5C5C5C}}3. Sexo del personaje\n\n"
			"{{DADADA}}Ingrese su dirección de correo electrónico.\n"
			"Esto le va a servir para poder recuperar su contraseña\n"
			"en caso que se la olvide.",
			player->name()
		),
	"Continuar", "Cancelar");
}

static void email_dialog_callback(std::reference_wrapper<std::unique_ptr<player>> player_ref, bool response, int listitem, std::string inputtext)
{
	auto& player = player_ref.get();

	if (!response)
	{
		player->dialog_cb() = std::bind(&password_dialog_callback, player_ref, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
		player->show_dialog(DIALOG_STYLE_PASSWORD, "{CB3126}Hyaxe{DADADA} - Registrar una cuenta",
			fmt::format(
				"{{DADADA}}Hola, {{CB3126}}{}{{DADADA}}. Esta cuenta no está registrada.\n\n"
				"\t{{E3E3E3}}1. Contraseña\n"
				"\t{{5C5C5C}}2. Correo\n"
				"\t{{5C5C5C}}3. Sexo del personaje\n\n"
				"{{DADADA}}Ingrese una contraseña de entre 6 y 18 caracteres de longitud.",
				player->name()
			),
		"Continuar", "Cancelar");
		return;
	}

	static std::regex email_regex{ "^[\\w\\d.!#$%&'*+/=?^`{|}~-]+@[\\w\\d-]+\\.[\\w\\d-]{2,11}$", std::regex::optimize };
	if (!std::regex_match(inputtext, email_regex))
	{
		player->show_dialog(DIALOG_STYLE_INPUT, "{CB3126}Hyaxe{DADADA} - Registrar una cuenta",
			fmt::format(
				"{{DADADA}}Hola, {{CB3126}}{}{{DADADA}}. Esta cuenta no está registrada.\n\n"
				"\t{{5C5C5C}}1. Contraseña\n"
				"\t{{E3E3E3}}2. Correo\n"
				"\t{{5C5C5C}}3. Sexo del personaje\n\n"
				"{{DADADA}}Ingrese una dirección de correo válida.",
				player->name()
			),
		"Continuar", "Cancelar");
		return;
	}

	pqxx::work w{ hyaxe::server_instance->db() };

	pqxx::result res = w.exec("SELECT EXISTS(SELECT * FROM ACCOUNT WHERE EMAIL = '" + w.esc(inputtext) + "');");
	w.commit();

	if (res[0][0].get<bool>().value_or(false))
	{
		player->show_dialog(DIALOG_STYLE_INPUT, "{CB3126}Hyaxe{DADADA} - Registrar una cuenta",
			fmt::format(
				"{{DADADA}}Hola, {{CB3126}}{}{{DADADA}}. Esta cuenta no está registrada.\n\n"
				"\t{{5C5C5C}}1. Contraseña\n"
				"\t{{E3E3E3}}2. Correo\n"
				"\t{{5C5C5C}}3. Sexo del personaje\n\n"
				"{{DADADA}}La dirección de correo que proporcionó ya está en uso.",
				player->name()
			),
		"Continuar", "Cancelar");
		return;
	}

	player->set_data("auth:email", inputtext);
	player->dialog_cb() = std::bind(&sex_dialog_callback, player_ref, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
	player->show_dialog(DIALOG_STYLE_MSGBOX, "{CB3126}Hyaxe{DADADA} - Registrar una cuenta",
		fmt::format(
			"{{DADADA}}Hola, {{CB3126}}{}{{DADADA}}. Esta cuenta no está registrada.\n\n"
			"\t{{5C5C5C}}1. Contraseña\n"
			"\t{{5C5C5C}}2. Correo\n"
			"\t{{E3E3E3}}3. Sexo del personaje\n\n"
			"{{DADADA}}Escoja el sexo de su personaje.",
			player->name()
		),
	"Hombre", "Mujer");
}

static void sex_dialog_callback(std::reference_wrapper<std::unique_ptr<player>> player_ref, bool response, int listitem, std::string inputtext)
{
	auto& player = player_ref.get();

	player->_sex = (response ? player::sex_male : player::sex_female);
	player->_money = 2000;
	player->_xp = 0;
	player->_level = 1;
	player->_pos_x = 1728.8326f;
	player->_pos_y = -1174.8977f;
	player->_pos_z = 23.8315f;
	player->_angle = 45.1207f;
	player->_skin = (response ? 250 : 192);
	player->_health = 100.f;
	player->_armor = 0.f;

	uv_work_t* work = new uv_work_t;
	work->data = reinterpret_cast<void*>(player->id());
	uv_queue_work(uv_default_loop(), work, [](uv_work_t* work) {
		unsigned short playerid = reinterpret_cast<unsigned short>(work->data);
		if (!hyaxe::server_instance->player_is_connected(playerid))
			return;

		auto& player = hyaxe::server_instance->get_player(playerid);

		auto password_opt = player->get_data<std::string>("auth:password");
		if (!password_opt.has_value())
			return;

		player->set_data("auth:password", Botan::generate_bcrypt(password_opt.value(), Botan::system_rng(), 12));
	}, [](uv_work_t* work, int status) {
		if (status == UV_ECANCELED)
		{
			delete work;
			return;
		}

		unsigned short playerid = reinterpret_cast<unsigned short>(work->data);
		if (!hyaxe::server_instance->player_is_connected(playerid))
			return;

		auto& player = hyaxe::server_instance->get_player(playerid);
		player->register_account();

		delete work;
	});
}

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

	TogglePlayerSpectating(playerid, true);

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

	pqxx::work w{ hyaxe::server_instance->db() };

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

	player->flags().set(player::flags::authenticating);

	pqxx::result res = w.exec("SELECT PASSWORD FROM ACCOUNT WHERE NAME = '" + w.esc(player->name()) + "';");
	if (res.empty())
	{
		player->dialog_cb() = std::bind(&password_dialog_callback, std::ref(player), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
		player->show_dialog(DIALOG_STYLE_PASSWORD, "{CB3126}Hyaxe{DADADA} - Registrar una cuenta", 
			fmt::format(
				"{{DADADA}}Hola, {{CB3126}}{}{{DADADA}}. Esta cuenta no está registrada.\n\n"
					"\t{{E3E3E3}}1. Contraseña\n"
					"\t{{5C5C5C}}2. Correo\n"
					"\t{{5C5C5C}}3. Sexo del personaje\n\n"
				"{{DADADA}}Ingrese una contraseña de entre 6 y 18 caracteres de longitud.",
				player->name()
			),
		"Continuar", "Cancelar");
	}
	else
	{

	}

	w.commit();

	return 1;
});