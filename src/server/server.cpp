#include "../main.hpp"
#include "server.hpp"

hyaxe::server::server()
{
	_db = std::make_unique<pqxx::connection>("hostaddr=127.0.0.1 port=5432 dbname=hyaxe user=postgres password=postgres");
	console::print("connected to database");

	UsePlayerPedAnims();
	DisableInteriorEnterExits();
	EnableStuntBonusForAll(false);
	ManualVehicleEngineAndLights();
	ShowPlayerMarkers(PLAYER_MARKERS_MODE_GLOBAL);
	SetNameTagDrawDistance(25.f);
}

void hyaxe::server::add_player(unsigned short playerid)
{
	_players[playerid] = std::make_unique<player>(playerid);
	console::print("registered player {} on server", playerid);
}

void hyaxe::server::delete_player(const std::unique_ptr<player>& player)
{
	console::print("deleted player {} on server", player->id());
	_players[player->id()].reset();
}

void hyaxe::server::delete_player(unsigned short playerid)
{
	_players[playerid].reset();
	console::print("deleted player {} on server", playerid);
}

static public_hook<callbacks::exec_order::init> _sv_init_ogmi("OnGameModeInit", []() -> cell {
	rakserver_instance = std::make_unique<rakserver>();
	if (!rakserver_instance->initialize(plugin_data))
	{
		console::print("failed to initialize rakserver");
		std::terminate();
		return ~1;
	}

	console::print("rakserver initialized successfully");

	hyaxe::server_instance = std::make_unique<hyaxe::server>();
	console::print("initialization finished");

	std::function<void(int)> timer_cb = [](int mamaguebo) {
		console::print("mamaguebo: {}", mamaguebo);
	};

	auto timerp = timer::create(timer_cb, 422);
	timerp->start(3000, true);

	return 1;
});

static public_hook<callbacks::exec_order::init> _init_opc("OnPlayerConnect", [](unsigned short playerid) -> cell {
	hyaxe::server_instance->add_player(playerid);
	return 1;
});

static public_hook<callbacks::exec_order::final> _rm_opd("OnPlayerDisconnect", [](unsigned short playerid, unsigned char reason) -> cell {
	hyaxe::server_instance->delete_player(playerid);
	return 1;
});