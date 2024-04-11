#include "../main.hpp"
#include "server.hpp"

void hyaxe::server::register_player(unsigned short playerid)
{
	_players[playerid] = std::make_unique<player>(playerid);
	console::print("registered player {} on server", playerid);
}

void hyaxe::server::delete_player(const std::unique_ptr<player>& player)
{
	_players[player->id()].reset();
}

void hyaxe::server::delete_player(unsigned short playerid)
{
	_players[playerid].reset();
}

PLUGIN_EXPORT bool PLUGIN_CALL OnPlayerConnect(int playerid) {
	console::print("player connected with id {}", playerid);
	hyaxe::server_instance->register_player(playerid);
	return true;
}

static public_hook<callbacks::exec_order::init> _("OnGameModeInit", []() -> cell {
	rakserver_instance = std::make_unique<rakserver>();
	if (!rakserver_instance->initialize(plugin_data))
	{
		console::print("failed to initialize rakserver");
		sampgdk::Unload();
		return ~1;
	}

	console::print("rakserver initialized successfully");

	hyaxe::server_instance = std::make_unique<hyaxe::server>();
	console::print("initialization finished");

	return 1;
});