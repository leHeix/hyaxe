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