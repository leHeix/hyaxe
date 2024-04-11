#pragma once

#include "../main.hpp"

namespace hyaxe
{
	class server
	{
		std::array<std::unique_ptr<player>, MAX_PLAYERS> _players{};
	public:
		void register_player(unsigned short playerid);
		void delete_player(const std::unique_ptr<player>& player);
		void delete_player(unsigned short playerid);

		inline std::unique_ptr<player>& get_player(unsigned playerid) { return _players[playerid]; }
		inline const std::unique_ptr<player>& get_player(unsigned playerid) const { return _players[playerid]; }

		inline bool player_is_connected(unsigned short playerid) const
		{
			return _players[playerid] != nullptr;
		}
	};

	inline std::unique_ptr<server> server_instance;
}