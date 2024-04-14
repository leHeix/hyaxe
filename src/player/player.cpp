#include "../main.hpp"

player::~player()
{
	_data.clear();
}

bool player::register_account()
{
	pqxx::work w{ hyaxe::server_instance->db() };

	pqxx::result res = w.exec(
		fmt::format(
			fmt::runtime("INSERT INTO ACCOUNT "
				"(NAME, EMAIL, PASSWORD, SKIN, SEX, LEVEL, XP, MONEY, POS_X, POS_Y, POS_Z, ANGLE, CURRENT_CONNECTION, CURRENT_PLAYERID, CONFIG_BITS) "
			"VALUES "
				"('{}', '{}', '{}', {}, {}, 1, 0, {}, {}, {}, {}, {}, EXTRACT(EPOCH FROM NOW()), {}, B'{}') RETURNING ID;"),
			w.esc(_name), w.esc(get_data<std::string>("auth:email").value()), get_data<std::string>("auth:password").value(), 
			_skin, _sex, _money, _pos_x, _pos_y, _pos_z, _angle, _playerid, _config.to_string()
		)
	);

	if (res.empty())
	{
		return false;
	}

	_account_id = res[0][0].get<int>().value_or(0);
	if (_account_id == 0)
		return false;

	w.exec(fmt::format("INSERT INTO CONNECTION_LOG (ACCOUNT_ID, IP_ADDRESS) VALUES ({}, '{}');", _account_id, ip_as_string()));
	w.commit();

	_flags.set(flags::registered);
	_flags.set(flags::authenticating, false);

	SetSpawnInfo(_playerid, NO_TEAM, _skin, _pos_x, _pos_y, _pos_z, _angle, 0, 0, 0, 0, 0, 0);
	TogglePlayerSpectating(_playerid, false);

	ResetPlayerMoney(_playerid);
	GivePlayerMoney(_playerid, _money);
	SetPlayerHealth(_playerid, _health);
	SetPlayerArmour(_playerid, _armor);
	SetPlayerVirtualWorld(_playerid, 0);
	SetPlayerInterior(_playerid, 0);
	SetCameraBehindPlayer(_playerid);
	SetPlayerScore(_playerid, _level);
	StopAudioStreamForPlayer(_playerid);

	send_message(-1, "te registraste loco");
	return true;
}