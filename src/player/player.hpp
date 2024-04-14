#pragma once

#include "../main.hpp"

enum sounds : std::uint32_t
{
	next = 14405,
	back = 14404,
	error = 1085,
	button = 17803,
	trumpet = 31205,
	sent = 40404,
	success = 1150,
	success_one = 1137,
	success_two = 1138,
	car_doors = 24600,
	eat = 32200,
	puke = 32201,
	dressing = 20800
};

class player
{
public:
	enum flags : std::uint8_t
	{
		authenticating = 0,
		registered,

		flag_count
	};

	static constexpr bool sex_female = false;
	static constexpr bool sex_male = true;

private:
	friend void sex_dialog_callback(std::reference_wrapper<std::unique_ptr<player>> player, bool response, int listitem, std::string inputtext);

	int _account_id{ 0 };
	unsigned short _playerid{ 0u };
	std::string _name{};
	bool _kicked{ false };
	std::function<void(bool response, int listitem, std::string inputtext)> _dialog_cb{};
	ankerl::unordered_dense::map<std::string, std::any> _data{};
	std::bitset<flags::flag_count> _flags{};
	std::bitset<flags::flag_count> _config{};

	int _money{ 0 };
	unsigned short _level{ 1u };
	unsigned int _xp{ 0u };
	bool _sex{ sex_male };
	unsigned short _skin{ 0u };

	float _health{ 100.f };
	float _armor{ 100.f };
	float _hunger{ 0.f };
	float _thirst{ 0.f };
	float _pos_x{ 0.f };
	float _pos_y{ 0.f };
	float _pos_z{ 0.f };
	float _angle{ 0.f };

	std::uint8_t _admin_level{ 0u };
	std::uint8_t _vip_level{ 0u };

	std::mutex _data_mutex{};

public:
	player(unsigned short playerid) : _playerid(playerid)
	{
		char name_buf[MAX_PLAYER_NAME]; // this is some bullshit
		GetPlayerName(playerid, name_buf, MAX_PLAYER_NAME);
		_name = name_buf;
	}

	~player();

	bool register_account();

	template<class T>
	inline std::optional<T> get_data(const std::string& key) noexcept
	{
		std::scoped_lock lk{ _data_mutex };

		try
		{
			const std::any& v = _data.at(key);
			return std::make_optional<T>(std::any_cast<T>(v));
		}
		catch (const std::exception& e)
		{
			return std::nullopt;
		}
	}

	template<class T>
	inline void set_data(const std::string& key, T data)
	{
		std::scoped_lock lk{ _data_mutex };
		_data[key] = std::make_any<T>(data);
	}

	inline void remove_data(const std::string& key)
	{
		std::scoped_lock lk{ _data_mutex };
		_data.erase(key);
	}

	inline unsigned short id() const { return _playerid; }
	inline std::string name() const { return _name; }
	inline bool& kicked() { return _kicked; }
	inline const bool& kicked() const { return _kicked; }
	inline const auto& dialog_cb() const { return _dialog_cb; }
	inline auto& dialog_cb() { return _dialog_cb; }
	inline auto& flags() { return _flags; }
	inline const auto& flags() const { return _flags; }
	inline unsigned int ip() const { return rakserver_instance->get_playerid_from_index(_playerid).binaryAddress; }
	inline std::string ip_as_string() const
	{
		std::string ip{ 16, '\0' };
		GetPlayerIp(_playerid, ip.data(), 16);
		return ip;
	}

	inline bool toggle_spectating(bool toggle) { return TogglePlayerSpectating(_playerid, toggle); }
	inline bool show_dialog(unsigned char style, const std::string_view title, const std::string_view body, const std::string_view button1, const std::string_view button2 = "") { return ShowPlayerDialog(_playerid, 422, style, title.data(), body.data(), button1.data(), button2.data()); }
	inline bool play_sound(int soundid, float x = 0.0, float y = 0.0, float z = 0.0) { return PlayerPlaySound(_playerid, soundid, x, y, z); }
	inline bool set_money(int amount)
	{
		ResetPlayerMoney(_playerid);
		return GivePlayerMoney(_playerid, amount);
	}
	inline bool send_message(int color, const std::string& message) { return SendClientMessage(_playerid, color, message.c_str()); }
};