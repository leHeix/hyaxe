#pragma once

#include "../main.hpp"

class player
{
	unsigned short _playerid{ 0u };
	std::string _name{};
	bool _kicked{ false };
	std::function<void(bool response, int listitem, std::string inputtext)> _dialog_cb{};
	ankerl::unordered_dense::map<std::string, std::any> _data{};

public:
	player(unsigned short playerid) : _playerid(playerid)
	{
		char name_buf[MAX_PLAYER_NAME]; // this is some bullshit
		GetPlayerName(playerid, name_buf, MAX_PLAYER_NAME);
		_name = name_buf;
	}

	~player();

	template<class T>
	inline std::optional<T> get_data(const std::string& key) noexcept
	{
		try
		{
			const std::any& v = _data.at(data);
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
		_data[key] = std::make_any<T>(data);
	}

	inline unsigned short id() const { return _playerid; }
	inline std::string name() const { return _name; }
	inline bool& kicked() { return _kicked; }
	inline const bool& kicked() const { return _kicked; }
	inline const auto& dialog_cb() const { return _dialog_cb; }
	inline auto& dialog_cb() { return _dialog_cb; }
	inline unsigned int ip() const { return rakserver_instance->get_playerid_from_index(_playerid).binaryAddress; }
	inline std::string ip_as_string() const 
	{ 
		std::string ip{ 16, '\0' };
		GetPlayerIp(_playerid, ip.data(), 16);
		return ip;
	}

	inline bool toggle_spectating(bool toggle) { return TogglePlayerSpectating(_playerid, toggle); }
	inline bool show_dialog(unsigned char style, const std::string_view title, const std::string_view body, const std::string_view button1, const std::string_view button2 = "") { return ShowPlayerDialog(_playerid, 422, style, title.data(), body.data(), button1.data(), button2.data()); }
	
};