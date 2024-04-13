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
		_name.resize(MAX_PLAYER_NAME);
		GetPlayerName(playerid, _name.data(), MAX_PLAYER_NAME);
		_name.shrink_to_fit();
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

	inline bool toggle_spectating(bool toggle) { return TogglePlayerSpectating(_playerid, toggle); }
	inline void set_dialog_cb(const std::function<void(bool response, int listitem, std::string inputtext)>& cb) { _dialog_cb = cb; }
	inline bool show_dialog(unsigned char style, const std::string_view title, const std::string_view body, const std::string_view button1, const std::string_view button2 = "") { return ShowPlayerDialog(_playerid, 422, style, title.data(), body.data(), button1.data(), button2.data()); }
};