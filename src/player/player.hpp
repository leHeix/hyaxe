#pragma once

#include "../main.hpp"

class player
{
	unsigned short _playerid{ 0u };
	ankerl::unordered_dense::map<std::string, std::any> _data{};

public:
	player(unsigned short playerid) : _playerid(playerid)
	{
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
};