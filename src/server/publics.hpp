#pragma once

#include "../main.hpp"

struct castable_cell
{
	operator cell() { return value; }
	operator cell* ()
	{
		cell* address{ nullptr };
		if (amx_GetAddr(amx, value, &address) != AMX_ERR_NONE)
			return nullptr;

		return address;
	}
	operator float() { return *reinterpret_cast<float*>(&value); }
	operator float* () { return reinterpret_cast<float*>(static_cast<cell*>(*this)); }
	operator std::string()
	{
		std::string result;
		cell* str_address;
		if (amx_GetAddr(amx, value, &str_address) != AMX_ERR_NONE)
			return result;

		int str_len{ 0 };
		amx_StrLen(str_address, &str_len);
		if (!str_len)
			return result;

		result.resize(++str_len);
		amx_GetString(result.data(), str_address, 0, str_len);
		result.pop_back();

		return result;
	}

	template<class T>
	operator T() {
		static_assert(std::is_convertible_v<T, cell>);
		return static_cast<T>(value);
	}

	AMX* amx;
	cell value;
};

namespace callbacks
{
	enum class exec_order : std::uint8_t
	{
		init = 0,
		prehook = 1,
		hook = 2,
		posthook = 3
	};

	struct public_hook_impl
	{
		exec_order order{ exec_order::hook };
		std::function<cell(AMX*, cell*)> call;

		template<class... Args>
		public_hook_impl(exec_order order, std::function<cell(Args...)>&& fun)
			:
			order(order), call([=](AMX* amx, cell* params) -> cell {
				if (params[0] / sizeof(cell) != sizeof...(Args))
				{
					console::print("error while converting callback hook parameters: expected {} arguments, got {}.", sizeof...(Args), params[0] / sizeof(cell));
					return 0;
				}

				auto unpack = [=]<std::size_t... idx>(std::index_sequence<idx...>) -> cell
				{
					return fun(castable_cell{ amx, params[idx + 1] }...);
				};

				return unpack(std::make_index_sequence<sizeof...(Args)>{});
			})
		{

		}
	};

	struct string_hash
	{
		using hash_type = std::hash<std::string_view>;
		using is_transparent = void;

		std::size_t operator()(const char* str) const { return hash_type{}(str); }
		std::size_t operator()(std::string_view str) const { return hash_type{}(str); }
		std::size_t operator()(std::string const& str) const { return hash_type{}(str); }
	};

	std::unordered_map<const std::string_view, std::vector<public_hook_impl>, string_hash>& get_public_hooks()
	{
		static std::unordered_map<const std::string_view, std::vector<public_hook_impl>, string_hash> hooks;
		return hooks;
	}
}

template<callbacks::exec_order order = callbacks::exec_order::hook>
class public_hook
{
public:
	template<class F>
	public_hook(const char* function_name, F&& fun)
	{
		// https://stackoverflow.com/questions/59356874
		auto function = std::function{ std::forward<F>(fun) };
		auto& vec = callbacks::get_public_hooks()[function_name];
		vec.push_back(callbacks::public_hook_impl{ order, std::move(function) });

		struct {
			bool operator()(callbacks::public_hook_impl& a, callbacks::public_hook_impl& b)
			{
				return (a.order < b.order);
			}
		} comp;
		std::sort(vec.begin(), vec.end(), comp);
	}

	public_hook(const public_hook&) = delete;
	public_hook(public_hook&&) = delete;
};
