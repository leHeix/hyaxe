#pragma once

// wow this is the first documented piece of code i've wrote

#include "../main.hpp"

class timer : public std::enable_shared_from_this<timer>
{
	uv_timer_t* _handle{ nullptr };
	std::function<void()> _callback{};
	std::shared_ptr<timer> _self_reference{};
	bool _stopped_completely{ false };
	bool _started{ false };

public:
	template<class... Args>
	timer(const std::function<void(Args...)>& cb, Args&&... args)
	{
		_handle = new uv_timer_t;
		_callback = std::bind(cb, std::forward<Args>(args)...);

		uv_timer_init(uv_default_loop(), _handle);
		_handle->data = reinterpret_cast<void*>(this);
		uv_update_time(uv_default_loop());
	}

	~timer();

	template<class... Args>
	[[nodiscard]] inline static std::shared_ptr<timer> create(const std::function<void(Args...)>& cb, Args... args)
	{
		return std::make_shared<timer>(cb, std::forward<Args>(args)...);
	}

	/**
	  * @brief Starts the timer
	  * @param interval Interval of milliseconds before the timer gets be called for the first time
	  * @param repeat Interval of milliseconds before the timer gets be called after the first time. If this value is 0, the timer will only be called once
      * @note If the timer is set to run only once, holding a reference to this timer only to destroy it after is not needed, the timer will destroy and cleanup memory itself.
      */
	void start(uint64_t interval, uint64_t repeat = 0);

	/**
	  * @brief Stops the timer
	  * @note If the timer is set to run only once, the timer will stop and destroy itself, calling this function is not needed
	  */
	inline void stop();

	template<class... Args>
	inline void set_callback(const std::function<void(Args...)>& cb, Args... args)
	{
		_callback = std::bind(cb, std::forward<Args>(args)...);
	}
};