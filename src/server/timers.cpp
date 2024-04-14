#include "../main.hpp"

timer::~timer()
{
	if (_stopped_completely)
	{
		delete _handle;
	}
	else
	{
		uv_timer_stop(_handle);
		uv_close(reinterpret_cast<uv_handle_t*>(_handle), [](uv_handle_t* handle) {
			delete handle;
		});
	}
}

void timer::start(uint64_t timeout, uint64_t repeat)
{
	if (_started)
		return;

	if (_stopped_completely)
	{
		// If the timer was set to run once, the handle is closed by the own timer, so it need to be initialized again
		uv_timer_init(uv_default_loop(), _handle);
		_handle->data = reinterpret_cast<void*>(this);
		uv_update_time(uv_default_loop());
		_stopped_completely = false;
	}

	/*
		To prevent the handle from getting destroyed in the case of a run-once timer where the original shared_ptr is discarded, the timer will
		hold a reference to itself and release it after the callback is done
	*/
	_self_reference = shared_from_this();

	uv_timer_start(_handle, [](uv_timer_t* handle) {
		timer* timerp = reinterpret_cast<timer*>(handle->data);
		timerp->_callback();

		if (uv_timer_get_repeat(handle) == 0)
		{
			uv_timer_stop(handle);

			// The handle can't be destroyed here, so queue it for the next event loop iteration
			uv_close(reinterpret_cast<uv_handle_t*>(handle), [](uv_handle_t* handle) {
				timer* timerp = reinterpret_cast<timer*>(handle->data);

				// We don't know if there's another shared_ptr owning the timer, so mark the timer to init the timer handle the next time it's started
				timerp->_started = false;
				timerp->_stopped_completely = true;

				// Free the shared_ptr
				timerp->_self_reference.reset();
			});
		}
	}, timeout, repeat);

	_started = true;
}

inline void timer::stop()
{
	_self_reference.reset();
	uv_timer_stop(_handle);
	_started = false;
}