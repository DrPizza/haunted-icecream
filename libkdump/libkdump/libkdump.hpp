#ifndef LIBKDUMP__HPP
#define LIBKDUMP__HPP

#include <cstddef>
#include <array>

namespace kdump {

	enum fault_handling_t
	{
		SEH,
		TSX
	};

	enum load_t
	{
		NOP,
		IO,
		YIELD
	};

	struct config_t
	{
		std::size_t cache_miss_threshold;
		fault_handling_t fault_handling;
		std::size_t measurements;
		std::size_t accept_after;
		std::size_t load_threads;
		load_t load_type;
		std::size_t retries;
	};

	bool libkdump_init(const config_t configuration);
	config_t libkdump_get_autoconfig();
	std::array<std::byte, 1> libkdump_read(std::size_t addr);
	int libkdump_cleanup();
	void libkdump_enable_debug(bool enable);
}

#endif
