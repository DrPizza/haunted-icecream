#ifndef LIBKDUMP__H
#define LIBKDUMP__H

extern "C" {

	enum libkdump_fault_handling_t
	{
		SEH,
		TSX
	};

	enum libkdump_load_t
	{
		NOP,
		IO,
		YIELD
	};

	struct libkdump_config_t
	{
		std::size_t cache_miss_threshold;
		libkdump_fault_handling_t fault_handling;
		std::size_t measurements;
		std::size_t accept_after;
		std::size_t load_threads;
		libkdump_load_t load_type;
		std::size_t retries;
		std::size_t physical_offset;
	};

	extern libkdump_config_t libkdump_auto_config;

	int libkdump_init(const libkdump_config_t configuration);
	libkdump_config_t libkdump_get_autoconfig();
	std::byte libkdump_read(std::size_t addr);
	int libkdump_cleanup();
	void libkdump_enable_debug(int enable);

}

#endif
