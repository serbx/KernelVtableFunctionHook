#include <Windows.h>
#include <iostream>
#include <ntstatus.h>
#include <TlHelp32.h>
#include "xorstr.h"
typedef struct RequestData {
	uint8_t type;
	PVOID args;
	int spid; int tpid; unsigned long long addr; int size;
}*pRequestData;

NTSTATUS(*NtUserCallTwoParam)(HWND hWnd, PVOID Param, DWORD Routine) = nullptr;
HWND ValidHwnd;
UINT MsgKey;

bool InitHandles() {
	LoadLibraryA("user32.dll");
	LoadLibraryA("win32u.dll");
	LoadLibraryA("ntdll.dll");

	*(PVOID*)&NtUserCallTwoParam = GetProcAddress(
		GetModuleHandleA("win32u.dll"),
		"NtUserCallTwoParam"
	);
	if (!NtUserCallTwoParam)
		return false;

	return true;
	
}

template <uint8_t type>
NTSTATUS syscall(PVOID rett, int spid, int tpid, unsigned long long addr, int size) {
	RequestData data = {
		type,
		rett,
		spid,tpid,addr,size
	};
	return NtUserCallTwoParam((HWND)(rand() % 0x35346) , &data, 130 );
}

std::uint32_t find_process_by_id(const std::string& name)
{
	const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 proc_entry{};
	proc_entry.dwSize = sizeof proc_entry;

	auto found_process = false;
	int x = 0;
	if (!!Process32First(snap, &proc_entry)) {
		do {
			if (name == proc_entry.szExeFile) {
				x++;
				found_process = true;
				if (x == 2)
					break;
			}
		} while (!!Process32Next(snap, &proc_entry));
	}

	CloseHandle(snap);
	return found_process
		? proc_entry.th32ProcessID
		: 0;
}

int sPid = 0;
int dpid = 0;
unsigned long long proc_base = 0;

template<typename T>
T ReadM(uint64_t address) {
	T Tret = {};

	//syscall<4>(&Tret, sPid, dpid, uint64_t(address), sizeof(T));
	syscall<4>(&Tret, dpid, dpid, uint64_t(address), sizeof(T));
	return Tret;
}

NTSTATUS main() {
    printf(XorString("InitHandles!\n"));
	srand(time(NULL));
	if (InitHandles()) {
		
		unsigned long long ret = 0x343;
		int spid = 0x110;
		int tpid = 0x120;
		unsigned long long addr = 0x110011001;
		int size = 0x16;
		
		dpid = GetCurrentProcessId();
		unsigned long long x = 0x1234;
		addr = (uint64_t)&x;

		auto status = syscall<4>(&ret, dpid, dpid, addr, sizeof(unsigned long long));

        ret = ReadM<uint64_t>(addr);
		printf("address of x:0x%llx | ret->ret: 0x%llx \n", addr,ret);

		//syscall<10>(&ret, sPid, dpid, 0x0, sizeof(unsigned long long));
		syscall<10>(&ret, dpid, dpid, 0x0, sizeof(unsigned long long));
		proc_base = ret;
		
		printf("Mbase: 0x%llx \n", proc_base);
		
		
		const char* abc = "abcdefghimno";
		char rabc[20];
		system("pause");
		
		syscall<4>(&rabc, dpid, dpid, (uint64_t)&*abc, sizeof(rabc));
		printf("ret->ret: %s \n", rabc);

		system("pause");
		Sleep(1000);
		

		system("pause");
		return ret;
	}
	printf("inintHandles Failed\n");
	system("pause");

	return STATUS_UNSUCCESSFUL;
}