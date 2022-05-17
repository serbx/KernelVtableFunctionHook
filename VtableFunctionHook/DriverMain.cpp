#include <ntifs.h>
#include <windef.h>
#include <cstdint>
#include <intrin.h>
#include <ntimage.h>
#define dbgprint(format, ...) DbgPrintEx(0, 0, format, __VA_ARGS__)
#define RVA(addr, size)       ((uintptr_t)((uintptr_t)(addr) + *(PINT)((uintptr_t)(addr) + ((size) - sizeof(INT))) + (size)))

#define to_rva(address, offset) address + (int32_t)((*(int32_t*)(address + offset) + offset) + sizeof(int32_t))
extern "C"
{
	PLIST_ENTRY NTKERNELAPI PsLoadedModuleList;
	NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
}
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	/* 0x0000 */ struct _LIST_ENTRY InLoadOrderLinks;
	/* 0x0010 */ void* ExceptionTable;
	/* 0x0018 */ unsigned long ExceptionTableSize;
	/* 0x001c */ long Padding_687;
	/* 0x0020 */ void* GpValue;
	/* 0x0028 */ struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	/* 0x0030 */ void* DllBase;
	/* 0x0038 */ void* EntryPoint;
	/* 0x0040 */ unsigned long SizeOfImage;
	/* 0x0044 */ long Padding_688;
	/* 0x0048 */ struct _UNICODE_STRING FullDllName;
	/* 0x0058 */ struct _UNICODE_STRING BaseDllName;
	/* 0x0068 */ unsigned long Flags;
	/* 0x006c */ unsigned short LoadCount;
	union
	{
		union
		{
			struct /* bitfield */
			{
				/* 0x006e */ unsigned short SignatureLevel : 4; /* bit position: 0 */
				/* 0x006e */ unsigned short SignatureType : 3; /* bit position: 4 */
				/* 0x006e */ unsigned short Unused : 9; /* bit position: 7 */
			}; /* bitfield */
			/* 0x006e */ unsigned short EntireField;
		}; /* size: 0x0002 */
	} /* size: 0x0002 */ u1;
	/* 0x0070 */ void* SectionPointer;
	/* 0x0078 */ unsigned long CheckSum;
	/* 0x007c */ unsigned long CoverageSectionSize;
	/* 0x0080 */ void* CoverageSection;
	/* 0x0088 */ void* LoadedImports;
	/* 0x0090 */ void* Spare;
	/* 0x0098 */ unsigned long SizeOfImageNotRounded;
	/* 0x009c */ unsigned long TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY; /* size: 0x00a0 */

UNICODE_STRING ansi_to_unicode(const char* str)
{
	UNICODE_STRING unicode;
	ANSI_STRING ansi_str;

	RtlInitAnsiString(&ansi_str, str);
	RtlAnsiStringToUnicodeString(&unicode, &ansi_str, TRUE);

	return unicode;
}

PVOID get_kernel_proc_address(const char* system_routine_name)
{
	UNICODE_STRING name;
	ANSI_STRING ansi_str;

	RtlInitAnsiString(&ansi_str, system_routine_name);
	RtlAnsiStringToUnicodeString(&name, &ansi_str, TRUE);

	return MmGetSystemRoutineAddress(&name);
}

PVOID get_module_base(const char* module_name)
{
	PLIST_ENTRY ps_loaded_module_list = PsLoadedModuleList;
	if (!ps_loaded_module_list)
		return (PVOID)NULL;

	UNICODE_STRING name = ansi_to_unicode(module_name);
	for (PLIST_ENTRY link = ps_loaded_module_list; link != ps_loaded_module_list->Blink; link = link->Flink)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlEqualUnicodeString((PCUNICODE_STRING)&entry->BaseDllName, (PCUNICODE_STRING)&name, TRUE))
		{
			return (PVOID)entry->DllBase;
		}
	}

	return (PVOID)NULL;
}

PVOID get_system_base_export(const char* module_name, LPCSTR routine_name)
{
	PVOID lp_module = get_module_base(module_name);
	if (!lp_module)
		return NULL;

	return RtlFindExportedRoutineByName(lp_module, routine_name);
}

PKLDR_DATA_TABLE_ENTRY get_ldr_data_by_name(const char* szmodule)
{
	PKLDR_DATA_TABLE_ENTRY ldr_entry = nullptr;
	UNICODE_STRING mod = ansi_to_unicode(szmodule);

	PLIST_ENTRY ps_loaded_module_list = PsLoadedModuleList;
	if (!ps_loaded_module_list)
		return ldr_entry;

	auto current_ldr_entry = reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(ps_loaded_module_list->Flink);

	while (reinterpret_cast<PLIST_ENTRY>(current_ldr_entry) != ps_loaded_module_list)
	{
		if (!RtlCompareUnicodeString(&current_ldr_entry->BaseDllName, &mod, TRUE))
		{
			ldr_entry = current_ldr_entry;
			break;
		}

		current_ldr_entry = reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(current_ldr_entry->InLoadOrderLinks.Flink);
	}

	return ldr_entry;
}

template <typename str_type, typename str_type_2>
__forceinline bool crt_strcmp(str_type str, str_type_2 in_str, bool two)
{
#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

	if (!str || !in_str)
		return false;

	wchar_t c1, c2;
	do
	{
		c1 = *str++; c2 = *in_str++;
		c1 = to_lower(c1); c2 = to_lower(c2);

		if (!c1 && (two ? !c2 : 1))
			return true;

	} while (c1 == c2);

	return false;
}

PIMAGE_SECTION_HEADER get_section_header(const uintptr_t image_base, const char* section_name)
{
	if (!image_base || !section_name)
		return nullptr;

	const auto pimage_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
	const auto pimage_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(image_base + pimage_dos_header->e_lfanew);

	auto psection = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers + 1);

	PIMAGE_SECTION_HEADER psection_hdr = nullptr;

	const auto number_of_sections = pimage_nt_headers->FileHeader.NumberOfSections;

	for (auto i = 0; i < number_of_sections; ++i)
	{
		if (crt_strcmp(reinterpret_cast<const char*>(psection->Name), section_name, false))
		{
			psection_hdr = psection;
			break;
		}

		++psection;
	}

	return psection_hdr;
}

bool data_compare(const char* pdata, const char* bmask, const char* szmask)
{
	for (; *szmask; ++szmask, ++pdata, ++bmask)
	{
		if (*szmask == 'x' && *pdata != *bmask)
			return false;
	}

	return !*szmask;
}

uintptr_t find_pattern(const uintptr_t base, const size_t size, const char* bmask, const char* szmask)
{
	for (size_t i = 0; i < size; ++i)
		if (data_compare(reinterpret_cast<const char*>(base + i), bmask, szmask))
			return base + i;

	return 0;
}

uintptr_t find_pattern_page_km(const char* szmodule, const char* szsection, const char* bmask, const char* szmask)
{
	if (!szmodule || !szsection || !bmask || !szmask)
		return 0;

	const auto* pldr_entry = get_ldr_data_by_name(szmodule);

	if (!pldr_entry)
		return 0;

	const auto  module_base = reinterpret_cast<uintptr_t>(pldr_entry->DllBase);
	const auto* psection = get_section_header(reinterpret_cast<uintptr_t>(pldr_entry->DllBase), szsection);

	return psection ? find_pattern(module_base + psection->VirtualAddress, psection->Misc.VirtualSize, bmask, szmask) : 0;
}


uintptr_t ger_module_base(const char* szmodule) {

	const auto* pldr_entry = get_ldr_data_by_name(szmodule);

	return pldr_entry? reinterpret_cast<uintptr_t>(pldr_entry->DllBase) : 0;
}


extern "C"
NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);
NTKERNELAPI extern "C" PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

#define index 16 //MAX 25 OR START AT 0 (26 == index[0], 27 == index[1])

typedef struct RequestData {
	uint8_t type;
	PVOID args;
	int spid; int tpid; unsigned long long addr; int size;
}*pRequestData;

NTSTATUS(__fastcall* OriginalFunction)(ULONG64 v6, UINT a2);
NTSTATUS __fastcall HookFunction(__int64 v6, __int64 a2) {
	//dbgprint("HookFunction Call\n");
	//NtUserCallHwndParam

	//dbgprint("a2: %d\n", a2);
	/*if (v6 != 95)
		goto jmphere;*/

	pRequestData data = reinterpret_cast<pRequestData>(a2);
	//if (arg4 == 0xDEAD420) 
	//{
	//	if (pRequestData data = reinterpret_cast<pRequestData>(a2))
	//	{
	//
	//		
	//dbgprint("data->type: %i\n", data->type);
	//
	//		dbgprint("data->spid: 0x%llx\n", data->spid);
	//		dbgprint("data->tpid: 0x%llx\n", data->tpid);
	//		dbgprint("data->size: 0x%llx\n", data->size);
	//		dbgprint("data->addr: 0x%llx\n", data->addr);
	//		dbgprint("data->args: 0x%llx\n", data->args);
	//		int x = 0x1203203;
	//		RtlCopyMemory((PVOID)data->args, &x, sizeof(x));
	//		//*(unsigned long long*)data->args = 0x1203203;
	//		
	//	}
	//	return STATUS_SUCCESS;
	//}


	if (data->type == 4)
	{
		//dbgprint("Read Req\n");
		PEPROCESS hClient, hSourceProc;
		KAPC_STATE apc_state;
		SIZE_T return_size = 0ull;

		if (data->spid == 0 || data->tpid == 0) goto jmphere;

		BOOLEAN source_valid = TRUE;
		BOOLEAN target_valid = TRUE;
		//PVOID DvrBuf = ExAllocatePoolWithTag(NonPagedPool, data->size, 'sxb');

		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data->spid, &hSourceProc)) ||
			!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data->tpid, &hClient)))
			goto jmphere;
		__try {
			KeStackAttachProcess(hSourceProc, &apc_state);
			//source_valid = MmIsAddressValid((PVOID)data->addr);
			//ProbeForRead((CONST PVOID)data->args, data->size, sizeof(CHAR));
			KeUnstackDetachProcess(&apc_state);
			KeStackAttachProcess(hClient, &apc_state);
			//ProbeForRead((CONST PVOID)data->addr, data->size, sizeof(CHAR));
			//target_valid = MmIsAddressValid((PVOID)data->args);
			KeUnstackDetachProcess(&apc_state);
			if (source_valid && source_valid)
			{
				//ProbeForRead((CONST PVOID)buffer->Source, buffer->Length, sizeof(CHAR));
				//RtlCopyMemory(DriverBuffer, (PVOID)buffer->Source, buffer->Length);
				//PVOID shitret = 0;
				MmCopyVirtualMemory(hSourceProc, (PVOID)data->addr, hClient, data->args, data->size, MaximumMode, &return_size);
				//RtlCopyMemory((PVOID)data->args, &shitret, data->size);
				//*(unsigned long long*)data->args = 0xDeadBB;

				//KeUnstackDetachProcess(&apc_state);
			}
		}
		__except (EXCEPTION_CONTINUE_EXECUTION) {}
	


	}


	if (data->type == 10)
	{

		PEPROCESS hClient, hGame;
		KAPC_STATE apc_state;
		if (data->spid == 0) goto jmphere;
		BOOLEAN source_valid = FALSE;
		BOOLEAN target_valid = FALSE;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data->spid, &hGame)) ||
			!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data->tpid, &hClient)))
			goto jmphere;

		__try
		{
			//int x = 0;
			KeStackAttachProcess(hClient, &apc_state);
			//ProbeForRead((PVOID)&data->args, data->size, sizeof(CHAR));

			uint64_t lMoudleBase = (DWORD64)PsGetProcessSectionBaseAddress(hGame);
			//dbgprint("mBase: 0x%llx\n", lMoudleBase);

			//*(unsigned long long *)data->args = lMoudleBase;
			//DbgPrintEx(0, 0, "\lMoudleBase1:  %p \n", lMoudleBase);
			RtlCopyMemory((PVOID)data->args, &lMoudleBase, sizeof(lMoudleBase));
			KeUnstackDetachProcess(&apc_state);
			//DbgPrintEx(0, 0, "\n GotHere %d: \n", ++x); //3
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			KeUnstackDetachProcess(&apc_state);
		}

	}

		
    jmphere:

	return OriginalFunction(v6, a2);
}

NTSTATUS InstallHook(const ULONG64 vtable_inst) {
	ULONG64 vtable_addr = RVA(vtable_inst, (7));
	ULONG64* vtable = (ULONG64*)vtable_addr;
	//BYTE vindex = (((BYTE)index + (6)) & (0x1F));
	__int64 vindex = 130;
	if (MmIsAddressValid((void*)vtable[vindex])) {
		*(ULONG64*)&OriginalFunction = vtable[vindex];

		// disable write protect bit in cr0...
		 {
			auto cr0 = __readcr0();
			cr0 &= (0xfffffffffffeffff);
			__writecr0(cr0);
			_disable();
		}
	//	dbgprint("vtable[vindex]: 0x%llx\n", vtable[vindex]);
		vtable[vindex] = (ULONG64)HookFunction;

		// enable write protect bit in cr0...
		 {
			auto cr0 = __readcr0();
			cr0 |= (0x10000);
			_enable();
			__writecr0(cr0);
		}
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}


NTSTATUS DrvEntry(ULONG64 base_address) {
	uintptr_t drvbase;
	size_t drvsize;
	//dbgprint("DVR Entry\n");
	{
		
          auto vtable_inst = find_pattern_page_km("win32kfull.sys", ".text", "\x48\x8D\x0D\x00\x00\x00\x00\x48\x8B\xD7\x48\x8B\x04\xD9\x48\x8B\xCE", "xxx????xxxxxxxxxx");//NtUserCallTwoParam
	
		if (vtable_inst != 0 )
		{
			//dbgprint("Got hre #1\n");
			//dbgprint("Driver Loaded\n vTable: 0x%x",  vtable_inst);
			return InstallHook(vtable_inst);
			
		}
		else
		{
			//dbgprint("vtable_inst not found \n");
		}
		
		
		//dbgprint("Driver Loaded drvbase: 0x%x drvSize: 0x%x vTable: 0x%x", drvbase, drvsize, vtable_inst);
	}

	//dbgprint("DVR Ret");

	return STATUS_UNSUCCESSFUL;
}
