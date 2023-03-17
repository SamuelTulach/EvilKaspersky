#pragma once

#define MAX_VIRTUAL_USERMODE 0x7FFFFFFFFFFF
#define MIN_VIRTUAL_USERMODE 0x10000

namespace enums
{
	enum SystemInformationClass
	{
		SystemProcessInformation = 5,
		SystemModuleInformationClass = 11
	};
}

namespace structs
{
	typedef struct _RTL_PROCESS_MODULE_INFORMATION
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
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	typedef struct _POOL_TRACKER_BIG_PAGES
	{
		volatile ULONGLONG Va;
		ULONG Key;
		ULONG Pattern : 8;
		ULONG PoolType : 12;
		ULONG SlushSize : 12;
		ULONGLONG NumberOfBytes;
	} POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	typedef struct _PEB_LDR_DATA
	{
		ULONG Length;
		UCHAR Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _PEB
	{
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		UCHAR BitField;
		PVOID Mutant;
		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PVOID ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PVOID FastPebLock;
		PVOID AtlThunkSListPtr;
		PVOID IFEOKey;
		PVOID CrossProcessFlags;
		PVOID KernelCallbackTable;
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		PVOID ApiSetMap;
	} PEB, * PPEB;

	typedef struct _SYSTEM_PROCESS_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		BYTE Reserved1[48];
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		PVOID Reserved2;
		ULONG HandleCount;
		ULONG SessionId;
		PVOID Reserved3;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG Reserved4;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		PVOID Reserved5;
		SIZE_T QuotaPagedPoolUsage;
		PVOID Reserved6;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved7[6];
	} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

	typedef struct _KPROCESS
	{
		struct _DISPATCHER_HEADER Header;                                       //0x0
		struct _LIST_ENTRY ProfileListHead;                                     //0x18
		ULONGLONG DirectoryTableBase;                                           //0x28
		struct _LIST_ENTRY ThreadListHead;                                      //0x30
		ULONG ProcessLock;                                                      //0x40
		ULONG ProcessTimerDelay;                                                //0x44
		ULONGLONG DeepFreezeStartTime;                                          //0x48
	} KPROCESS, * PKPROCESS;
}

namespace imports
{
	extern "C" NTSTATUS ZwQuerySystemInformation(INT systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
	extern "C" NTSTATUS MmCopyVirtualMemory(PEPROCESS sourceProcess, PVOID sourceAddress, PEPROCESS targetProcess, PVOID targetAddress, SIZE_T bufferSize, KPROCESSOR_MODE previousMode, PSIZE_T returnSize);
	extern "C" PPEB PsGetProcessPeb(PEPROCESS process);
	extern "C" PVOID PsGetProcessSectionBaseAddress(PEPROCESS process);
	extern "C" NTKERNELAPI NTSTATUS KeFlushCurrentTbImmediately();
	extern "C" NTKERNELAPI NTSTATUS NtQueryInformationAtom();
}

#define RELATIVE_ADDRESS(address, size) ((PVOID)((PBYTE)(address) + *(PINT)((PBYTE)(address) + ((size) - (INT)sizeof(INT))) + (size)))

#define STATUS_KASPERSKY_BASE_NOT_FOUND 0xCCCCCC0
#define STATUS_SCAN_0_NOT_FOUND 0xCCCCCC1
#define STATUS_SCAN_1_NOT_FOUND 0xCCCCCC2
#define STATUS_SCAN_2_NOT_FOUND 0xCCCCCC3
#define STATUS_SCAN_3_NOT_FOUND 0xCCCCCC4
#define STATUS_SCAN_4_NOT_FOUND 0xCCCCCC5
#define STATUS_HVM_START_FAILED 0xCCCCCC6
#define STATUS_HOOK_0_FAILED 0xCCCCCC7
#define STATUS_HOOK_1_FAILED 0xCCCCCC8
#define STATUS_HOOK_2_FAILED 0xCCCCCC9
#define STATUS_HOOK_3_FAILED 0xCCCCCF0

namespace indexes
{
	// can be read using SSDTView or Windows Kernel Explorer
	// should correspond with syscall numbers
	static USHORT NtCreateProfileIndex = 186;
	static USHORT NtCreateProfileExIndex = 187;
	static USHORT NtSetCachedSigningLevelIndex = 393;
	static USHORT NtSetBootOptionsIndex = 392;
}