#include "general.h"

using SetHvmEvent_t = NTSTATUS(*)();

static VOID*** systemDispatchArray;
static UINT* ssdtServiceCount;
static UINT* shadowSsdtServiceCount;
static UINT* provider;

UINT GetServiceCountSsdt()
{
	return ssdtServiceCount ? *ssdtServiceCount : 0;
}

UINT GetServiceCountShadow()
{
	return shadowSsdtServiceCount ? *shadowSsdtServiceCount : 0;
}

BOOL HookSsdtRoutine(USHORT index, VOID* dest, VOID** original)
{
	PROTECT_ULTRA();
	if (!systemDispatchArray || !dest || !original)
		return false;

	UINT svcCount = GetServiceCountSsdt();
	if (!svcCount || index >= svcCount)
		return false;

	*original = *systemDispatchArray[index];
	*systemDispatchArray[index] = dest;

	PROTECT_END();
	return true;
}

BOOL UnhookSsdtRoutine(USHORT index, VOID* original)
{
	PROTECT_ULTRA();
	if (!systemDispatchArray || !original)
		return false;

	UINT svcCount = GetServiceCountSsdt();
	if (!svcCount || index >= svcCount || *systemDispatchArray[index] == original)
		return false;

	*systemDispatchArray[index] = original;

	PROTECT_END();
	return true;
}

BOOL HookShadowSsdtRoutine(USHORT index, VOID* dest, VOID** original)
{
	PROTECT_ULTRA();
	if (!systemDispatchArray || !dest || !original)
		return false;

	UINT svcCount = GetServiceCountSsdt(), svcCountShadowSsdt = GetServiceCountShadow();
	if (!svcCount || !svcCountShadowSsdt)
		return false;

	UINT indexDispatchTable = (index - 0x1000) + svcCount;
	UINT dispatchTableLimit = svcCount + svcCountShadowSsdt;
	if (indexDispatchTable >= dispatchTableLimit)
		return false;

	*original = *systemDispatchArray[indexDispatchTable];
	*systemDispatchArray[indexDispatchTable] = dest;

	PROTECT_END();
	return true;
}

BOOL UnhookShadowSsdtRoutine(USHORT index, VOID* original)
{
	PROTECT_ULTRA();
	if (!systemDispatchArray || !original)
		return false;

	UINT svcCount = GetServiceCountSsdt(), svcCountShadowSsdt = GetServiceCountShadow();
	if (!svcCount || !svcCountShadowSsdt)
		return false;

	UINT indexDispatchTable = (index - 0x1000) + svcCount;
	UINT dispatchTableLimit = svcCount + svcCountShadowSsdt;
	if (indexDispatchTable >= dispatchTableLimit || *systemDispatchArray[indexDispatchTable] == original)
		return false;

	*systemDispatchArray[indexDispatchTable] = original;

	PROTECT_END();
	return true;
}

PVOID GetRoutine(PCWSTR targetRoutine)
{
	PROTECT_ULTRA();
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, targetRoutine);

	PROTECT_END();
	return MmGetSystemRoutineAddress(&routineName);
}

NTSTATUS UpdateSyscallIndexes()
{
	PROTECT_ULTRA();
	RTL_OSVERSIONINFOEXW versionInfo = { 0 };
	versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

	NTSTATUS status = RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&versionInfo));
	if (!NT_SUCCESS(status))
		return STATUS_VERSION_QUERY_FAIL;

	// Windows 10 21H2
	if (versionInfo.dwBuildNumber == 19044)
	{
		indexes::NtCreateProfileExIndex = 187;
		indexes::NtSetCachedSigningLevelIndex = 393;
		indexes::NtSetBootOptionsIndex = 392;
		return STATUS_SUCCESS;
	}

	// Windows 11 22H2
	if (versionInfo.dwBuildNumber == 22621)
	{
		indexes::NtCreateProfileExIndex = 193;
		indexes::NtSetCachedSigningLevelIndex = 406;
		indexes::NtSetBootOptionsIndex = 405;
		return STATUS_SUCCESS;
	}

	PROTECT_END();
	return STATUS_UNSUPPORTED_VERSION;
}

extern "C" NTSTATUS DriverEntry(VOID * driver, VOID * registry)
{
	PROTECT_ULTRA();
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registry);

	NTSTATUS status = UpdateSyscallIndexes();
	if (!NT_SUCCESS(status))
		return status;

	PVOID MmCopyVirtualMemoryPtr = GetRoutine(EW(L"MmCopyVirtualMemory"));
	if (!MmCopyVirtualMemoryPtr)
		return STATUS_IMPORT_NOT_FOUND;

	PVOID ExAllocatePoolPtr = GetRoutine(EW(L"ExAllocatePool"));
	if (!ExAllocatePoolPtr)
		return STATUS_IMPORT_NOT_FOUND;

	PVOID PsLookupProcessByProcessIdPtr = GetRoutine(EW(L"PsLookupProcessByProcessId"));
	if (!PsLookupProcessByProcessIdPtr)
		return STATUS_IMPORT_NOT_FOUND;

	PCHAR kasperskyBase = utils::FindTargetModule(E("klhk.sys"));
	if (!kasperskyBase)
		return STATUS_KASPERSKY_BASE_NOT_FOUND;

	SetHvmEvent_t setHvmEvent = reinterpret_cast<SetHvmEvent_t>(utils::FindPatternImage(kasperskyBase, EC("\x48\x83\xEC\x38\x48\x83\x3D"), EC("xxxxxxx")));
	if (!setHvmEvent)
		return STATUS_SCAN_0_NOT_FOUND;

	PCHAR scan = static_cast<PCHAR>(utils::FindPatternSection(kasperskyBase, EC("_hvmcode"), EC("\x4C\x8D\x0D\x00\x00\x00\x00\x4D"), EC("xxx????x")));
	if (!scan)
		return STATUS_SCAN_1_NOT_FOUND;

	systemDispatchArray = reinterpret_cast<VOID***>(scan + *reinterpret_cast<INT*>(scan + 0x3) + 0x7);

	scan = static_cast<PCHAR>(utils::FindPatternImage(kasperskyBase, EC("\x89\x0D\x00\x00\x00\x00\x8B\xFB"), EC("xx????xx")));
	if (!scan)
		return STATUS_SCAN_2_NOT_FOUND;

	ssdtServiceCount = reinterpret_cast<UINT*>(scan + *reinterpret_cast<INT*>(scan + 0x2) + 0x6);

	scan = static_cast<PCHAR>(utils::FindPatternImage(kasperskyBase, EC("\x89\x05\x00\x00\x00\x00\x8B\xFB"), EC("xx????xx")));
	if (!scan)
		return STATUS_SCAN_3_NOT_FOUND;

	shadowSsdtServiceCount = reinterpret_cast<UINT*>(scan + *reinterpret_cast<INT*>(scan + 0x2) + 0x6);

	scan = static_cast<PCHAR>(utils::FindPatternImage(kasperskyBase, EC("\x39\x2D\x00\x00\x00\x00\x75"), EC("xx????x")));
	if (!scan)
		return STATUS_SCAN_4_NOT_FOUND;

	provider = reinterpret_cast<unsigned int*>(scan + *reinterpret_cast<int*>(scan + 0x2) + 0x6);

	*provider = 4;
	status = setHvmEvent();
	if (!NT_SUCCESS(status))
		return status;

	VOID* dummy = nullptr;
	bool hooked = HookSsdtRoutine(indexes::NtSetCachedSigningLevelIndex, PsLookupProcessByProcessIdPtr, &dummy);
	if (!hooked)
		return STATUS_HOOK_0_FAILED;

	hooked = HookSsdtRoutine(indexes::NtSetBootOptionsIndex, ExAllocatePoolPtr, &dummy);
	if (!hooked)
		return STATUS_HOOK_1_FAILED;

	hooked = HookSsdtRoutine(indexes::NtCreateProfileExIndex, MmCopyVirtualMemoryPtr, &dummy);
	if (!hooked)
		return STATUS_HOOK_2_FAILED;

	PROTECT_END();
	return STATUS_SUCCESS;
}