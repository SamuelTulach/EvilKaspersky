#include "general.h"

using SetHvmEvent_t = NTSTATUS(*)();

static VOID*** systemDispatchArray;
static UINT* ssdtServiceCount;
static UINT* shadowSsdtServiceCount;
static UINT* provider;

extern "C" NTSTATUS DriverEntry(void* driver, void* registry)
{
	PROTECT_ULTRA();
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registry);

	PCHAR kasperskyBase = utils::FindTargetModule(E("klhk.sys"));
	if (!kasperskyBase)
		return STATUS_KASPERSKY_BASE_NOT_FOUND;

	SetHvmEvent_t setHvmEvent = reinterpret_cast<SetHvmEvent_t>(utils::FindPatternImage(kasperskyBase, EC("\x48\x83\xEC\x38\x48\x83\x3D"),EC("xxxxxxx")));
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
		return STATUS_HVM_START_FAILED;



	PROTECT_END();
	return STATUS_SUCCESS;
}