#include "general.h"

PCHAR utils::FindTargetModule(const char* inputName)
{
	PROTECT_ULTRA();
	void* buffer = ExAllocatePool(NonPagedPool, 8);
	if (!buffer)
		return nullptr;

	ULONG bufferSize = 0;
	NTSTATUS status = imports::ZwQuerySystemInformation(enums::SystemModuleInformationClass, buffer, bufferSize, &bufferSize);
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePool(buffer);

		buffer = ExAllocatePool(NonPagedPool, bufferSize);
		status = imports::ZwQuerySystemInformation(enums::SystemModuleInformationClass, buffer, bufferSize, &bufferSize);
	}

	if (!NT_SUCCESS(status))
	{
		ExFreePool(buffer);
		return nullptr;
	}

	structs::PRTL_PROCESS_MODULES modules = static_cast<structs::PRTL_PROCESS_MODULES>(buffer);

	for (ULONG i = 0; i < modules->NumberOfModules; ++i)
	{
		const char* moduleName = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;

		if (strcmp(moduleName, inputName) == 0)
		{
			PCHAR result = static_cast<PCHAR>(modules->Modules[i].ImageBase);

			ExFreePool(buffer);
			return result;
		}
	}

	ExFreePool(buffer);
	PROTECT_END();
	return nullptr;
}

BOOL utils::CheckMask(PCHAR base, PCHAR pattern, PCHAR mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
	{
		if (*mask == 'x' && *base != *pattern)
			return FALSE;
	}

	return TRUE;
}

PVOID utils::FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask)
{
	PROTECT_MUTATE();
	length -= static_cast<DWORD>(strlen(mask));
	for (DWORD i = 0; i <= length; ++i)
	{
		PVOID addr = &base[i];
		if (CheckMask(static_cast<PCHAR>(addr), pattern, mask))
		{
			return addr;
		}
	}

	PROTECT_END();
	return 0;
}

PVOID utils::FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask)
{
	PROTECT_MUTATE();
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base + reinterpret_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (*reinterpret_cast<PINT>(section->Name) == 'EGAP' || memcmp(section->Name, ".text", 5) == 0)
		{
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match)
				break;
		}
	}

	PROTECT_END();
	return match;
}

PVOID utils::FindPatternSection(PCHAR base, PCHAR sectionName, PCHAR pattern, PCHAR mask)
{
	PROTECT_MUTATE();
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base + reinterpret_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, sectionName, 5) == 0)
		{
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match)
				break;
		}
	}

	PROTECT_END();
	return match;
}