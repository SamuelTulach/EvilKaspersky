#pragma once

namespace utils
{
	PCHAR FindTargetModule(const char* inputName);
	BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask);
	PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask);
	PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask);
	PVOID FindPatternSection(PCHAR base, PCHAR sectionName, PCHAR pattern, PCHAR mask);
}