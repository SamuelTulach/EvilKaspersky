#pragma once

#define VMP_MARKERS false

#include <ntifs.h>
#include <ntimage.h>
#include <minwindef.h>
#include <fltKernel.h>
#include <intrin.h>

#include "xor.h"
#include "defines.h"
#include "vmp.h"
#include "utils.h"

namespace global
{
	inline UCHAR* ShellcodeBase = nullptr;
	inline SIZE_T ShellcodeSize = 0;
	inline UCHAR OriginalCode[13];
	inline RTL_OSVERSIONINFOEXW VersionInfo = { 0 };
	inline PVOID NtTerminateThread = nullptr;
}
