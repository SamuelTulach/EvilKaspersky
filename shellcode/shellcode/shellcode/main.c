#include <ntifs.h>

typedef NTSTATUS(__stdcall* func_t)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

NTSTATUS CustomEntry(DWORD64 magic, PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize)
{
	if (magic != 0x89F7E893497)
		return STATUS_UNSUCCESSFUL;

	func_t targetFunction = (func_t)0xDEADFEEDDEAD;
	return targetFunction(SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
}