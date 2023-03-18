#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include "driver.h"

DriverControl driver;

typedef struct _LargeBuffer
{
	unsigned char Buffer[56000];
} LargeBuffer;

void PrintHex(const unsigned char* buf, size_t buf_len)
{
	size_t i = 0;
	for (i = 0; i < buf_len; ++i)
		printf("%02X%s", buf[i],
			(i + 1) % 16 == 0 ? "\r\n" : " ");

	printf("\n");
}

int GetProcessID(const wchar_t* processName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot)
	{
		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		if (Process32First(snapshot, &entry))
		{
			do
			{
				if (0 == _wcsicmp(entry.szExeFile, processName))
				{
					CloseHandle(snapshot);
					return entry.th32ProcessID;
				}
			} while (Process32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	return 0;
}

static DWORD64 moduleBase = 0;
void ThreadBench(int id)
{
	while (true)
	{
		DWORD64 totalOk = 0;
		DWORD64 totalFail = 0;

		auto t1 = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < 100000; i++)
		{
			int offset = rand() % 20 + 1; // this is slow btw
			offset += 0x48;
			volatile int readValue = driver.Read<int>(moduleBase + offset);
			volatile int readConfirm = driver.Read<int>(moduleBase + offset);
			if (readValue == readConfirm && readValue != 0)
				totalOk++;
			else
			{
				totalFail++;
				printf("Invalid read: %x %x\n", readValue, readConfirm);
			}
		}
		auto t2 = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
		printf("Ok: %llu Fail: %llu In: %llu\n", totalOk, totalFail, duration);
	}
}

int main()
{
	printf("Waiting on ProcessHacker.exe...\n");
	int targetProcessId = 0;
	while (targetProcessId == 0)
	{
		targetProcessId = GetProcessID(L"ProcessHacker.exe");
		Sleep(10);
	}

	printf("Init...\n");
	driver.Init();

	printf("Check...\n");
	bool status = driver.Check();
	if (!status)
	{
		printf("Failed check!\n");
		getchar();
		return -1;
	}
	printf("Communication check done\n");

	printf("Set target...\n");
	driver.SetTarget(reinterpret_cast<HANDLE>(targetProcessId));

	printf("Get modules...\n");
	PVOID module1 = driver.GetModule(L"kernel32.dll");
	PVOID module2 = driver.GetModule(L"user32.dll");
	moduleBase = (DWORD64)module1;
	printf("kernel32.dll: 0x%p\n", module1);
	printf("user32.dll: 0x%p\n", module2);

	printf("Waiting...\n");
	Sleep(100);

	printf("Press key\n");
	getchar();

	LargeBuffer* largeBuffer = static_cast<LargeBuffer*>(malloc(sizeof(LargeBuffer)));
	printf("Short read test...\n");
	memset(largeBuffer, 0, sizeof(LargeBuffer));
	driver.ReadMemory(module1, largeBuffer, 20);
	PrintHex(largeBuffer->Buffer, 20);

	printf("Multi-thread test...\n");
	for (int i = 0; i < 5; i++)
	{
		printf("Starting ID %i...\n", i);
		std::thread thread(ThreadBench, i);
		thread.detach();
	}

	while (true)
		Sleep(10000);
}