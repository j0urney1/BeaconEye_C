#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <stdio.h>
#include <NTSecAPI.h>

#pragma comment(lib,"ntdll.lib")

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessorInformation = 1,
	SystemProcessInformation = 5,
}SYSTEM_INFORMATION_CLASS;
typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessWow64Information = 26,
}PROCESSINFOCLASS;
typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
	USHORT 	ProcessorArchitecture;
	USHORT 	ProcessorLevel;
	USHORT 	ProcessorRevision;
	USHORT 	MaximumProcessors;
	ULONG 	ProcessorFeatureBits;
}SYSTEM_PROCESSOR_INFORMATION, * PSYSTEM_PROCESSOR_INFORMATION;
typedef LONG KPRIORITY;
typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS* PVM_COUNTERS;
typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	MaximumWaitReason
} KWAIT_REASON;
typedef struct _SYSTEM_THREAD {
#if !defined(_M_X64) || !defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER KernelTime;
#endif
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER unk;
#endif
} SYSTEM_THREAD, * PSYSTEM_THREAD;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE ParentProcessId;
	ULONG HandleCount;
	LPCWSTR Reserved2[2];
	ULONG PrivatePageCount;
	VM_COUNTERS VirtualMemoryCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
typedef LONG KPRIORITY;
typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;
typedef struct _PROCESS_BASIC_INFORMATION64 {
	ULONGLONG ExitStatus;
	ULONGLONG PebBaseAddress;
	ULONGLONG AffinityMask;
	ULONG BasePriority;
	ULONGLONG UniqueProcessId;
	ULONGLONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;
NTSTATUS NTAPI RtlGetNativeSystemInformation(SYSTEM_INFORMATION_CLASS a, PSYSTEM_PROCESSOR_INFORMATION b, SIZE_T c, DWORD d);
NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PULONG);
NTSTATUS WINAPI NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT OPTIONAL PULONG ReturnLength);
NTSTATUS NTAPI 	NtQueryInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
NTSTATUS NTAPI NtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG NumberOfBytesToRead, OUT PULONG NumberOfBytesRead);

typedef NTSTATUS(NTAPI* _NtWow64QueryInformationProcess64)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS(NTAPI* _NtWow64ReadVirtualMemory64)(IN HANDLE ProcessHandle, IN ULONGLONG BaseAddress, OUT PVOID Buffer, IN ULONG64 Size, OUT PULONG64 NumberOfBytesRead);

_NtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = NULL;
_NtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = NULL;
char outString[MAX_PATH];

void DisplayX86(HANDLE hProcess, PVOID address)
{
	PVOID stringAddress = NULL;

	RtlSecureZeroMemory(outString, sizeof(outString));
	wprintf(L"\tC2Server: ");
	NtReadVirtualMemory(hProcess, (PBYTE)address + 8 * 8 + 4, &stringAddress, sizeof(stringAddress), NULL);
	NtReadVirtualMemory(hProcess, stringAddress, outString, sizeof(outString), NULL);
	wprintf(L"%hs\n", outString);
	RtlSecureZeroMemory(outString, sizeof(outString));
	wprintf(L"\tUser-Agent: ");
	NtReadVirtualMemory(hProcess, (PBYTE)address + 9 * 8 + 4, &stringAddress, sizeof(stringAddress), NULL);
	NtReadVirtualMemory(hProcess, stringAddress, outString, sizeof(outString), NULL);
	wprintf(L"%hs\n\n", outString);
}
BOOL CheckX86(HANDLE hProcess, PVOID heapAddress, DWORD dwHezpSize, PWSTR ProcessName, DWORD PID)
{
	BOOL re = FALSE;
	PBYTE buffer = NULL;
	BYTE temp[0x8];
	DWORD i = 0, offset, CheckValue = 0;

	if (dwHezpSize >= 0x408)
	{
		if (buffer = LocalAlloc(LPTR, dwHezpSize))
		{
			NtReadVirtualMemory(hProcess, heapAddress, buffer, dwHezpSize, NULL);
			for (i = 8; i < dwHezpSize - 54; i++)
			{
				memset(temp, buffer[i], sizeof(temp));
				CheckValue = *(PDWORD)temp & ~0xFFFF;
				if (RtlEqualMemory(buffer + i, temp, 8))
				{
					offset = i + 8;
					if ((*(USHORT*)(buffer + offset) == 0x1) && ((*(PDWORD)(buffer + offset) & ~0xFFFF) == CheckValue))
					{
						offset += 4;
						if (*(USHORT*)(buffer + offset) == 0x00 || *(USHORT*)(buffer + offset) == 0x01 || *(USHORT*)(buffer + offset) == 0x02 || *(USHORT*)(buffer + offset) == 0x04 || *(USHORT*)(buffer + offset) == 0x08 || *(USHORT*)(buffer + offset) == 0x10)
						{
							offset += 2;
							if (*(USHORT*)(buffer+offset) == *(USHORT*)temp)
							{
								offset += 2;
								if ((*(USHORT*)(buffer + offset) == 0x1) && ((*(PDWORD)(buffer + offset) & ~0xFFFF) == CheckValue))
								{
									offset += 6;
									if (*(USHORT*)(buffer + offset) == *(USHORT*)temp)
									{
										offset += 2;
										if (*(USHORT*)(buffer + offset) == 0x2 && ((*(PDWORD)(buffer + offset) & ~0xFFFF) == CheckValue))
										{
											offset += 8;
											if (*(USHORT*)(buffer + offset) == 0x2 && ((*(PDWORD)(buffer + offset) & ~0xFFFF) == CheckValue))
											{
												offset += 8;
												if (*(USHORT*)(buffer + offset) == 0x1 && ((*(PDWORD)(buffer + offset) & ~0xFFFF) == CheckValue))
												{
													offset += 6;
													if (RtlEqualMemory(buffer + offset, temp, 8))
													{
														wprintf(L"Process: %ws Pid: %d Arch x86\n\tFind Data at %p\n", ProcessName, PID, (PBYTE)heapAddress + i);
														DisplayX86(hProcess, (PBYTE)heapAddress + i);
														re = TRUE;
														break;
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			LocalFree(buffer);
		}
	}
	return re;
}
void SearchBeaconConfigX86(HANDLE hProcess, PWSTR ProcessName, DWORD pid)
{
	PROCESS_BASIC_INFORMATION pbi;
	ULONG ret;
	PVOID address, heapAddress, heapListEntry, heapListFlink, check, firstHeapEntry, lastHeapEntry;
	DWORD i = 0, SegmentSignature, decryptSize;
	USHORT xorKey, heapSize;

	if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret)))
	{

		NtReadVirtualMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x90, &address, sizeof(address), NULL);
		NtReadVirtualMemory(hProcess, address, &heapAddress, sizeof(heapAddress), NULL);
		i = 0;
		while (heapAddress)
		{
			i++;
			NtReadVirtualMemory(hProcess, (PBYTE)heapAddress + 0x8, &SegmentSignature, sizeof(SegmentSignature), NULL);
			//wprintf(L"%p\n", heapAddress);
			if (SegmentSignature == 0xffeeffee)
			{
				
				NtReadVirtualMemory(hProcess, (PBYTE)heapAddress + 0x50, &xorKey, sizeof(xorKey), NULL);
				heapListEntry = (PBYTE)heapAddress + 0x10;
				NtReadVirtualMemory(hProcess, (PBYTE)heapAddress + 0x10, &heapListFlink, sizeof(heapListFlink), NULL);
				check = heapListFlink;
				while (heapListEntry != heapListFlink)
				{
					NtReadVirtualMemory(hProcess, (PBYTE)heapAddress + 0x24, &firstHeapEntry, sizeof(firstHeapEntry), NULL);
					NtReadVirtualMemory(hProcess, (PBYTE)heapAddress + 0x28, &lastHeapEntry, sizeof(lastHeapEntry), NULL);
					if (firstHeapEntry != NULL)
					{
						NtReadVirtualMemory(hProcess, firstHeapEntry, &heapSize, sizeof(heapSize), NULL);
						while (firstHeapEntry <= lastHeapEntry)
						{
							decryptSize = heapSize ^ xorKey;
							//wprintf(L"\t%p %x\n", firstHeapEntry, decryptSize * 0x8);
							if (CheckX86(hProcess, firstHeapEntry, decryptSize * 0x8, ProcessName, pid))
								return;
							
							firstHeapEntry = (PBYTE)firstHeapEntry + (0x8 * decryptSize);
					
							if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, firstHeapEntry, &heapSize, sizeof(heapSize), NULL)))
								break;
						}
					}
					heapAddress = (PBYTE)heapListFlink - 0x10;
					NtReadVirtualMemory(hProcess, (PBYTE)heapAddress + 0x10, &heapListFlink, sizeof(heapListFlink), NULL);
					if (check == heapListFlink)
						break;
				}
			}
			heapAddress = NULL;
			NtReadVirtualMemory(hProcess, (PBYTE)address + i * 4, &heapAddress, sizeof(heapAddress), NULL);
		}
	}
}
void DisplayX64(HANDLE hProcess, ULONGLONG address)
{
	ULONGLONG stringAddress = 0;
	RtlSecureZeroMemory(outString, sizeof(outString));
	wprintf(L"\tC2Server: ");
	NtWow64ReadVirtualMemory64(hProcess, address + 8 * 0x10 + 8, &stringAddress, sizeof(stringAddress), NULL);
	NtWow64ReadVirtualMemory64(hProcess, stringAddress, outString, sizeof(outString), NULL);
	wprintf(L"%hs\n", outString);
	RtlSecureZeroMemory(outString, sizeof(outString));
	wprintf(L"\tUser-Agent: ");
	NtWow64ReadVirtualMemory64(hProcess, address + 9 * 0x10 + 8, &stringAddress, sizeof(stringAddress), NULL);
	NtWow64ReadVirtualMemory64(hProcess, stringAddress, outString, sizeof(outString), NULL);
	wprintf(L"%hs\n\n", outString);
}

	BOOL CheckX64(HANDLE hProcess,ULONGLONG heapAddress, DWORD dwHezpSize,PWSTR ProcessName,DWORD PID)
	{
		BOOL re = FALSE;
		PBYTE buffer = NULL;
		BYTE temp[0x10];
		DWORD i = 0, offset;
		ULONGLONG CheckValue = 0;

		if (dwHezpSize >= 0x810)
		{
			if (buffer = LocalAlloc(LPTR, dwHezpSize))
			{
				if (NT_SUCCESS(NtWow64ReadVirtualMemory64(hProcess, heapAddress, buffer, dwHezpSize, NULL)))
				{
					for (i = 0x10; i < dwHezpSize - 106; i++)
					{
						memset(temp, buffer[i], sizeof(temp));
						CheckValue = *(PULONGLONG)temp & ~0xFFFF;
						if (RtlEqualMemory(buffer + i, temp, 0x10))
						{
							offset = i + 0x10;
							if (*(USHORT*)(buffer + offset) == 0x1 && ((*(PULONGLONG)(buffer + offset) & ~0xFFFF) == CheckValue))
							{
								offset += 8;
								if (*(USHORT*)(buffer + offset) == 0x00 || *(USHORT*)(buffer + offset) == 0x01 || *(USHORT*)(buffer + offset) == 0x02 || *(USHORT*)(buffer + offset) == 0x04 || *(USHORT*)(buffer + offset) == 0x08 || *(USHORT*)(buffer + offset) == 0x10)
								{
									if ((*(PULONGLONG)(buffer + offset) & ~0xFFFF) == CheckValue)
									{
										offset += 8;
										if (*(USHORT*)(buffer + offset) == 0x1 && ((*(PULONGLONG)(buffer + offset) & ~0xFFFF) == CheckValue))
										{
											offset += 10;
											if ((*(PULONGLONG)(buffer + offset) & 0xFFFFFFFFFFFF) == (*(PULONGLONG)temp & 0xFFFFFFFFFFFF))
											{
												offset += 6;
												if (*(USHORT*)(buffer + offset) == 0x2 && ((*(PULONGLONG)(buffer + offset) & ~0xFFFF) == CheckValue))
												{
													offset += 12;
													if (*(PDWORD)(buffer + offset) == *(PDWORD)temp)
													{
														offset += 4;
														if (*(USHORT*)(buffer + offset) == 0x2 && ((*(PULONGLONG)(buffer + offset) & ~0xFFFF) == CheckValue))
														{
															offset += 12;
															if (*(PDWORD)(buffer + offset) == *(PDWORD)temp)
															{
																offset += 4;
																if (*(USHORT*)(buffer + offset) == 0x1 && ((*(PULONGLONG)(buffer + offset) & ~0xFFFF) == CheckValue))
																{
																	offset += 10;
																	if (RtlEqualMemory(buffer + offset, temp, 0x10))
																	{
																		wprintf(L"Process: %ws Pid: %d Arch x64\n\tFind Data at %I64X\n", ProcessName, PID, heapAddress + i);
																		DisplayX64(hProcess, heapAddress + i);
																		re = TRUE;
																		break;
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
				LocalFree(buffer);
			}
		}
		return re;

	}

void SearchBeaconConfigX64(HANDLE hProcess, PWSTR ProcessName,DWORD pid)
{

	PROCESS_BASIC_INFORMATION64 pbi;
	ULONG ret;
	ULONGLONG address = 0, heapAddress = 0, heapListEntry = 0, heapListFlink = 0, firstHeapEntry = 0, lastHeapEntry = 0, check = 0;
	DWORD i = 0;
	DWORD SegmentSignature, decryptSize;
	USHORT xorKey, heapSize;

	if (NT_SUCCESS(NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret)))
	{
		NtWow64ReadVirtualMemory64(hProcess, pbi.PebBaseAddress + 0xf0, &address, sizeof(address), NULL);
		NtWow64ReadVirtualMemory64(hProcess, address, &heapAddress, sizeof(heapAddress), NULL);
		i = 0;
		while (heapAddress)
		{
			i++;
			NtWow64ReadVirtualMemory64(hProcess, heapAddress + 0x10, &SegmentSignature, sizeof(SegmentSignature), NULL);
			if(SegmentSignature == 0xffeeffee)
			{ 
				//wprintf(L"%I64X\n", heapAddress);
				NtWow64ReadVirtualMemory64(hProcess, heapAddress + 0x88, &xorKey, sizeof(xorKey), NULL);
				heapListEntry = heapAddress + 0x18;
				NtWow64ReadVirtualMemory64(hProcess, heapAddress + 0x18, &heapListFlink, sizeof(heapListFlink), NULL);
				check = heapListFlink;
				while (heapListEntry != heapListFlink)
				{
					NtWow64ReadVirtualMemory64(hProcess, heapAddress + 0x40, &firstHeapEntry, sizeof(firstHeapEntry), NULL);
					NtWow64ReadVirtualMemory64(hProcess, heapAddress + 0x48, &lastHeapEntry, sizeof(lastHeapEntry), NULL);
					if (firstHeapEntry != 0)
					{
						NtWow64ReadVirtualMemory64(hProcess, firstHeapEntry + 0x8, &heapSize, sizeof(heapSize), NULL);
						while (firstHeapEntry <= lastHeapEntry)
						{
							decryptSize = heapSize ^ xorKey;
							//wprintf(L"\t%I64X %x\n", firstHeapEntry, decryptSize * 0x10);
							if (CheckX64(hProcess, firstHeapEntry, decryptSize * 0x10, ProcessName, pid))
								return;
							firstHeapEntry = firstHeapEntry + (0x10 * decryptSize);
							if (!NT_SUCCESS(NtWow64ReadVirtualMemory64(hProcess, firstHeapEntry + 0x8, &heapSize, sizeof(heapSize), NULL)))
								break;

						}
					}
					heapAddress = heapListFlink - 0x18;
					NtWow64ReadVirtualMemory64(hProcess, heapAddress + 0x18, &heapListFlink, sizeof(heapListFlink), NULL);
					if (check == heapListFlink)
						break;
				}
			}
			heapAddress = 0;
			NtWow64ReadVirtualMemory64(hProcess, address + i * 8, &heapAddress, sizeof(heapAddress), NULL);
		}
	}
}
int wmain()
{
	SYSTEM_PROCESSOR_INFORMATION ProcInfo;
	BOOL isX64OS = FALSE;
	ULONG previousState;
	PSYSTEM_PROCESS_INFORMATION buffer = NULL, tokenInfo;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	ULONG sizeOfBuffer;
	HANDLE hProcess = 0;
	ULONG_PTR pbi = 0;
	HMODULE hModule = NULL;

	RtlAdjustPrivilege(20, TRUE, FALSE, &previousState);
	RtlGetNativeSystemInformation(SystemProcessorInformation, &ProcInfo, sizeof(ProcInfo), 0);
	if (ProcInfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || ProcInfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		isX64OS = TRUE;
		hModule = GetModuleHandleW(L"ntdll");
		NtWow64QueryInformationProcess64 = (_NtWow64QueryInformationProcess64)GetProcAddress(hModule, "NtWow64QueryInformationProcess64");
		NtWow64ReadVirtualMemory64 = (_NtWow64ReadVirtualMemory64)GetProcAddress(hModule, "NtWow64ReadVirtualMemory64");
	}
	for (sizeOfBuffer = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (buffer = LocalAlloc(LPTR, sizeOfBuffer));)
	{
		status = NtQuerySystemInformation(SystemProcessInformation, buffer, sizeOfBuffer, &sizeOfBuffer);
		if (!NT_SUCCESS(status))
			LocalFree(buffer);
	}
	if (NT_SUCCESS(status))
	{
		for (tokenInfo = buffer; tokenInfo->NextEntryOffset; tokenInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)tokenInfo + tokenInfo->NextEntryOffset))
		{

			hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ALL_ACCESS, FALSE, PtrToUlong(tokenInfo->UniqueProcessId));

			if (hProcess)
			{
				if (!isX64OS)
				{
					SearchBeaconConfigX86(hProcess, tokenInfo->ImageName.Buffer, PtrToUlong(tokenInfo->UniqueProcessId));
				}
				else
				{
					
					NtQueryInformationProcess(hProcess, ProcessWow64Information, &pbi, sizeof(pbi), NULL);
					if (pbi != 0)
						SearchBeaconConfigX86(hProcess, tokenInfo->ImageName.Buffer, PtrToUlong(tokenInfo->UniqueProcessId));
					else SearchBeaconConfigX64(hProcess, tokenInfo->ImageName.Buffer, PtrToUlong(tokenInfo->UniqueProcessId));
				}
				CloseHandle(hProcess);

			}
			hProcess = NULL;
		}
		LocalFree(buffer);
	}
}