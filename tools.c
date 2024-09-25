#include "tools.h"
#include<ntddk.h>
#include<ntimage.h>

UINT64 _strcmp_a(LPSTR s1, LPSTR s2)
{
	char c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return (UINT64)-1;

	if (s2 == 0)
		return 1;

	do {
		c1 = *s1;
		c2 = *s2;
		s1++;
		s2++;
	} while ((c1 != 0) && ((c1 | 0x20) == (c2 | 0x20)));

	return (int)((INT64)(c1 | 0x20) - (c2 | 0x20));
}

UINT64 strfind(LPSTR str1, LPSTR str2) {
	UINT64  str2len = strlen(str2);
	UINT64 str1len = strlen(str1);
	char temp;
	if (str1len > str2len) {
		for (UINT64 i = 0; i <= str1len - str2len; i++) {
			temp = str1[str2len + i];
			str1[str2len + i] = 0;
			if (_strcmp_a(&str1[i], str2) == 0) {
				return i;
			}

			str1[str2len + i] = temp;
		}
	}
	return (UINT64)-1;
}


EXTERN_C RTL_PROCESS_MODULE_INFORMATION GetSystemModuleInfo(LPSTR ModuleName) {
	ULONG BufferSizeNeed = 0;
	RTL_PROCESS_MODULE_INFORMATION ret;
	PRTL_PROCESS_MODULES  Buffer = 0;
	NTSTATUS status;
	INT T;
	RtlZeroMemory(&ret, sizeof(ret));

	__try {
		status = NtQuerySystemInformation(11, &BufferSizeNeed, BufferSizeNeed, &BufferSizeNeed);
		Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSizeNeed, 35353535);
		if (Buffer) {
			status = NtQuerySystemInformation(11, Buffer, BufferSizeNeed, &BufferSizeNeed);

			if (NT_SUCCESS(status)) {
				T = Buffer->NumberOfModules;
				while ((T--) >= 0) {
					if ((INT64)Buffer->Modules[T].ImageBase != 0x140000000 && strfind(Buffer->Modules[T].FullPathName, ModuleName) != -1) {
						ret = Buffer->Modules[T];
						break;
					}
					if (T == 0) ret.ImageBase = 0;
				}
			}
			ExFreePoolWithTag(Buffer, 0);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	return ret;
}

BOOLEAN CheckMask(CHAR* base, CHAR* pattern, CHAR* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
	{
		if ('x' == *mask && *base != *pattern)
		{
			return FALSE;
		}
	}
	return TRUE;
}


PVOID FindPattern(PVOID base, INT length, CHAR* pattern, CHAR* mask)
{
	length -= (INT)(strlen(mask));
	for (INT i = 0; i <= length; ++i)
	{
		CHAR* data = (CHAR*)base;
		PVOID address = &data[i];
		if (CheckMask(address, pattern, mask))
			return address;
	}
	return NULL;
}

EXTERN_C PVOID FindPatternImage(PVOID base, CHAR* pattern, CHAR* mask)
{
	PVOID match = 0;
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((CHAR*)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (ULONG64 i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if ('EGAP' == *(PINT64)section->Name || memcmp(section->Name, ".text", 5) == 0) {
			match = FindPattern((CHAR*)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match)
			{
				break;
			}
		}
	}
	return match;
}
