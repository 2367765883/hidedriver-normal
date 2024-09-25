#include "Head.h"


#include "tools.h"

#include "oxygenPdb.h"

extern PDRIVER_OBJECT Driver;

////导出的函数或全局变量才能用这个
//ULONG64 GetSymAddress(PWCHAR Name) {
//	UNICODE_STRING UName = { 0 };
//	RtlInitUnicodeString(&UName, Name);
//	return MmGetSystemRoutineAddress(&UName);
//}



extern "C" 
{

//初始化需要用到的偏移  自己想办法拿咯
 BOOLEAN InitAllOffSet() 
{

	oxygenPdb::Pdber ntos(L"ntoskrnl.exe");
	ntos.init();



	RTL_PROCESS_MODULE_INFORMATION module_ntoskrnl = GetSystemModuleInfo("ntoskrnl.exe");

	if (!module_ntoskrnl.ImageBase)
	{
		DbgPrintEx(77, 0, "ntoskrnl:[%p]\n", module_ntoskrnl.ImageBase);

		return FALSE;
	}

	PsLoadedModuleList = NULL;

	PsLoadedModuleList = reinterpret_cast<PLIST_ENTRY64> (ntos.GetPointer("PsLoadedModuleList"));

	if (!PsLoadedModuleList)
	{
		DbgPrintEx(77, 0, "PsLoadedModuleList:[%p]\n", PsLoadedModuleList);

		return FALSE;
	}

	BaseDllNameOffset = ntos.GetOffset("LDR_DATA_TABLE_ENTRY","BaseDllName"); //GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY", L"BaseDllName");1

	SectionOffset = ntos.GetOffset("LDR_DATA_TABLE_ENTRY", "HashLinks"); //GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY",L"HashLinks");1

	DllBaseOffset = ntos.GetOffset("LDR_DATA_TABLE_ENTRY", "DllBase");//GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY", L"DllBase");1

	SizeOfImageOffset = ntos.GetOffset("LDR_DATA_TABLE_ENTRY", "SizeOfImage"); //GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY", L"SizeOfImage");

	FlagsOffset = ntos.GetOffset("LDR_DATA_TABLE_ENTRY", "Flags"); //GetMembersOffset(L"_LDR_DATA_TABLE_ENTRY", L"Flags");


	//Pqword_14040EF40 = 0xfffff8042ba0ef20 + 0x20;//GetSymAddress(L"SeCiCallbacks") + 0x20;1


	PVOID SeciCallbacksAddress = reinterpret_cast<PVOID>(ntos.GetPointer("SeValidateImageHeader"));

	PVOID qword_FFFFF80641437500 = (PVOID)((LONG64)SeciCallbacksAddress + 0x20);

	Pqword_14040EF40 = reinterpret_cast<PULONG64>(qword_FFFFF80641437500);

	RtlImageNtHeader = NULL;

	PULONG64 b = reinterpret_cast<PULONG64>(&RtlImageNtHeader);
	

	*b = (ULONG64)(ntos.GetPointer("RtlImageNtHeader")); 

	if (!RtlImageNtHeader)
	{
		DbgPrintEx(77, 0, "RtlImageNtHeader:[%p]\n", RtlImageNtHeader);

		return FALSE;
	}




	PVOID MiGenerateSystemImageNamesAddress= reinterpret_cast<PVOID>(ntos.GetPointer("MiGenerateSystemImageNames"));

	b = reinterpret_cast<PULONG64>(&MiGenerateSystemImageNames);

	*b = (unsigned long long)MiGenerateSystemImageNamesAddress;



	PVOID MiObtainSectionForDriverAddress = reinterpret_cast<PVOID>(ntos.GetPointer("MiObtainSectionForDriver"));

	b = reinterpret_cast<PULONG64>(&MiObtainSectionForDriver);
	*b = (unsigned long long)MiObtainSectionForDriverAddress;



	PVOID MiGetSystemAddressForImageAddress = reinterpret_cast<PVOID>(ntos.GetPointer("MiGetSystemAddressForImage"));


	b = reinterpret_cast<PULONG64>(&MiGetSystemAddressForImage);
	*b = (unsigned long long)MiGetSystemAddressForImageAddress;


	PVOID MiMapSystemImageImageAddress = reinterpret_cast<PVOID>(ntos.GetPointer("MiMapSystemImage"));

	b = reinterpret_cast<PULONG64>(&MiMapSystemImage);
	*b = (unsigned long long)MiMapSystemImageImageAddress;

	RtlImageDirectoryEntryToData = NULL;

	b = reinterpret_cast<PULONG64>(&RtlImageDirectoryEntryToData);

	*b = (ntos.GetPointer("MiGetSystemAddressForImage"));

	if (!RtlImageDirectoryEntryToData)
	{
		DbgPrintEx(77, 0, "RtlImageDirectoryEntryToData:[%p]\n", RtlImageDirectoryEntryToData);

		return FALSE;
	}



	//MiSnapThunk
	PVOID MiSnapThunkAddress = reinterpret_cast<PVOID>(ntos.GetPointer("MiSnapThunk"));


	b = reinterpret_cast<PULONG64>(&MiSnapThunk);
	*b = (unsigned long long)MiSnapThunkAddress;


	//MmAcquireLoadLock
	PVOID MmAcquireLoadLockAddress = reinterpret_cast<PVOID>(ntos.GetPointer("MmAcquireLoadLock"));


	b = reinterpret_cast<PULONG64>(&MmAcquireLoadLock);
	*b = (unsigned long long)MmAcquireLoadLockAddress;




	PVOID MmReleaseLoadLockAddress = reinterpret_cast<PVOID>(ntos.GetPointer("MmReleaseLoadLock"));


	b = reinterpret_cast<PULONG64>(&MmReleaseLoadLock);
	*b = (unsigned long long)MmReleaseLoadLockAddress;
	


	PVOID MiFillPteHierarchyAddress = reinterpret_cast<PVOID>(ntos.GetPointer("MiFillPteHierarchy"));


	b = reinterpret_cast<PULONG64>(&MiFillPteHierarchy);
	*b = (unsigned long long)MiFillPteHierarchyAddress;


	//IopReadyDeviceObjects
	PVOID IopReadyDeviceObjectsAddress = reinterpret_cast<PVOID>(ntos.GetPointer("IopReadyDeviceObjects"));

	

	b = reinterpret_cast<PULONG64>(&IopReadyDeviceObjects);
	*b = (unsigned long long)IopReadyDeviceObjectsAddress;

	////------驱动伪装特有-------------



	PVOID CmRegistryMachineHardwareDescriptionSystemNameAddress = reinterpret_cast<PVOID>(ntos.GetPointer("CmRegistryMachineHardwareDescriptionSystemName"));


	PCmRegistryMachineHardwareDescriptionSystemName = (ULONG64)CmRegistryMachineHardwareDescriptionSystemNameAddress;


	//MiConstructLoaderEntry
	PVOID MiConstructLoaderEntryAddress = reinterpret_cast<PVOID>(ntos.GetPointer("MiConstructLoaderEntry"));

	

	b = reinterpret_cast<PULONG64>(&MiConstructLoaderEntry);
	*b = (unsigned long long)MiConstructLoaderEntryAddress;


	//ObInsertObjectEx
	PVOID ObInsertObjectExAddress = reinterpret_cast<PVOID>(ntos.GetPointer("ObInsertObjectEx"));

	

	b = reinterpret_cast<PULONG64>(&ObInsertObjectEx);
	*b = (unsigned long long)ObInsertObjectExAddress;


	
	//ObCreateObjectEx
	PVOID ObCreateObjectExAddress = reinterpret_cast<PVOID>(ntos.GetPointer("ObCreateObjectEx"));



	b = reinterpret_cast<PULONG64>(&ObCreateObjectEx);
	*b = (unsigned long long)ObCreateObjectExAddress;



	PVOID IopInvalidDeviceRequestAddress = reinterpret_cast<PVOID>(ntos.GetPointer("IopInvalidDeviceRequest"));

	

	PIopInvalidDeviceRequest = (ULONG64)IopInvalidDeviceRequestAddress;

	

	

	PVOID IopDriverLoadResourceAddress = reinterpret_cast<PVOID>(ntos.GetPointer("IopDriverLoadResource"));



	PIopDriverLoadResource = (ULONG64)IopDriverLoadResourceAddress;

	
	PIoDriverObjectType = reinterpret_cast<PULONG64>(ntos.GetPointer("IoDriverObjectType"));

	if (!PIoDriverObjectType)
	{
		DbgPrintEx(77, 0, "PIoDriverObjectType:[%p]\n", PIoDriverObjectType);

		return FALSE;
	}

	DbgPrintEx(77, 0, "PsLoadedModuleList:[%p]\n", PsLoadedModuleList);

	DbgPrintEx(77, 0, "SeciCallbacksAddress :[%p]\n", SeciCallbacksAddress);

	DbgPrintEx(77, 0, "qword_FFFFF80641437500 :[%p]\n", qword_FFFFF80641437500);

	DbgPrintEx(77, 0, "RtlImageNtHeader :[%p]\n", reinterpret_cast<PULONG64>(ntos.GetPointer("RtlImageNtHeader")));

	DbgPrintEx(77, 0, "MiGenerateSystemImageNamesAddress :[%p]\n", MiGenerateSystemImageNamesAddress);

	DbgPrintEx(77, 0, "MiObtainSectionForDriverAddress :[%p]\n", MiObtainSectionForDriverAddress);

	DbgPrintEx(77, 0, "MiGetSystemAddressForImageAddress :[%p]\n", MiGetSystemAddressForImageAddress);

	DbgPrintEx(77, 0, "MiMapSystemImageImageAddress :[%p]\n", MiMapSystemImageImageAddress);

	DbgPrintEx(77, 0, "RtlImageDirectoryEntryToData :[%p]\n", reinterpret_cast<PULONG64>(ntos.GetPointer("RtlImageDirectoryEntryToData")));

	DbgPrintEx(77, 0, "MiSnapThunkAddress :[%p]\n", MiSnapThunkAddress);

	DbgPrintEx(77, 0, "MmAcquireLoadLockAddress :[%p]\n", MmAcquireLoadLockAddress);

	DbgPrintEx(77, 0, "MmReleaseLoadLockAddress :[%p]\n", MmReleaseLoadLockAddress);

	DbgPrintEx(77, 0, "MiFillPteHierarchyAddress :[%p]\n", MiFillPteHierarchyAddress);

	DbgPrintEx(77, 0, "IopReadyDeviceObjectsAddress :[%p]\n", IopReadyDeviceObjectsAddress);

	DbgPrintEx(77, 0, "CmRegistryMachineHardwareDescriptionSystemNameAddress :[%p]\n",
		CmRegistryMachineHardwareDescriptionSystemNameAddress);

	DbgPrintEx(77, 0, "MiConstructLoaderEntryAddress :[%p]\n", MiConstructLoaderEntryAddress);

	DbgPrintEx(77, 0, "ObInsertObjectExAddress :[%p]\n", ObInsertObjectExAddress);

	DbgPrintEx(77, 0, "ObCreateObjectExAddress :[%p]\n", ObCreateObjectExAddress);

	DbgPrintEx(77, 0, "IopInvalidDeviceRequestAddress :[%p]\n", IopInvalidDeviceRequestAddress);

	DbgPrintEx(77, 0, "IopDriverLoadResourceAddress :[%p]\n", IopDriverLoadResourceAddress);

	DbgPrintEx(77, 0, "PIoDriverObjectType :[%p]\n", reinterpret_cast<PULONG64>(ntos.GetPointer("IoDriverObjectType")) );

	return TRUE;
}

}