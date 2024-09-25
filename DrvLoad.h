#pragma once
#include<ntifs.h>

#define DrvObjNamePrefix L"\\Driver\\"
#define ServiceRegistryPath L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define WDF "WDFLDR.SYS"

typedef struct _ShellContext {
	PDRIVER_OBJECT DrvObj;
	PUNICODE_STRING PSTR;
}ShellContext, * PShellContext;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG32 Flags;
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//WCHAR  DriverRegistryPrefix[0x100];

//关于无签名驱动加载
EXTERN_C ULONG64 CIFun;
EXTERN_C PULONG64 Pqword_14040EF40;
//获取Nt头
EXTERN_C PIMAGE_NT_HEADERS(*RtlImageNtHeader)(PVOID DllBase);

//获取资源第一步
EXTERN_C NTSTATUS(*MiGenerateSystemImageNames)(PUNICODE_STRING DriverPath, ULONG64 zero1, ULONG64 zero2, PUNICODE_STRING OutUnicode, PUNICODE_STRING OutUnicode14, PUNICODE_STRING String1);

//获取资源第二步 获取DriverSection _LDR_DATA_TABLE_ENTRY
EXTERN_C NTSTATUS(*MiObtainSectionForDriver)(PUNICODE_STRING String1, PUNICODE_STRING DriverPath, ULONG64 zero1, ULONG64 zero2, PULONG64 PDriverSection);

//创建镜像虚拟地址
EXTERN_C PUCHAR(*MiGetSystemAddressForImage)(PVOID PSECTION, int zero, int* un);

//映射镜像物理地址
EXTERN_C NTSTATUS(*MiMapSystemImage)(PVOID PSECTION, PUCHAR BaseVa);

//get 数据目录地址
EXTERN_C PUCHAR(*RtlImageDirectoryEntryToData)(PUCHAR DllBase, ULONG64 one, ULONG64 one1, PULONG32 PSize);

//填充IAT辅助函数
EXTERN_C NTSTATUS(*MiSnapThunk)(PUCHAR importDllBase, PUCHAR DllBase, PULONG64 PITE, PULONG64 PIATE, ULONG64 zero);

//线程上锁
EXTERN_C PKTHREAD(*MmAcquireLoadLock)();

//线程解锁
EXTERN_C VOID(*MmReleaseLoadLock)(PKTHREAD thread);

//获取PPTE
EXTERN_C ULONG64(*MiFillPteHierarchy)(ULONG64 va, PPTE_HIERARCHY Pout);

//需要调用这个函数，R3才能成功 CreateFile
EXTERN_C VOID(*IopReadyDeviceObjects)(PDRIVER_OBJECT DrvObj);

//驱动入口
EXTERN_C NTSTATUS(*ShellDriverEntry)(PVOID a, PVOID b);

//Other


EXTERN_C ULONG64 SectionOffset;
EXTERN_C PLIST_ENTRY64 PsLoadedModuleList;
EXTERN_C ULONG64 BaseDllNameOffset;
EXTERN_C ULONG64 DllBaseOffset;
EXTERN_C ULONG64 SizeOfImageOffset;
EXTERN_C ULONG64 FlagsOffset;


//----------------------

EXTERN_C PULONG64 PIoDriverObjectType;

//资源锁参数
EXTERN_C ULONG64 PIopDriverLoadResource;

//默认MajorFunction
EXTERN_C ULONG64 PIopInvalidDeviceRequest;

//创建对象
EXTERN_C NTSTATUS(*ObCreateObjectEx)(BOOLEAN AccMode, ULONG64 Type, POBJECT_ATTRIBUTES attributes, ULONG64 zero, PULONG64 Out, ULONG64 Size, ULONG64 zero1, ULONG64 zero2, PVOID PObject, ULONG64 zero3);

//加入对象表
EXTERN_C NTSTATUS(*ObInsertObjectEx)(PVOID PObject, ULONG64 zero, ULONG64 one, ULONG64 zero1, ULONG64 zero2, ULONG64 zero3, PHANDLE PHandle);

//重新构造DriverSection并插入链表
EXTERN_C NTSTATUS(*MiConstructLoaderEntry)(PLDR_DATA_TABLE_ENTRY DriverSection,
	PUNICODE_STRING DrvName,//"XXX.sys"
	PUNICODE_STRING DrvPath,//
	ULONG64 zero,
	ULONG64 one,
	PVOID PnewDriverSection);

EXTERN_C ULONG64 PCmRegistryMachineHardwareDescriptionSystemName;

VOID LoadDrv(PWCHAR DrvPath);
BOOLEAN CamouflageDrvLoad(PWCHAR ADrvPath, PWCHAR ODrvPath, PWCHAR ServiceName);