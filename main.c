#include"head.h"

#define HideDrvPath L"\\??\\C:\\Windows\\System32\\drivers\\klupd_klif_arkmon64.sys"

#define ADrvPath L"\\??\\C:\\Windows\\System32\\drivers\\klupd_klif_arkmon64.sys"

#define ODrvPath L"\\??\\C:\\Windows\\System32\\drivers\\TAOKernelEx64_ev.sys"

#define ServiceName  L"TAOKernelDriver"

PDRIVER_OBJECT Driver = NULL;

NTSTATUS Exit(DRIVER_OBJECT* DriverObject) {
	DbgPrintEx(77, 0, "DriverUnload\n");
	return STATUS_SUCCESS;
}



NTSTATUS DriverEntry(DRIVER_OBJECT* DriverObject, UNICODE_STRING* STR) {

	NTSTATUS status = STATUS_SUCCESS;

	Driver = DriverObject;

	



	if (!InitAllOffSet())
	{
		DbgPrintEx(77, 0, "Initialization All OffSets Failed£¡\n");

		return STATUS_UNSUCCESSFUL;
	}


	//LoadDrv(HideDrvPath);// Çý¶¯Òþ²Ø¼ÓÔØ²âÊÔ

	CamouflageDrvLoad(ADrvPath, ODrvPath, ServiceName);//Çý¶¯Î±×°¼ÓÔØ²âÊÔ


	return STATUS_INVALID_PARAMETER;

}