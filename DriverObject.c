#include"Head.h"

extern PDRIVER_OBJECT Driver;

//��һ��û���豸���������ٳ�����IO
PDRIVER_OBJECT FindNotDeviceDriver() {
	PUCHAR DriverObjectByte = (PUCHAR)Driver;
	POBJECT_HEADER_NAME_INFO PObjHeaderNameInfo = (POBJECT_HEADER_NAME_INFO)(DriverObjectByte - _OBJECT_HEADER_Body_Offset - sizeof(OBJECT_HEADER_NAME_INFO));
	POBJECT_DIRECTORY PDirectory = PObjHeaderNameInfo->Directory;//����������Ŀ¼
	PDRIVER_OBJECT TargetDrvObj = NULL;
	POBJECT_DIRECTORY_ENTRY PSubDirectoryEntry = NULL;
	POBJECT_DIRECTORY_ENTRY PDirectoryEntry = NULL;
	//DbgBreakPoint();
	for (int i = 0; i < 37; i++) {
		PDirectoryEntry = PDirectory->HashBuckets[i];
		if (PDirectoryEntry == NULL) {
			continue;
		}
		PSubDirectoryEntry = PDirectoryEntry;
		while (PSubDirectoryEntry != NULL) {
			TargetDrvObj = (PDRIVER_OBJECT)(PSubDirectoryEntry->Object);
			if (TargetDrvObj->DeviceObject == NULL) {
				return TargetDrvObj;
			}
			PSubDirectoryEntry = PSubDirectoryEntry->ChainLink;
		}
	}
	return NULL;
}