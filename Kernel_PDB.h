#pragma once
#include<ntifs.h>

typedef struct _MyIID {
	ULONG32 a;//Dllbase + a Ϊ ���뺯������ƫ�Ʊ��n�� ��ַ
	ULONG32 b;
	ULONG32 c;
	ULONG32 d;//Dllbase + d Ϊ ����ģ������ ��ַ
	ULONG32 e;//Dllbase + e Ϊ ����n��뺯������ĵ�n�� ��ַ    
}MyIID, * PMyIID;


typedef struct _PTE_HIERARCHY {
	PULONG64* pte;
	PULONG64* PDE;
	PULONG64* PDPTE;
	PULONG64* PML4E;
}PTE_HIERARCHY,*PPTE_HIERARCHY;


//4kb  PDPE and PDE and PTE
typedef struct _PML4_ENTRY_4KB {
	union {
		UINT64 AsUInt64;
		struct {
			UINT64 Valid : 1;               // [0]
			UINT64 Write : 1;               // [1]
			UINT64 User : 1;                // [2]
			UINT64 WriteThrough : 1;        // [3]
			UINT64 CacheDisable : 1;        // [4]
			UINT64 Accessed : 1;            // [5]
			UINT64 Reserved1 : 3;           // [6:8]
			UINT64 Avl : 3;                 // [9:11]
			UINT64 PageFrameNumber : 40;    // [12:51]
			UINT64 Reserved2 : 11;          // [52:62]
			UINT64 NoExecute : 1;           // [63]
		} Fields;
	};
}
PML4_ENTRY_4KB, * PPML4_ENTRY_4KB, PDP_ENTRY_4KB, * PPDP_ENTRY_4KB, PD_ENTRY_4KB, * PPD_ENTRY_4KB, PT_ENTRY_4KB, * PPT_ENTRY_4KB;

EXTERN_C BOOLEAN InitAllOffSet();