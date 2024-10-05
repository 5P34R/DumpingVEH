#include <Windows.h>
#include <stdio.h>


#define WIN11Offset 0x019b408
#define ROR(x, y) ((unsigned)(x) >> (y) | (unsigned)(x) << 32 - (y))



typedef struct _VECTOR_HANDLER_ENTRY {
    LIST_ENTRY ListEntry;
    PLONG64 pRefCount; // ProcessHeap allocated, initialized with 1
    DWORD unk_0; // always 0
    DWORD pad_0;
    PVOID EncodedHandler;
} VECTOR_HANDLER_ENTRY, * PVECTOR_HANDLER_ENTRY;


typedef struct _LDRP_VECTOR_HANDLER_LIST {
    PSRWLOCK LdrpVehLock;
    LIST_ENTRY LdrpVehList;
    PSRWLOCK LdrpVchLock;
    LIST_ENTRY LdrpVchList;
} LDRP_VECTOR_HANDLER_LIST, * PLDRP_VECTOR_HANDLER_LIST;



typedef NTSTATUS(NTAPI* NtQueryInformationProcess)(
	HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS  ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);
    


DWORD GetProcessCookie() {
    DWORD cookie;
    ULONG ret;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) {
		return NULL;
	}

	NtQueryInformationProcess pNtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		return NULL;
	}

	pNtQueryInformationProcess(GetCurrentProcess(), 0x24, &cookie, sizeof(cookie), &ret);
	return (DWORD)cookie;

}



PVOID DecodePointers(PVOID pointer) {
	DWORD cookie = GetProcessCookie();
    return (PVOID)RotateRight64((ULONG_PTR)pointer, 0x40 - (cookie & 0x3f) ^ cookie);
}

PVOID EncodePointer(PVOID pointer, DWORD cookie) {
	return (PVOID)(RotateLeft64((ULONG_PTR)pointer ^ cookie, (cookie & 0x3f)));
}


PVOID HandlerList() {

    PBYTE pNext = NULL;
    PBYTE pRtlpAddVectoredHandler = NULL;
    PBYTE pVehList = NULL;
    int offset = 0;
    int     i = 1;

    PBYTE pRtlAddVectoredExceptionHandler = (PBYTE)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "RtlAddVectoredExceptionHandler");
    printf("[*] RtlAddVectoredExceptionHandler: 0x%p\n", pRtlAddVectoredExceptionHandler);

    //RtlpAddVectoredHandler is always 0x10 away
    pRtlpAddVectoredHandler = (ULONG_PTR)pRtlAddVectoredExceptionHandler + 0x10;
    printf("[*] RtlpAddVectoredHandler: 0x%p\n", pRtlpAddVectoredHandler);

    while (TRUE) {

        if ((*pRtlpAddVectoredHandler == 0x48) && (*(pRtlpAddVectoredHandler + 1) == 0x8d) && (*(pRtlpAddVectoredHandler + 2) == 0x0d)) {

            if (i == 2) {
                offset = *(int*)(pRtlpAddVectoredHandler + 3);
                pNext = (ULONG_PTR)pRtlpAddVectoredHandler + 7;
                pVehList = pNext + offset;
                return pVehList;
            }
            else {
                i++;
            }
        }

        pRtlpAddVectoredHandler++;
    }

    return NULL;
}


LONG NTAPI MyVEHHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    printf("MyVEHHandler (0x%x)\n", ExceptionInfo->ExceptionRecord->ExceptionCode);

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        printf("  Divide by zero at 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
        ExceptionInfo->ContextRecord->Rip += 2; // Skip the div instruction
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {

    PVOID addr = AddVectoredExceptionHandler(1, MyVEHHandler);
    printf("[+] Added VEH at : 0x%p\n", addr);


    addr = AddVectoredExceptionHandler(1, MyVEHHandler);
    printf("[+] Added VEH at : 0x%p\n", addr);

    addr = AddVectoredExceptionHandler(1, MyVEHHandler);
    printf("[+] Added VEH at : 0x%p\n", addr);


    PLDRP_VECTOR_HANDLER_LIST pLdrpVectorHandlerList = HandlerList();

    LDRP_VECTOR_HANDLER_LIST handle_list = { 0 };

    LIST_ENTRY* pListHead = &pLdrpVectorHandlerList->LdrpVehList;
	
   for (LIST_ENTRY* pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
  {
        PVECTOR_HANDLER_ENTRY pEntry = CONTAINING_RECORD(pListEntry, VECTOR_HANDLER_ENTRY, ListEntry);
		printf("Entry: 0x%p\n", pEntry);
        LPVOID pExceptionHandler = DecodePointer(pEntry->EncodedHandler);

		printf("Handler: 0x%p\n\n", pExceptionHandler);


  //      // do something with the pointer
    }

	getchar();

    return 0;
}
