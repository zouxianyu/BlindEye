#include "DriverUtil.h"

namespace DriverUtil
{
    // This function was created with help from wlan
    //
    // Links to his work: 
    // https://github.com/not-wlan/driver-hijack
    // https://www.unknowncheats.me/forum/c-and-c-/274073-iterating-driver_objects.html
    // https://www.unknowncheats.me/forum/anti-cheat-bypass/274881-memedriver-driver-object-hijack-poc.html

    PDRIVER_OBJECT GetDriverObject(PUNICODE_STRING lpDriverName)
    {
        HANDLE handle{};
        OBJECT_ATTRIBUTES attributes{};
        UNICODE_STRING directory_name{};
        PVOID directory{};
        BOOLEAN success = FALSE;
        FAST_IO_DISPATCH fastIoDispatch;
        bool installedHook = false;
        RtlZeroMemory(&fastIoDispatch, sizeof(FAST_IO_DISPATCH));
        RtlInitUnicodeString(&directory_name, L"\\Driver");
        InitializeObjectAttributes(
            &attributes,
            &directory_name,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL
        );

        // open OBJECT_DIRECTORY for \\Driver
        auto status = ZwOpenDirectoryObject(
            &handle,
            DIRECTORY_ALL_ACCESS,
            &attributes
        );

        if (!NT_SUCCESS(status))
        {
            DBG_PRINT("ZwOpenDirectoryObject Failed");
            return NULL;
        }

        // Get OBJECT_DIRECTORY pointer from HANDLE
        status = ObReferenceObjectByHandle(
            handle,
            DIRECTORY_ALL_ACCESS,
            nullptr,
            KernelMode,
            &directory,
            nullptr
        );

        if (!NT_SUCCESS(status))
        {
            DBG_PRINT("ObReferenceObjectByHandle Failed");
            ZwClose(handle);
            return NULL;
        }

        const auto directory_object = POBJECT_DIRECTORY(directory);
        if (!directory_object)
            return NULL;

        ExAcquirePushLockExclusiveEx(&directory_object->Lock, 0);

        // traverse hash table with 37 entries
        // when a new object is created, the object manager computes a hash value in the range zero to 36 from the object name and creates an OBJECT_DIRECTORY_ENTRY.    
        // http://www.informit.com/articles/article.aspx?p=22443&seqNum=7
        for (auto entry : directory_object->HashBuckets)
        {
            if (!entry)
                continue;

            while (entry && entry->Object)
            {
                auto driver = PDRIVER_OBJECT(entry->Object);
                if (!driver)
                    continue;

                if (wcscmp(driver->DriverExtension->ServiceKeyName.Buffer, lpDriverName->Buffer) == 0)
                    return driver;
            }
        }

        ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
        // Release the acquired resources back to the OS
        ObDereferenceObject(directory);
        ZwClose(handle);
        //TODO remove
        return NULL;
    }

    PVOID GetDriverBase(LPCSTR module_name)
    {
        ULONG bytes{};
        NTSTATUS status = ZwQuerySystemInformation(
            SystemModuleInformation,
            NULL,
            bytes,
            &bytes
        );
        if (!bytes)
            return NULL;
        PRTL_PROCESS_MODULES modules =
            (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, POOLTAG);

        if (modules)
        {
            status = ZwQuerySystemInformation(
                SystemModuleInformation,
                modules,
                bytes,
                &bytes
            );

            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(modules, POOLTAG);
                return NULL;
            }
            
            PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
            PVOID module_base{}, module_size{};
            for (ULONG i = 0; i < modules->NumberOfModules; i++)
            {
                if (strcmp(reinterpret_cast<char*>(module[i].FullPathName + module[i].OffsetToFileName), module_name) == 0)
                {
                    module_base = module[i].ImageBase;
                    module_size = (PVOID)module[i].ImageSize;
                    break;
                }
            }
            ExFreePoolWithTag(modules, POOLTAG);
            return module_base;
        }
        return NULL;
    }

    PVOID GetSystemModuleExport(LPCSTR ModName, LPCSTR RoutineName)
    {
        PVOID result = GetDriverBase(ModName);
        if (!result)
            return NULL;
        return RtlFindExportedRoutineByName(result, RoutineName);
    }

    PVOID IATHook(PVOID lpBaseAddress, CHAR* lpcStrImport, PVOID lpFuncAddress)
    {
        if (!lpBaseAddress || !lpcStrImport || !lpFuncAddress)
            return NULL;

        PIMAGE_DOS_HEADER dosHeaders = 
            reinterpret_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);

        PIMAGE_NT_HEADERS ntHeaders = 
            reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<DWORD_PTR>(lpBaseAddress) + dosHeaders->e_lfanew);

        IMAGE_DATA_DIRECTORY importsDirectory = 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = 
            reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importsDirectory.VirtualAddress + (DWORD_PTR)lpBaseAddress);

        LPCSTR libraryName = NULL;
        PVOID result = NULL;
        PIMAGE_IMPORT_BY_NAME functionName = NULL;

        if (!importDescriptor) 
            return NULL;

        while (importDescriptor->Name != NULL)
        {
            libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)lpBaseAddress;
            if (GetDriverBase(libraryName))
            {
                PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
                originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + importDescriptor->OriginalFirstThunk);
                firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + importDescriptor->FirstThunk);
                while (originalFirstThunk->u1.AddressOfData != NULL)
                {
                    functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBaseAddress + originalFirstThunk->u1.AddressOfData);
                    if (strcmp(functionName->Name, lpcStrImport) == 0)
                    {
                        // save old function pointer
                        result = reinterpret_cast<PVOID>(firstThunk->u1.Function);
                        Memory::WriteProtectOff();
                        // swap address
                        firstThunk->u1.Function = reinterpret_cast<ULONG64>(lpFuncAddress);
                        Memory::WriteProtectOn();
                        return result;
                    }
                    ++originalFirstThunk;
                    ++firstThunk;
                }
            }
            importDescriptor++;
        }
        return NULL;
    }

    PVOID DriverIATHook(PDRIVER_OBJECT pDriverObject, CHAR* lpcStrImport, PVOID lpFuncAddress)
    {
        if (!pDriverObject || !lpcStrImport)
            return NULL;
        return IATHook(pDriverObject->DriverStart, lpcStrImport, lpFuncAddress);
    }

    VOID DumpDriver(PDRIVER_OBJECT lpDriverObject)
    {
        DumpDriver(lpDriverObject->DriverStart);
    }

    VOID DumpDriver(PVOID lpBaseAddress)
    {
        if (!lpBaseAddress || *(short*) lpBaseAddress != 0x5A4D)
            return;

        PIMAGE_DOS_HEADER dosHeaders =
            reinterpret_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);

        PIMAGE_NT_HEADERS ntHeaders =
            reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<DWORD_PTR>(lpBaseAddress) + dosHeaders->e_lfanew);

        HANDLE             hFile;
        UNICODE_STRING     uniName;
        OBJECT_ATTRIBUTES  objAttr;
        IO_STATUS_BLOCK    ioStatusBlock;
        LARGE_INTEGER      offset{};

        RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\DriverDump.sys");
        InitializeObjectAttributes(&objAttr, &uniName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL
        );

        ZwCreateFile(&hFile,
            GENERIC_WRITE,
            &objAttr,
            &ioStatusBlock, 
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 
            NULL
        );

        ZwWriteFile(
            hFile,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            lpBaseAddress,
            ntHeaders->OptionalHeader.SizeOfImage,
            &offset,
            NULL
        );

        ZwClose(hFile);
    }

    void MemDump(void* BaseAddress, unsigned Size)
    {
        if (!BaseAddress || !Size)
            return;

        HANDLE             h_file;
        UNICODE_STRING     name;
        OBJECT_ATTRIBUTES  attr;
        IO_STATUS_BLOCK    status_block;
        LARGE_INTEGER      offset{ NULL };

        RtlInitUnicodeString(&name, L"\\DosDevices\\C:\\dump.bin");
        InitializeObjectAttributes(&attr, &name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL
        );

        auto status = ZwCreateFile(
            &h_file,
            GENERIC_WRITE,
            &attr,
            &status_block,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            NULL,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            NULL
        );

        status = ZwWriteFile(
            h_file,
            NULL,
            NULL,
            NULL,
            &status_block,
            BaseAddress,
            Size,
            &offset,
            NULL
        );
        ZwClose(h_file);
    }
}