

# BlindEye: BattlEye kernel module bypass

## Abstract

By hooking the `ExAllocatePool` and `ExAllocatePoolWithTag` functions imported by the BattlEye kernel module, the memory allocation requests of the "report" function are dropped and the kernel detections are bypassed.

## Background

### BattlEye Kernel Module IAT

As shown in the figure below, the import table of BattlEye kernel module imports only few system functions, such as `MmGetSystemRoutineAddress`, `FltGetRoutineAddress`, etc. The rest of the large number of imported functions are obtained by calling `MmGetSystemRoutineAddress`, `FltGetRoutineAddress`.

<img src="import.png" alt="import" style="zoom:50%;" />

### Analysis of the "report" Function

The BattlEye kernel module will send packets when it finds an abnormal situation. By reverse analyzing the code after taking off the VMP, we can see the "report" function as follows.

1. customized reporting (no encryption)

```c++
void __fastcall daisy::report::custom(const void *Buffer, __int64 Size, ReportNode **Head, ReportNode **Tail)
{
    ReportNode *Node; // rbx
    void *Data; // rax

    Node = (ReportNode *)fn_ExAllocatePool(1i64, 24i64);
    if ( Node )
    {
        Data = (void *)fn_ExAllocatePool(1i64, Size);
        Node->Data = Data;
        if ( Data )
        {
            Node->Size = Size;
            memmove(Data, Buffer, (unsigned int)Size);
            Node->Next = 0i64;
            Node->UnknownFlag = 0;
            fn_KeWaitForSingleObject(&g_Mutex, 0i64, 0i64, 0i64, 0i64);
            if ( *Head )
                (*Tail)->Next = Node;
            else
                *Head = Node;
            *Tail = Node;
            fn_KeReleaseMutex(&g_Mutex, 0i64);
        }
        else
        {
            fn_ExFreePoolWithTag(Node, 0i64);
        }
    }
}
```

2. normal reporting (just "xor" encrypted)

```c++
void __fastcall daisy::report::normal(const void *Buffer, int Size)
{
    ReportNode *Node; // rbx
    void *Data; // rax
    int Key; // eax
    char ByteKey; // r8
    char *EncryptBuffer; // rcx
    int i; // edx
    signed __int64 v10; // rdi
    char t; // al
    __int64 TickCount; // [rsp+50h] [rbp+18h] BYREF

    Node = (ReportNode *)fn_ExAllocatePoolWithTag(1i64, 24i64, 'EB');
    if ( Node )
    {
        Node->Size = Size + 4;
        Data = (void *)fn_ExAllocatePoolWithTag(1i64, (unsigned int)(Size + 4), 'EB');// the first 4 bytes is the key
        Node->Data = Data;
        if ( Data )
        {
            TickCount = MEMORY[0xFFFFF78000000320];
            Key = fn_RtlRandomEx(&TickCount);
            ByteKey = Key;
            *(_DWORD *)Node->Data = Key;
            EncryptBuffer = (char *)Node->Data + 4;
            if ( Node->Data == (PVOID)-4i64 )   // WTF?
                EncryptBuffer = (char *)Buffer;
            i = 0;
            if ( Size > 0 )
            {
                v10 = (_BYTE *)Buffer - EncryptBuffer;
                do
                {
                    t = i++ ^ ByteKey ^ EncryptBuffer[v10];// EncryptBuffer[v10] just means Buffer[i]
                    t ^= 0xA5u;
                    *EncryptBuffer++ = t;
                    ByteKey = ~t;
                }
                while ( i < Size );
            }
            Node->Next = 0i64;
            fn_KeWaitForSingleObject(&g_Mutex, 0i64, 0i64, 0i64, 0i64);
            if ( g_EncryptHead )
                g_EncryptTail->Next = Node;
            else
                g_EncryptHead = Node;
            g_EncryptTail = Node;
            fn_KeReleaseMutex(&g_Mutex, 0i64);
        }
        else
        {
            fn_ExFreePoolWithTag(Node, 0i64);
        }
    }
}
```

The data structure is as follows:

```
+----------+                              +----------+
|   Head   |                              |   Tail   |
+----------+                              +----------+
     |                                         |
     V                                         V
+----------+     +----------+             +----------+
|  Node 1  | --> |  Node 2  | --> ... --> |  Node n  |
+----------+     +----------+             +----------+
     |                |                        |
     V                V                        V
+----------+     +----------+             +----------+
|  Data 1  |     |  Data 2  |             |  Data n  |
+----------+     +----------+             +----------+
```

Note：

1. The size of each node is 24 bytes and the type is `PagedPool`.

```c++
Node = (ReportNode *)fn_ExAllocatePool(1i64, 24i64);
```

```c++
Node = (ReportNode *)fn_ExAllocatePoolWithTag(1i64, 24i64, 'EB');
```

2. If the memory allocation request fails, the **function returns directly with no additional impact**.

## BlindEye

The project is based on GoodEye.

### Design

Watch the loading of BEDaisy.sys kernel module by calling `PsSetLoadImageNotifyRoutine` to register the callback, and return the address of the corresponding hook function through IAT hooking `MmGetSystemRoutineAddress` function. When the BattlEye kernel module calls `MmGetSystemRoutineAddress` to get the address of other import functions, it returns the address of the corresponding hook function again, so as to realize hooking other import functions.

The functions we need to hook are `ExAllocatePool`, `ExAllocatePoolWithTag `, and drop requests for memory of type `PagedPool` and size 24 when calling these functions.

Note that some other functions will also call `ExAllocatePool`, `ExAllocatePoolWithTag ` to allocate memory, and we need to let these requests go, otherwise BattlEye will not start properly. The method I use is a whitelist policy, where if the caller has previously allocated memory that is not filtered, that caller is whitelisted and all subsequent requests are allowed. Only requests that are not whitelisted and are of type `PagedPool` with a size of 24 are dropped.

The code is as follows: 

```c++
	PVOID gh_ExAllocatePoolWithTag(
		POOL_TYPE PoolType,
		SIZE_T NumberOfBytes,
		ULONG Tag
	) {
		const int WhiteListSize = 1000;
		static void* WhiteList[WhiteListSize]{};
		static int size = 0;
		void* ReturnAddress = _ReturnAddress();

		for (int i = 0; i < size; i++) {
			if (WhiteList[i] == ReturnAddress) {
				return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
			}
		}
		if (PoolType == 1 && NumberOfBytes == 24) {
			DBG_PRINT("ExAllocatePoolWithTag called from: 0x%p rejected!", ReturnAddress);
			return nullptr;
		}
		else {
			if (size < WhiteListSize) {
				WhiteList[size++] = ReturnAddress;
				return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
			}
			else {
				DBG_PRINT("ExAllocatePoolWithTag WhiteList is full");
				return nullptr;
			}
		}
	}
```

### Screenshot

<img src="screenshot.png" alt="screenshot" style="zoom:50%;" />

## Related Work

BattlEye devirtualized kernel module: https://www.unknowncheats.me/forum/anti-cheat-bypass/489381-bedaisy-sys-devirtualized.html

BattlEye reverse engineering analysis: https://github.com/dllcrt0/bedaisy-reversal

GoodEye: https://github.com/huoji120/goodeye
