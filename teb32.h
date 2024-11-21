//
// [TEB_/PEB_/SEH SUMMARY]
// This file contains the undocumented TEB_ (Thread Environment Block) and PEB_ (Process Environment Block)
// definitions for the Intel x86 32-bit Windows operating systems starting from NT 3.51 through Windows 10.  The TEB_
// is also known as the TIB (Thread Information Block), especially under the Windows 9.x operating systems.
//
// Additionally I have added the definitions for the partially documented Win32 SEH (Structured Exception Handling)
// that are not only referenced by the TEB_, but are normally strewn across both C headers and assembler includes.
// These definitions also include the constants specific to the Visual C++ compiler's implementation of Win32
// SEH beyond the facilities provided by the Windows operating systems.  The TEB_ and PEB_ are declared near the
// bottom of this file, with all referenced structures recursively defined above them for completeness sake.
//
// Should you be writing low level code, you might find all of these definitions in one spot a handy reference.  If
// you wanted to use this C header file in your own code, you'd probably want to remove the redundant definitions
// (almost all except for the TEB_ and PEB_ structures) as they are defined automatically as a result of including
// windows.h.  If you won't be including windows.h or are compiling with GCC under Linux, no changes are
// necessary.
//
// [WINDOWS COMPATIBILITY]
// Both the TEB_ and PEB_ structures support Windows NT 3.51 thru Windows 10
//
// [HOW TO ACCESS THESE STRUCTURES]
// The pointers to these structures can be obtained using the following x86 assembly code:
//      mov eax, fs:[18h]   //eax = TEB_
//      mov eax, fs:[30h]   //eax = PEB_
//
// Or, by using the following Visual C++ compiler intrinsics:
//      voidp pTeb = __readfsdword(0x18);
//      voidp pPeb = __readfsdword(0x30);
//
// [BUGS]
// This header file is meant mostly for documentation purposes as an alternative to the various tables found
// online; therefore it may contain bugs such that certain members might not be at the offsets stated in the
// comments because I may have forgotten to pad prior members so that everything lines up.  However, I did attempt
// to have all the members line up as documented by each member's offset (see comment to right of each member), so
// please report any bugs or additions to: http://bytepointer.com/contact.htm
//
// [STYLE USED IN THIS FILE]
// I modified the structures included in this file either from the original official forms found in the Windows
// headers or from various sources online, although the result is functionally equivalent.  The modifications were
// made according to the following scheme for simplicity and clarity:
//
// - array size values are in hex (base-16)
//
// - I avoided creating extraneous pointer types either standalone or as part of the trailing portions of structure
//  definitions.  These take the format Pxxxx where xxxx is the type. Microsoft has historically declared Pxxxx
//  definitions for practically every Windows structure in place of the type identifier with a trailing asterisk.
//  I've always found the trailing asterisk signifying a pointer type to be clearer than the Pxxxx alternative
//  because you can quickly spot them at a glance (especially when syntax hilighting kicks in).
//
// - Windows headers use many aliases for 8, 16, 32 and 64-bit values (UCHAR, ULONG, ULONG_PTR, LONG, LONGLONG, etc.)
//   which are inconsistent at times. I tend to prefer the explicitly specific assembler names: BYTE, WORD, DWORD and
//   QWORD as they are more platform independent names for unsigned values.  Any signed integer type consisting of
//   the term LONG (especially the recursive LONGLONG) just makes me cringe because I don't feel they convey size
//   very well. My naming scheme is therefore:
//
//     BYTE-SIZE                      1     2       4         8
//     unsigned integer types:     BYTE, WORD,  DWORD and QWORD
//     signed integer types:       CHAR, INT16, INT32 and INT64
//
// NOTE: voidp and DWORD may be used interchangeably on 32-bit operating systems, however I attempted
//       to use voidp (or typed structure pointer where possible) where I was sure the member was to
//       hold a pointer.  Otherwise and where members were to hold padding ints (of any size), I
//       avoided the use of pointer types even when originally declared to be of type voidp. Also I
//       retained the use of some aliases, such as BOOLEAN, NTSTATUS, _HANDLE, etc. only for the
//       purpose of preserving the meaning of the associated structure members.
//
// [MICROSOFT FIRST DOCUMENTS THE TEB_ and PEB_]
// Starting with the release of Visual Studio .NET (2002), Microsoft released a new header, winternl.h
// with the Platform SDK. Within this new header was the first public documentation for the TEB_ and PEB_.
// Microsoft, being legally forced to disclose this information, only released 2 members of the PEB_
// (BeingDebugged,SessionId) and 3 members of the TEB_ (TlsSlots,ReservedForOle,TlsExpansionSlots).
// The original portion of the winternl.h header file is shown below along with Microsoft's usual stern
// warnings about not using these fields because Windows might change.
//
//      //
//      // The PEB_ and TEB_ structures are subject to changes between Windows
//      // releases, thus the fields offsets may change as well as the Reserved
//      // fields.  The Reserved fields are reserved for use only by the Windows
//      // operating systems.  Do not assume a maximum size for the structures.
//      //
//
//      // Instead of using the BeingDebugged field, use the Win32 APIs
//      //     IsDebuggerPresent, CheckRemoteDebuggerPresent
//      // Instead of using the SessionId field, use the Win32 APIs
//      //     GetCurrentProcessId and ProcessIdToSessionId
//      // Sample x86 assembly code that gets the SessionId (subject to change
//      //     between Windows releases, use the Win32 APIs to make your application
//      //     resilient to changes)
//      //     mov     eax,fs:[00000018]
//      //     mov     eax,[eax+0x30]
//      //     mov     eax,[eax+0x1d4]
//      //
//      struct PEB_ {
//          BYTE Reserved1[2];
//          BYTE BeingDebugged;
//          BYTE Reserved2[229];
//          voidp Reserved3[59];
//          ULONG SessionId;
//      } PEB_, *PPEB;
//
//      // Instead of using the Tls fields, use the Win32 TLS APIs
//      //     TlsAlloc, TlsGetValue, TlsSetValue, TlsFree
//      //
//      // Instead of using the ReservedForOle field, use the COM API
//      //     CoGetContextToken
//      //
//      struct TEB_ {
//          BYTE Reserved1[1952];
//          voidp Reserved2[412];
//          voidp TlsSlots[64];
//          BYTE Reserved3[8];
//          voidp Reserved4[26];
//          voidp ReservedForOle;  // Windows 2000 only
//          voidp Reserved5[4];
//          voidp TlsExpansionSlots;
//      } TEB_;
//      typedef TEB_ *PTEB;
//
// [REFERENCES]
// The information below was compiled from various sources:
//    http://www.geoffchappell.com/studies/windows/win32/ntdll/structs/TEB_/index.htm
//    http://www.geoffchappell.com/studies/windows/win32/ntdll/structs/PEB_/index.htm
//    http://terminus.rewolf.pl/terminus/structures/ntdll/_TEB32_x86.html
//    https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
//    http://www.nirsoft.net/kernel_struct/vista/index.html
//    Microsoft's Platform SDK headers / MSDN
//
// [CHANGELIST]
//    2018-05-02:   -now can be compiled alongside windows.h (without changes) or by defining WANT_ALL_WINDOWS_H_DEFINITIONS so this file can be used standalone
//                  -this file may also be included alongside tebpeb64.h which can be found at http://bytepointer.com/resources/tebpeb64.h
//                  -increased PEB_ size to 0x258 for [at least] Windows 10: member addition dwSystemCallMode at offset 0x254
//                   REFERENCE: https://www.malwaretech.com/2015/07/windows-10-system-call-stub-changes.html
//
//    2017-07-29:   initial public release (first stable version)
//

#include <stdint.h>

//disable some Visual C++ warnings
#ifdef _MSC_VER
    //when compiling as C
    #pragma warning (disable:4214) //Warning Level 4: C4214: nonstandard extension used : bit field types other than int

    //"#pragma pack(1)" not needed as Microsoft has designed all structure members to be on natural boundaries

    #ifndef STDCALL
        #define STDCALL         __stdcall
    #endif
    #ifndef CDECL
        #define CDECL           __cdecl
    #endif
#else
    //assume GCC
    #ifndef STDCALL
        #define STDCALL         __attribute__ ((stdcall))
    #endif
    #ifndef CDECL
        #define CDECL           __attribute__ ((cdecl))
    #endif
#endif

typedef uint32_t voidp;     //proxy for void*
typedef uint32_t CHARp;     //proxy for CHAR*
typedef uint32_t WCHARp;     //proxy for WCHAR*
typedef uint32_t DWORDp;     //proxy for DWORD*
typedef voidp    _HANDLE;

#ifndef _MSC_VER

//
// Base types
//

//This is for 32 bit so we need pointer fields to size out to 32 bits even when
//building on 64-bit systems

typedef uint8_t           BYTE;
typedef int8_t            CHAR;
typedef uint16_t          WORD;
typedef int16_t           INT16;
typedef uint32_t          DWORD;
typedef int32_t           INT32;
typedef BYTE              BOOLEAN;
typedef BYTE              UCHAR;
typedef voidp             _HANDLE;
typedef WORD              WCHAR;
typedef WORD              USHORT;
typedef DWORD             LCID;
typedef DWORD             KAFFINITY;
typedef DWORD             ULONG;

#endif //#ifdef WANT_ALL_WINDOWS_H_DEFINITIONS


//always declare 64-bit types

#ifdef _MSC_VER
    //Visual C++
    typedef unsigned __int64    QWORD;
    typedef __int64             INT64;
#else
    //GCC
    typedef uint64_t  QWORD;
    typedef int64_t   INT64;
#endif


//#ifdef WANT_ALL_WINDOWS_H_DEFINITIONS

//
// General-purpose structures
//

union LARGE_INTEGER_
{
    struct
    {
        DWORD   LowPart;
        INT32   HighPart;
    } u;
    INT64       QuadPart;
};

union ULARGE_INTEGER_
{
    struct
    {
       DWORD LowPart;
       DWORD HighPart;
    } u;
    QWORD QuadPart;
};

struct GUID_
{
    DWORD   Data1;
    WORD    Data2;
    WORD    Data3;
    BYTE    Data4[8];
};

typedef voidp LIST_ENTRY_p;

struct LIST_ENTRY_
{
    LIST_ENTRY_p Flink;
    LIST_ENTRY_p Blink;
};

struct RTL_CRITICAL_SECTION_;

typedef voidp RTL_CRITICAL_SECTION_p;

struct RTL_CRITICAL_SECTION_
{
    WORD                    Type;
    WORD                    CreatorBackTraceIndex;
    RTL_CRITICAL_SECTION_p   CriticalSection;
    LIST_ENTRY_              ProcessLocksList;
    DWORD                   EntryCount;
    DWORD                   ContentionCount;
    DWORD                   Flags;
    WORD                    CreatorBackTraceIndexHigh;
    WORD                    SpareUSHORT;
};

typedef voidp RTL_CRITICAL_SECTION_DEBUG_p;

struct RTL_CRITICAL_SECTION_DEBUG_
{
    RTL_CRITICAL_SECTION_DEBUG_p DebugInfo;
    INT32                       LockCount;
    INT32                       RecursionCount;
    _HANDLE                      OwningThread;
    _HANDLE                      LockSemaphore;
    DWORD                       SpinCount;
};

//#endif //WANT_ALL_WINDOWS_H_DEFINITIONS


struct CLIENT_ID_
{
     DWORD  ProcessId;
     DWORD  ThreadId;
};

struct PROCESSOR_NUMBER_
{
    WORD    Group;
    BYTE    Number;
    BYTE    Reserved;
};

struct STRING_
{
    WORD    Length;
    WORD    MaximumLength;
    CHARp   Buffer;
};

struct UNICODE_STRING_
{
    WORD    Length;
    WORD    MaximumLength;
    WCHARp  Buffer;
};


//
// Exception-specific structures and definitions
//

//CONTEXT_ flags
#define CONTEXT_i386                    0x00010000                      // this assumes that i386 and
#define CONTEXT_i486                    0x00010000                      // i486 have identical CONTEXT_ records
#define CONTEXT_CONTROL                 (CONTEXT_i386 | 0x00000001L)    // SS:SP, CS:IP, FLAGS, BP
#define CONTEXT_INTEGER                 (CONTEXT_i386 | 0x00000002L)    // AX, BX, CX, DX, SI, DI
#define CONTEXT_SEGMENTS                (CONTEXT_i386 | 0x00000004L)    // DS, ES, FS, GS
#define CONTEXT_FLOATING_POINT          (CONTEXT_i386 | 0x00000008L)    // 387 state
#define CONTEXT_DEBUG_REGISTERS         (CONTEXT_i386 | 0x00000010L)    // DB 0-3,6,7
#define CONTEXT_EXTENDED_REGISTERS      (CONTEXT_i386 | 0x00000020L)    // cpu specific extensions
#define CONTEXT_FULL                    (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)
#define CONTEXT_ALL                     (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS)

//exception flags
#define EXCEPTION_NONCONTINUABLE        0x1     // Noncontinuable exception
#define EXCEPTION_UNWINDING             0x2     // Unwind is in progress; same as EH_UNWINDING
#define EXCEPTION_EXIT_UNWIND           0x4     // Exit unwind is in progress; same as EH_EXIT_UNWIND
#define EXCEPTION_STACK_INVALID         0x8     // Stack out of limits or unaligned
#define EXCEPTION_NESTED_CALL           0x10    // Nested exception handler call
#define EXCEPTION_TARGET_UNWIND         0x20    // Target unwind in progress
#define EXCEPTION_COLLIDED_UNWIND       0x40    // Collided exception handler call
#define EXCEPTION_UNWIND                (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND)
#define IS_UNWINDING(Flag)              ((Flag & EXCEPTION_UNWIND) != 0)
#define IS_DISPATCHING(Flag)            ((Flag & EXCEPTION_UNWIND) == 0)
#define IS_TARGET_UNWIND(Flag)          (Flag & EXCEPTION_TARGET_UNWIND)

//msvc exception filter expression return codes
#define EXCEPTION_EXECUTE_HANDLER       1   //same as FILTER_ACCEPT
#define EXCEPTION_CONTINUE_SEARCH       0   //same as FILTER_CONTINUE_SEARCH
#define EXCEPTION_CONTINUE_EXECUTION    -1  //same as FILTER_DISMISS

//#ifdef WANT_ALL_WINDOWS_H_DEFINITIONS

//exception handler (disposition) return values
enum EXCEPTION_DISPOSITION_
{
    _ExceptionContinueExecution,         //0; same as DISPOSITION_DISMISS, _XCPT_CONTINUE_EXECUTION
    _ExceptionContinueSearch,            //1; same as DISPOSITION_CONTINUE_SEARCH, _XCPT_CONTINUE_SEARCH
    _ExceptionNestedException,           //2; same as DISPOSITION_NESTED_EXCEPTION
    _ExceptionCollidedUnwind             //3; same as DISPOSITION_COLLIDED_UNWIND
};

typedef voidp EXCEPTION_RECORD_p;

#define EXCEPTION_MAXIMUM_PARAMETERS 15
struct EXCEPTION_RECORD_ //size=0x50
{
    DWORD               ExceptionCode;                                          //0x00
    DWORD               ExceptionFlags;                                         //0x04 - see possible values above
    EXCEPTION_RECORD_p   ExceptionRecord;                                        //0x08
    voidp               ExceptionAddress;                                       //0x0C
    DWORD               NumberParameters;                                       //0x10
    DWORD               ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];     //0x14
};

#define SIZE_OF_80387_REGISTERS 80
struct FLOATING_SAVE_AREA_ //size=0x70
{
    DWORD   ControlWord;                                //0x00
    DWORD   StatusWord;                                 //0x04
    DWORD   TagWord;                                    //0x08
    DWORD   ErrorOffset;                                //0x0C
    DWORD   ErrorSelector;                              //0x10
    DWORD   DataOffset;                                 //0x14
    DWORD   DataSelector;                               //0x18
    BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];      //0x1C
    DWORD   Cr0NpxState;                                //0x6C
};

#define MAXIMUM_SUPPORTED_EXTENSION 512
struct CONTEXT_ //size=0x2CC
{
    //determines which groups of members are valid
    DWORD               ContextFlags;                                       //0x00 - see possible values above
    //following member group valid when CONTEXT_DEBUG_REGISTERS set
    DWORD               Dr0;                                                //0x04
    DWORD               Dr1;                                                //0x08
    DWORD               Dr2;                                                //0x0C
    DWORD               Dr3;                                                //0x10
    DWORD               Dr6;                                                //0x14
    DWORD               Dr7;                                                //0x18
    //following member valid when CONTEXT_FLOATING_POINT set
    FLOATING_SAVE_AREA_  FloatSave;                                          //0x1C
    //following member group valid when CONTEXT_SEGMENTS set
    DWORD               SegGs;                                              //0x8C
    DWORD               SegFs;                                              //0x90
    DWORD               SegEs;                                              //0x94
    DWORD               SegDs;                                              //0x98
    //following member group valid when CONTEXT_INTEGER set
    DWORD               Edi;                                                //0x9C
    DWORD               Esi;                                                //0xA0
    DWORD               Ebx;                                                //0xA4
    DWORD               Edx;                                                //0xA8
    DWORD               Ecx;                                                //0xAC
    DWORD               Eax;                                                //0xB0
    //following member group valid when CONTEXT_CONTROL set
    DWORD               Ebp;                                                //0xB4
    DWORD               Eip;                                                //0xB8
    DWORD               SegCs;                                              //0xBC
    DWORD               EFlags;                                             //0xC0
    DWORD               Esp;                                                //0xC4
    DWORD               SegSs;                                              //0xC8
    //following member valid when CONTEXT_EXTENDED_REGISTERS set
    BYTE                ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];     //0xCC
};

typedef voidp CONTEXT_p;

//used with UnhandledExceptionFilter()/SetUnhandledExceptionFilter() and newer Vectored Exception handling functions
struct EXCEPTION_POINTERS_
{
    EXCEPTION_RECORD_p   ExceptionRecord;
    CONTEXT_p            ContextRecord;
};

//#endif //WANT_ALL_WINDOWS_H_DEFINITIONS

struct EXCEPTION_REGISTRATION_;

typedef voidp EXCEPTION_REGISTRATION_p;

//dispatcher CONTEXT_ is reserved for exception handler implementation (e.g. compilers)
struct DISPATCHER_CONTEXT_
{
    EXCEPTION_REGISTRATION_p RegistrationPointer;
};

//exception handler signatures
//typedef EXCEPTION_DISPOSITION_ (CDECL *ExceptionHandler)(EXCEPTION_RECORD_p ExceptionRecord, EXCEPTION_REGISTRATION_p EstablisherFrame, CONTEXT_p ContextRecord, DISPATCHER_CONTEXT_p DispatcherContext); //same as EXCEPTION_ROUTINE and _except_handler
//typedef INT32 (STDCALL *TopLevelExceptionFilter)(EXCEPTION_POINTERS_* ExceptionInfo); //same as TOP_LEVEL_EXCEPTION_FILTER for SetUnhandledExceptionFilter();
//typedef INT32 (STDCALL *VectoredExceptionHandler)(EXCEPTION_POINTERS_* ExceptionInfo); //same as PVECTORED_EXCEPTION_HANDLER and above signature used with AddVectoredExceptionHandler(), RemoveVectoredExceptionHandler() for XP/WS03 and up

typedef voidp ExceptionHandler_p;
typedef voidp EXCEPTION_REGISTRATION_p;

//stack exception frame a.k.a. EXCEPTION_REGISTRATION_RECORD
struct EXCEPTION_REGISTRATION_
{
    EXCEPTION_REGISTRATION_p     prev;
    ExceptionHandler_p           handler;
};
#define EXCEPTION_CHAIN_END ((EXCEPTION_REGISTRATION_p)-1)

//
// PEB_-specific structures
//

//forward declarations for unknown structures
struct ACTIVATION_CONTEXT_DATA_ {voidp dummy;}; //XP and up
struct ASSEMBLY_STORAGE_MAP_ {voidp dummy;};       //XP and up
struct FLS_CALLBACK_INFO_ {voidp dummy;};             //WS03 and up

struct RTL_DRIVE_LETTER_CURDIR_
{
     WORD       Flags;
     WORD       Length;
     DWORD      TimeStamp;
     STRING_     DosPath;
};

struct PEB_LDR_DATA_
{
     DWORD          Length;
     BYTE           Initialized;
     voidp          SsHandle;
     LIST_ENTRY_     InLoadOrderModuleList;
     LIST_ENTRY_     InMemoryOrderModuleList;
     LIST_ENTRY_     InInitializationOrderModuleList;
     voidp          EntryInProgress;
};

struct LDR_DATA_TABLE_ENTRY_ {
   LIST_ENTRY_ InLoadOrderLinks;
   LIST_ENTRY_ InMemoryOrderLinks;
   union {
       LIST_ENTRY_ InInitializationOrderLinks;
       LIST_ENTRY_ InProgressLinks;
   };
   voidp DllBase;
   voidp EntryPoint;
   ULONG SizeOfImage;
   UNICODE_STRING_ FullDllName;
   UNICODE_STRING_ BaseDllName;
   ULONG Flags;
   union {
       UCHAR FlagGroup [4];
       ULONG _Flags;
       struct {
           ULONG PackagedBinary : 1;           // 0x00000001
           ULONG MarkedForRemoval : 1;         // 0x00000002
           ULONG ImageDll : 1;                 // 0x00000004
           ULONG LoadNotificationsSent : 1;    // 0x00000008
           ULONG TelemetryEntryProcessed : 1;  // 0x00000010
           ULONG ProcessStaticImport : 1;      // 0x00000020
           ULONG InLegacyLists : 1;            // 0x00000040
           ULONG InIndexes : 1;                // 0x00000080
           ULONG ShimDll : 1;                  // 0x00000100
           ULONG InExceptionTable : 1;         // 0x00000200
           ULONG ReservedFlags1 : 2;
           ULONG LoadInProgress : 1;           // 0x00001000
           ULONG ReservedFlags2 : 1;
           ULONG EntryProcessed : 1;           // 0x00004000
           ULONG ReservedFlags3 : 3;
           ULONG DontCallForThreads : 1;       // 0x00040000
           ULONG ProcessAttachCalled : 1;      // 0x00080000
           ULONG ProcessAttachFailed : 1;      // 0x00100000
           ULONG CorDeferredValidate : 1;      // 0x00200000
           ULONG CorImage : 1;                 // 0x00400000
           ULONG DontRelocate : 1;             // 0x00800000
           ULONG CorILOnly : 1;                // 0x01000000
           ULONG ReservedFlags5 : 3;
           ULONG Redirected : 1;               // 0x10000000
           ULONG ReservedFlags6 : 2;
           ULONG CompatDatabaseProcessed : 1;  // 0x80000000
       };
   };
   USHORT LoadCount;
   USHORT ObsoleteLoadCount;
   USHORT TlsIndex;
   union {
       LIST_ENTRY_ HashLinks;
       struct {
           voidp SectionPointer;
           ULONG CheckSum;
       };
   };
};

typedef voidp PEB_FREE_BLOCK_p;

struct PEB_FREE_BLOCK_
{
     PEB_FREE_BLOCK_p    Next;
     DWORD              Size;
};

struct RTL_USER_PROCESS_PARAMETERS_
{
    DWORD                   MaximumLength;                 //0x00
    DWORD                   Length;                        //0x04
    DWORD                   Flags;                         //0x08
    DWORD                   DebugFlags;                    //0x0C
    voidp                   ConsoleHandle;                 //0x10
    DWORD                   ConsoleFlags;                  //0x14
    _HANDLE                  StdInputHandle;                //0x18
    _HANDLE                  StdOutputHandle;               //0x1C
    _HANDLE                  StdErrorHandle;                //0x20
    UNICODE_STRING_          CurrentDirectoryPath;          //0x24
    _HANDLE                  CurrentDirectoryHandle;        //0x2C
    UNICODE_STRING_          DllPath;                       //0x30
    UNICODE_STRING_          ImagePathName;                 //0x38
    UNICODE_STRING_          CommandLine;                   //0x40
    voidp                   Environment;                   //0x48
    DWORD                   StartingPositionLeft;          //0x4C
    DWORD                   StartingPositionTop;           //0x50
    DWORD                   Width;                         //0x54
    DWORD                   Height;                        //0x58
    DWORD                   CharWidth;                     //0x5C
    DWORD                   CharHeight;                    //0x60
    DWORD                   ConsoleTextAttributes;         //0x64
    DWORD                   WindowFlags;                   //0x68
    DWORD                   ShowWindowFlags;               //0x6C
    UNICODE_STRING_          WindowTitle;                   //0x70
    UNICODE_STRING_          DesktopName;                   //0x78
    UNICODE_STRING_          ShellInfo;                     //0x80
    UNICODE_STRING_          RuntimeData;                   //0x88
    RTL_DRIVE_LETTER_CURDIR_ DLCurrentDirectory[0x20];      //0x90
};

typedef voidp PEB_LDR_DATA_p;
typedef voidp RTL_USER_PROCESS_PARAMETERS_p;

typedef voidp ACTIVATION_CONTEXT_DATA_p;
typedef voidp ASSEMBLY_STORAGE_MAP_p;
typedef voidp ACTIVATION_CONTEXT_DATA_p;
typedef voidp ASSEMBLY_STORAGE_MAP_p;

typedef voidp FLS_CALLBACK_INFO_p;


//
// PEB_ (Process Environment Block) 32-bit
//
// The size of this structure is OS dependent:
//    0x0098    NT 3.51
//    0x0150    NT 4.0
//    0x01E8    Win2k
//    0x020C    XP
//    0x0230    WS03
//    0x0238    Vista
//    0x0240    Win7_BETA
//    0x0248    Win6
//    0x0250    Win8
//    0x0258    Win10
//
struct PEB_
{
    BOOLEAN                         InheritedAddressSpace;              //0x0000
    BOOLEAN                         ReadImageFileExecOptions;           //0x0001
    BOOLEAN                         BeingDebugged;                      //0x0002
    union
    {
        BOOLEAN                     SpareBool;                          //0x0003 (NT3.51-late WS03)
        struct
        {
            BYTE                    ImageUsesLargePages          : 1;   //0x0003:0 (WS03_SP1+)
            BYTE                    IsProtectedProcess           : 1;   //0x0003:1 (Vista+)
            BYTE                    IsLegacyProcess              : 1;   //0x0003:2 (Vista+)
            BYTE                    IsImageDynamicallyRelocated  : 1;   //0x0003:3 (Vista+)
            BYTE                    SkipPatchingUser32Forwarders : 1;   //0x0003:4 (Vista_SP1+)
            BYTE                    IsPackagedProcess            : 1;   //0x0003:5 (Win8_BETA+)
            BYTE                    IsAppContainer               : 1;   //0x0003:6 (Win8_RTM+)
            BYTE                    SpareBits                    : 1;   //0x0003:7
        } bits;
    } byte3;
    _HANDLE                          Mutant;                             //0x0004
    voidp                           ImageBaseAddress;                   //0x0008
    PEB_LDR_DATA_p                   Ldr;                                //0x000C  (all loaded modules in process)
    RTL_USER_PROCESS_PARAMETERS_p    ProcessParameters;                  //0x0010
    voidp                           SubSystemData;                      //0x0014
    voidp                           ProcessHeap;                        //0x0018
    RTL_CRITICAL_SECTION_p           FastPebLock;                        //0x001C
    union
    {
        voidp                       FastPebLockRoutine;                 //0x0020 (NT3.51-Win2k)
        voidp                       SparePtr1;                          //0x0020 (early WS03)
        voidp                       AtlThunkSListPtr;                   //0x0020 (late WS03+)
    } dword20;
    union
    {
        voidp                       FastPebUnlockRoutine;               //0x0024 (NT3.51-XP)
        voidp                       SparePtr2;                          //0x0024 (WS03)
        voidp                       IFEOKey;                            //0x0024 (Vista+)
    } dword24;
    union
    {
        DWORD                       EnvironmentUpdateCount;             //0x0028 (NT3.51-WS03)
        struct
        {
            DWORD                   ProcessInJob            : 1;        //0x0028:0 (Vista+)
            DWORD                   ProcessInitializing     : 1;        //0x0028:1 (Vista+)
            DWORD                   ProcessUsingVEH         : 1;        //0x0028:2 (Vista_SP1+)
            DWORD                   ProcessUsingVCH         : 1;        //0x0028:3 (Vista_SP1+)
            DWORD                   ProcessUsingFTH         : 1;        //0x0028:4 (Win7_BETA+)
            DWORD                   ReservedBits0           : 27;       //0x0028:5 (Win7_BETA+)
        } vista_CrossProcessFlags;
    } struct28;
    union
    {
        voidp                       KernelCallbackTable;                //0x002C (Vista+)
        voidp                       UserSharedInfoPtr;                  //0x002C (Vista+)
    } dword2C;
    DWORD                           SystemReserved;                     //0x0030 (NT3.51-XP)
    //Microsoft seems to keep changing their mind with DWORD 0x34
    union
    {
        DWORD                       SystemReserved2;                    //0x0034 (NT3.51-Win2k)
        struct
        {
            DWORD                   ExecuteOptions          : 2;        //0x0034:0 (XP-early WS03)
            DWORD                   SpareBits               : 30;       //0x0034:2 (XP-early WS03)
        } xpBits;
        DWORD                       AtlThunkSListPtr32;                 //0x0034 (late XP,Win7+)
        DWORD                       SpareUlong;                         //0x0034 (late WS03-Vista)
        struct
        {
            DWORD                   HeapTracingEnabled      : 1;        //0x0034:0 (Win7_BETA)
            DWORD                   CritSecTracingEnabled   : 1;        //0x0034:1 (Win7_BETA)
            DWORD                   SpareTracingBits        : 30;       //0x0034:2 (Win7_BETA)
        } win7_TracingFlags;
    } dword34;
    union
    {
        PEB_FREE_BLOCK_p             FreeList;                           //0x0038 (NT3.51-early Vista)
        DWORD                       SparePebPtr0;                       //0x0038 (last Vista)
        voidp                       ApiSetMap;                          //0x0038 (Win7+)
    } dword38;
    DWORD                           TlsExpansionCounter;                //0x003C
    voidp                           TlsBitmap;                          //0x0040
    DWORD                           TlsBitmapBits[2];                   //0x0044
    voidp                           ReadOnlySharedMemoryBase;           //0x004C
    union
    {
        voidp                       ReadOnlyShareMemoryHeap;            //0x0050 (NT3.51-WS03)
        voidp                       HotpatchInformation;                //0x0050 (Vista+)
    } dword50;
    voidp                          ReadOnlyStaticServerData;           //0x0054 really void**
    voidp                           AnsiCodePageData;                   //0x0058
    voidp                           OemCodePageData;                    //0x005C
    voidp                           UnicodeCaseTableData;               //0x0060
    DWORD                           NumberOfProcessors;                 //0x0064
    DWORD                           NtGlobalFlag;                       //0x0068
    LARGE_INTEGER_                   CriticalSectionTimeout;             //0x0070
    DWORD                           HeapSegmentReserve;                 //0x0078
    DWORD                           HeapSegmentCommit;                  //0x007C
    DWORD                           HeapDeCommitTotalFreeThreshold;     //0x0080
    DWORD                           HeapDeCommitFreeBlockThreshold;     //0x0084
    DWORD                           NumberOfHeaps;                      //0x0088
    DWORD                           MaximumNumberOfHeaps;               //0x008C
    voidp                           ProcessHeaps;                       //0x0090 really void**
    voidp                           GdiSharedHandleTable;               //0x0094

    //end of NT 3.51 members / members that follow available on NT 4.0 and up

    voidp                           ProcessStarterHelper;               //0x0098
    DWORD                           GdiDCAttributeList;                 //0x009C
    union
    {
        struct
        {
            voidp                   LoaderLock;                         //0x00A0 (NT4)
        } nt4;
        struct
        {
            RTL_CRITICAL_SECTION_p   LoaderLock;                         //0x00A0 (Win2k+)
        } win2k;
    } dwordA0;
    DWORD                           OSMajorVersion;                     //0x00A4
    DWORD                           OSMinorVersion;                     //0x00A8
    WORD                            OSBuildNumber;                      //0x00AC
    WORD                            OSCSDVersion;                       //0x00AE
    DWORD                           OSPlatformId;                       //0x00B0
    DWORD                           ImageSubsystem;                     //0x00B4
    DWORD                           ImageSubsystemMajorVersion;         //0x00B8
    DWORD                           ImageSubsystemMinorVersion;         //0x00BC
    union
    {
        KAFFINITY                   ImageProcessAffinityMask;           //0x00C0 (NT4-early Vista)
        KAFFINITY                   ActiveProcessAffinityMask;          //0x00C0 (late Vista+)
    } dwordC0;
    DWORD                           GdiHandleBuffer[0x22];              //0x00C4
    voidp                           PostProcessInitRoutine;             //0x014C / void (*PostProcessInitRoutine) (void);

    //members that follow available on Windows 2000 and up

    voidp                           TlsExpansionBitmap;                 //0x0150
    DWORD                           TlsExpansionBitmapBits[0x20];       //0x0154
    DWORD                           SessionId;                          //0x01D4
    ULARGE_INTEGER_                  AppCompatFlags;                     //0x01D8
    ULARGE_INTEGER_                  AppCompatFlagsUser;                 //0x01E0
    voidp                           pShimData;                          //0x01E8
    voidp                           AppCompatInfo;                      //0x01EC
    UNICODE_STRING_                  CSDVersion;                         //0x01F0

    //members that follow available on Windows XP and up

    ACTIVATION_CONTEXT_DATA_p        ActivationContextData;              //0x01F8
    ASSEMBLY_STORAGE_MAP_p           ProcessAssemblyStorageMap;          //0x01FC
    ACTIVATION_CONTEXT_DATA_p        SystemDefaultActivationContextData; //0x0200
    ASSEMBLY_STORAGE_MAP_p           SystemAssemblyStorageMap;           //0x0204
    DWORD                           MinimumStackCommit;                 //0x0208

    //members that follow available on Windows Server 2003 and up

    FLS_CALLBACK_INFO_p              FlsCallback;                        //0x020C
    LIST_ENTRY_                      FlsListHead;                        //0x0210
    voidp                           FlsBitmap;                          //0x0218
    DWORD                           FlsBitmapBits[4];                   //0x021C
    DWORD                           FlsHighIndex;                       //0x022C

    //members that follow available on Windows Vista and up

    voidp                           WerRegistrationData;                //0x0230
    voidp                           WerShipAssertPtr;                   //0x0234

    //members that follow available on Windows 7 BETA and up

    union
    {
        voidp                       pContextData;                       //0x0238 (prior to Windows 8)
        voidp                       pUnused;                            //0x0238 (Windows 8)
    } dword238;
    voidp                           pImageHeaderHash;                   //0x023C

    //members that follow available on Windows 7 RTM and up

    struct //TracingFlags
    {
        DWORD                       HeapTracingEnabled       :1;        //0x0240:0
        DWORD                       CritSecTracingEnabled    :1;        //0x0240:1
        DWORD                       LibLoaderTracingEnabled  :1;        //0x0240:2
        DWORD                       SpareTracingBits         :29;       //0x0240:3
    } dword240;
    DWORD                           dummy02;                            //0x0244

    //members that follow available on Windows 8 and up

    QWORD                           CsrServerReadOnlySharedMemoryBase;  //0x0248

    //members that follow available by at least Windows 10 (possibly Windows 8)

    DWORD                           dwUnknown0250;                      //0x0250 (must exist at least by Windows 10)
    DWORD                           dwSystemCallMode;                   //0x0254 / set to 2 under 64-bit Windows in a 32-bit process (WOW64)
                                                                        //         used in 64-bit mode switch prior to ring 0 kernel-mode transitions
};


//
// TEB_-specific structures
//

//GDI_TEB_BATCH_ - size=0x04E0
struct GDI_TEB_BATCH_
{
    union
    {
        DWORD   Offset;
        struct
        {
            DWORD Offset                : 31;  //0x00:00  Win 8.1 Update 1+
            DWORD HasRenderingCommand   : 1;   //0x00:31  Win 8.1 Update 1+
        } bits;
    } dword0;
    DWORD   HDC;
    DWORD   Buffer[0x136];
};

struct TEB_ACTIVE_FRAME_CONTEXT_
{
     DWORD  Flags;
     CHARp  FrameName;
};

typedef voidp TEB_ACTIVE_FRAME_p;
typedef voidp TEB_ACTIVE_FRAME_CONTEXT_p;

struct TEB_ACTIVE_FRAME_
{
     DWORD                      Flags;
     TEB_ACTIVE_FRAME_p          Previous;
     TEB_ACTIVE_FRAME_CONTEXT_p  CONTEXT_;
};

typedef voidp PEB_p;
typedef voidp TEB_p;
typedef voidp TEB_ACTIVE_FRAME_p;

//
// TEB_ (Thread Environment Block) a.k.a. TIB (Thread Information Block) 32-bit
//
// The size of this structure is OS dependent:
//    0x0F28    NT 3.51
//    0x0F88    NT 4.0
//    0x0FA4    Win2k
//    0x0FB4    prior to XP SP2
//    0x0FB8    XP SP2/WS03+
//    0x0FBC    WS03 SP1+
//    0x0FF8    Vista/WS08
//    0x0FE4    Win7/WS08 R2
//    0x0FE8    Win8-Win8.1/WS12
//    0x1000    Win10
//
struct TEB_
{
    //NT_TIB structure portion
    EXCEPTION_REGISTRATION_p     ExceptionList;                              //0x0000 / Current Structured Exception Handling (SEH) frame
    voidp                       StackBase;                                  //0x0004 / Bottom of stack (high address)
    voidp                       StackLimit;                                 //0x0008 / Ceiling of stack (low address)
    voidp                       SubSystemTib;                               //0x000C
    union
    {
        voidp                   FiberData;                                  //0x0010
        DWORD                   Version;                                    //0x0010
    } dword10;
    voidp                       ArbitraryUserPointer;                       //0x0014
    TEB_p                        Self;                                       //0x0018
    //NT_TIB ends (NT subsystem independent part)

    voidp                       EnvironmentPointer;                         //0x001C
    CLIENT_ID_                   ClientId;                                   //0x0020
    //                          ClientId.ProcessId                          //0x0020 / value retrieved by GetCurrentProcessId()
    //                          ClientId.ThreadId                           //0x0024 / value retrieved by GetCurrentThreadId()
    voidp                       ActiveRpcHandle;                            //0x0028
    voidp                       ThreadLocalStoragePointer;                  //0x002C
    PEB_p                       ProcessEnvironmentBlock;                    //0x0030
    DWORD                       LastErrorValue;                             //0x0034
    DWORD                       CountOfOwnedCriticalSections;               //0x0038
    voidp                       CsrClientThread;                            //0x003C
    voidp                       Win32ThreadInfo;                            //0x0040
    DWORD                       User32Reserved[0x1A];                       //0x0044
    DWORD                       UserReserved[5];                            //0x00AC
    voidp                       WOW32Reserved;                              //0x00C0 / user-mode 32-bit (WOW64) -> 64-bit CONTEXT_ switch function prior to kernel-mode transition
    LCID                        CurrentLocale;                              //0x00C4
    DWORD                       FpSoftwareStatusRegister;                   //0x00C8
    union
    {
        DWORD                   SystemReserved1[0x36];                      //0x00CC (NT 3.51-Win8)
        struct
        {
            DWORD               Reserved1[0x16];                            //0x00CC
            voidp               pKThread;                                   //0x0124 / pointer to KTHREAD (ETHREAD) structure
            DWORD               Reserved2[0x1F];                            //0x0128
        } kernelInfo;
        struct
        {
            DWORD               ReservedForDebuggerInstrumentation[0x10];   //0x00CC (Win10 PRE-RTM+)
            DWORD               SystemReserved1[0x26];                      //0x010C (Win10 PRE-RTM+)
        } win10;
    } dwordCC;
    int32_t /*NTSTATUS*/        ExceptionCode;                              //0x01A4
    union
    {
        BYTE                    SpareBytes1[0x2C];                          //0x01A8 (NT3.51-Win2k)
        struct
        {
            BYTE                ActivationContextStack[0x14];               //0x01A8 (XP-early WS03)
            BYTE                SpareBytes1[0x18];                          //0x01BC (XP-early WS03)
        } xp;
        struct
        {
            voidp               ActivationContextStackPointer;              //0x01A8 (WS03+)
            union
            {
                BYTE            SpareBytes1[0x24];                          //0x01AC (WS03-Win8.1)
                struct
                {
                    voidp       InstrumentationCallbackSp;                  //0x01AC (Win10+)
                    voidp       InstrumentationCallbackPreviousPc;          //0x01B0 (Win10+)
                    voidp       InstrumentationCallbackPreviousSp;          //0x01B4 (Win10+)
                    BOOLEAN     InstrumentationCallbackDisabled;            //0x01B8 (Win10+)
                    BYTE        SpareBytes[0x17];                           //0x01B9 (Win10+)
                } win10;
            } dword1AC;
            union
            {
                BYTE            SpareBytes2[4];                             //0x01D0 (WS03)
                DWORD           TxFsContext;                                //0x01D0 (Vista+)
            } dword1D0;
        } lateWs03;
    } dword1A8;
    GDI_TEB_BATCH_               GdiTebBatch;                                //0x01D4
    CLIENT_ID_                   RealClientId;                               //0x06B4
    _HANDLE                      GdiCachedProcessHandle;                     //0x06BC
    DWORD                       GdiClientPID;                               //0x06C0
    DWORD                       GdiClientTID;                               //0x06C4
    voidp                       GdiThreadLocalInfo;                         //0x06C8
    DWORD                       Win32ClientInfo[0x3E];                      //0x06CC
    voidp                       glDispatchTable[0xE9];                      //0x07C4
    DWORD                       glReserved1[0x1D];                          //0x0B68
    voidp                       glReserved2;                                //0x0BDC
    voidp                       glSectionInfo;                              //0x0BE0
    voidp                       glSection;                                  //0x0BE4
    voidp                       glTable;                                    //0x0BE8
    voidp                       glCurrentRC;                                //0x0BEC
    voidp                       glContext;                                  //0x0BF0
    int32_t /*NTSTATUS*/        LastStatusValue;                            //0x0BF4
    UNICODE_STRING_              StaticUnicodeString;                        //0x0BF8
    WCHAR                       StaticUnicodeBuffer[0x105];                 //0x0C00
    voidp                       DeallocationStack;                          //0x0E0C
    voidp                       TlsSlots[0x40];                             //0x0E10
    LIST_ENTRY_                  TlsLinks;                                   //0x0F10
    voidp                       Vdm;                                        //0x0F18
    voidp                       ReservedForNtRpc;                           //0x0F1C
    voidp                       DbgSsReserved[2];                           //0x0F20

    //end of NT 3.51 members / members that follow available on NT 4.0 and up

    union
    {
        DWORD                   ThreadErrorMode;                            //0x0F28 (OS?) / RtlSetThreadErrorMode
        DWORD                   HardErrorsAreDisabled;                      //0x0F28 (NT4-XP)
        DWORD                   HardErrorMode;                              //0x0F28 (WS03+)
    } dwordF28;
    union
    {
        struct
        {
            DWORD               Instrumentation[0x10];                      //0x0F2C (NT4-early WS03)
        } nt;
        struct
        {
            union
            {
                struct
                {
                    DWORD       Instrumentation[0x0E];                      //0x0F2C (late WS03+)
                    voidp       SubProcessTag;                              //0x0F64 (late WS03+)
                } beforeVista;
                struct
                {
                    DWORD       Instrumentation[9];                         //0x0F2C (Vista+)
                    GUID_        ActivityId;                                 //0x0F50 (Vista+)
                    voidp       SubProcessTag;                              //0x0F60 (Vista+)
                    union
                    {
                        DWORD   EtwLocalData;                               //0x0F64 (WIN8 PRE-RTM)
                        DWORD   PerflibData;                                //0x0F64 (WIN8 RTM+)
                    } win8;

                } vista;
            } dwordF2C;
            voidp               EtwTraceData;                               //0x0F68 (late WS03+)
        } ws03;
    } dwordF2C;
    voidp                       WinSockData;                                //0x0F6C
    DWORD                       GdiBatchCount;                              //0x0F70
    union
    {
        struct
        {
            union
            {
                struct
                {
                    BOOLEAN     InDbgPrint;                                 //0x0F74 (NT4-WS03)
                    BOOLEAN     FreeStackOnTermination;                     //0x0F75 (NT4-WS03)
                    BOOLEAN     HasFiberData;                               //0x0F76 (NT4-WS03)
                } beforeVista;
                union
                {
                    BOOLEAN     SpareBool0;                                 //0x0F74 (Vista)
                    BOOLEAN     SpareBool1;                                 //0x0F75 (Vista)
                    BOOLEAN     SpareBool2;                                 //0x0F76 (Vista)
                } vista;
            } u;
            BOOLEAN             IdealProcessor;                             //0x0F77 (NT4-Vista)
        } beforeWin7;
        PROCESSOR_NUMBER_        CurrentIdealProcessor;                      //0x0F74 (Win7+)
    } dwordF74;
    union
    {
        DWORD                   Spare3;                                     //0x0F78 (NT4-early WS03)
        DWORD                   GuaranteedStackBytes;                       //0x0F78 (late WS03+)
    } dwordF78;
    voidp                       ReservedForPerf;                            //0x0F7C
    voidp                       ReservedForOle;                             //0x0F80
    DWORD                       WaitingOnLoaderLock;                        //0x0F84

    //members that follow available on Windows 2000 and up

    union
    {
        struct
        {
            //Wx86ThreadState structure
            DWORDp              CallBx86Eip;                                //0x0F88 (Win2k-early WS03)
            voidp               DeallocationCpu;                            //0x0F8C (Win2k-early WS03)
            BYTE                UseKnownWx86Dll;                            //0x0F90 (Win2k-early WS03)
            CHAR                OleStubInvoked;                             //0x0F91 (Win2k-early WS03)
            BYTE                Padding[2];                                 //0x0F92
        } beforeLateWs03;
        struct
        {
            union
            {
                voidp           SparePointer1;                              //0x0F88 (late WS03)
                voidp           SavedPriorityState;                         //0x0F88 (Vista+)
            } dwordF88;
            union
            {
                voidp           SoftPatchPtr1;                              //0x0F8C (late WS03-Win7)
                voidp           ReservedForCodeCoverage;                    //0x0F8C (Win8+)
            } dwordF8C;
            union
            {
                voidp           SoftPatchPtr2;                              //0x0F90 (late WS03)
                voidp           ThreadPoolData;                             //0x0F90 (Vista+)
            } dwordF90;
        } lateWs03;
    } dwordF88;
    voidp                       TlsExpansionSlots;                          //0x0F94
    union
    {
        LCID                    ImpersonationLocale;                        //0x0F98 (Win2k-Vista)
        DWORD                   MuiGeneration;                              //0x0F98 (Win7+)
    } dwordF98;
    DWORD                       IsImpersonating;                            //0x0F9C
    voidp                       NlsCache;                                   //0x0FA0

    //members that follow available on Windows XP and up

    voidp                       pShimData;                                  //0x0FA4
    union
    {
        DWORD                   HeapVirtualAffinity;                        //0x0FA8 (XP-Win7)
        struct
        {
            WORD                HeapVirtualAffinity;                        //0x0FA8 (Win8+)
            WORD                LowFragHeapDataSlot;                        //0x0FAA (Win8+)
        } win8;
    } dwordFA8;
    _HANDLE                      CurrentTransactionHandle;                   //0x0FAC
    TEB_ACTIVE_FRAME_p           ActiveFrame;                                //0x0FB0

    //members that follow available on Windows XP SP2 and up

    union
    {
        voidp                   FlsData;                                    //0x0FB4 (WS03+)
        struct
        {
            BOOLEAN             SafeThunkCall;                              //0x0FB4 (XP SP2)
            BOOLEAN             BooleanSpare[3];                            //0x0FB5 (XP SP2)
        } xpSp2;
    } dwordFB4;
    union
    {
        struct
        {
            BOOLEAN             SafeThunkCall;                              //0x0FB8 (late WS03)
            BOOLEAN             BooleanSpare[3];                            //0x0FB9 (late WS03)
        } ws03;
        voidp                   PreferredLanguages;                         //0x0FB8 (Vista+)
    } dwordFB8;

    //members that follow available on Windows Vista and up

    voidp                       UserPrefLanguages;                          //0x0FBC
    voidp                       MergedPrefLanguages;                        //0x0FC0
    DWORD                       MuiImpersonation;                           //0x0FC4
    union
    {
        volatile WORD           CrossTebFlags;                              //0x0FC8
        struct
        {
            WORD                SpareCrossTebBits : 16;                     //0x0FC8
        } bits;
    } wordFC8;
    union
    {
        WORD                    SameTebFlags;                               //0x0FCA
        struct
        {
            WORD                SafeThunkCall        : 1;                   //0x0FCA:0x00
            WORD                InDebugPrint         : 1;                   //0x0FCA:0x01
            WORD                HasFiberData         : 1;                   //0x0FCA:0x02
            WORD                SkipThreadAttach     : 1;                   //0x0FCA:0x03
            WORD                WerInShipAssertCode  : 1;                   //0x0FCA:0x04
            WORD                RanProcessInit       : 1;                   //0x0FCA:0x05
            WORD                ClonedThread         : 1;                   //0x0FCA:0x06
            WORD                SuppressDebugMsg     : 1;                   //0x0FCA:0x07
            WORD                DisableUserStackWalk : 1;                   //0x0FCA:0x08
            WORD                RtlExceptionAttached : 1;                   //0x0FCA:0x09
            WORD                InitialThread        : 1;                   //0x0FCA:0x0A
            WORD                SessionAware         : 1;                   //0x0FCA:0x0B
        } bits;
    } wordFCA;
    voidp                       TxnScopeEnterCallback;                      //0x0FCC
    voidp                       TxnScopeExitCallback;                       //0x0FD0
    voidp                       TxnScopeContext;                            //0x0FD4
    DWORD                       LockCount;                                  //0x0FD8
    union
    {
        DWORD           ProcessRundown;                             //0x0FDC (Vista)
        DWORD           SpareUlong0;                                //0x0FDC (Win7-Win8)
        INT32           WowTebOffset;                               //0x0FDC (Win10+)
    } dwordFDC;

    union
    {
        struct
        {
            QWORD               LastSwitchTime;                             //0x0FE0 (Vista)
            QWORD               TotalSwitchOutTime;                         //0x0FE8 (Vista)
            LARGE_INTEGER_       WaitReasonBitMap;                           //0x0FF0 (Vista)

            //end of Vista members

        } vista;

        struct
        {
            voidp               ResourceRetValue;                           //0x0FE0 (Win7+)

            //end of Windows 7 members (TEB_ shrunk after Vista)

            voidp               ReservedForWdf;                             //0x0FE4 (Win8+)

            //end of Windows 8 members

            //members that follow available on Windows 10 and up
            QWORD               ReservedForCrt;                             //0x0FE8

            GUID_               EffectiveContainerId;                       //0x0FF0

            //end of Windows 10/11
        } afterVista;
    } dwordFE0;
}; //struct TEB_
