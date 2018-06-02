#ifndef __PE_LOCAL
#define __PE_LOCAL

#include <stdint.h>

#define DOS_MAGIC 0x5a4d       //'MZ'
#define PE_MAGIC 0x4550       //'PE'

struct IMAGE_DOS_HEADER_ {      // DOS .EXE header
   uint16_t   e_magic;            // Magic number
   uint16_t   e_cblp;             // Bytes on last page of file
   uint16_t   e_cp;               // Pages in file
   uint16_t   e_crlc;             // Relocations
   uint16_t   e_cparhdr;          // Size of header in paragraphs
   uint16_t   e_minalloc;         // Minimum extra paragraphs needed
   uint16_t   e_maxalloc;         // Maximum extra paragraphs needed
   uint16_t   e_ss;               // Initial (relative) SS value
   uint16_t   e_sp;               // Initial SP value
   uint16_t   e_csum;             // Checksum
   uint16_t   e_ip;               // Initial IP value
   uint16_t   e_cs;               // Initial (relative) CS value
   uint16_t   e_lfarlc;           // File address of relocation table
   uint16_t   e_ovno;             // Overlay number
   uint16_t   e_res[4];           // Reserved uint16_ts
   uint16_t   e_oemid;            // OEM identifier (for e_oeminfo)
   uint16_t   e_oeminfo;          // OEM information; e_oemid specific
   uint16_t   e_res2[10];         // Reserved uint16_ts
   uint32_t   e_lfanew;           // 0x3C File address of new exe header
};

struct IMAGE_FILE_HEADER_ {
   uint16_t    Machine;                   //0
   uint16_t    NumberOfSections;          //2 
   uint32_t    TimeDateStamp;             //4
   uint32_t    PointerToSymbolTable;      //8
   uint32_t    NumberOfSymbols;           //12
   uint16_t    SizeOfOptionalHeader;      //16
   uint16_t    Characteristics;           //18
};                            //size 20

struct IMAGE_DATA_DIRECTORY_ {
   uint32_t   VirtualAddress;
   uint32_t   Size;
};

struct IMAGE_OPTIONAL_HEADER32_ {
   //
   // Standard fields.
   //
   uint16_t   Magic;                   //0
   uint8_t    MajorLinkerVersion;      //2
   uint8_t    MinorLinkerVersion;      //3
   uint32_t   SizeOfCode;              //4
   uint32_t   SizeOfInitializedData;   //8
   uint32_t   SizeOfUninitializedData; //12
   uint32_t   AddressOfEntryPoint;     //16
   uint32_t   BaseOfCode;              //20
   uint32_t   BaseOfData;              //24 

   //
   // NT additional fields.
   //

   uint32_t   ImageBase;                   //28
   uint32_t   SectionAlignment;            //32
   uint32_t   FileAlignment;               //36
   uint16_t   MajorOperatingSystemVersion; //40
   uint16_t   MinorOperatingSystemVersion; //42
   uint16_t   MajorImageVersion;           //44
   uint16_t   MinorImageVersion;           //46
   uint16_t   MajorSubsystemVersion;       //48
   uint16_t   MinorSubsystemVersion;       //50
   uint32_t   Win32VersionValue;           //52
   uint32_t   SizeOfImage;                 //56
   uint32_t   SizeOfHeaders;               //60
   uint32_t   CheckSum;                    //64
   uint16_t   Subsystem;                   //68
   uint16_t   DllCharacteristics;          //70
   uint32_t   SizeOfStackReserve;          //72
   uint32_t   SizeOfStackCommit;           //76
   uint32_t   SizeOfHeapReserve;           //80
   uint32_t   SizeOfHeapCommit;            //84
   uint32_t   LoaderFlags;                 //88
   uint32_t   NumberOfRvaAndSizes;         //92
   IMAGE_DATA_DIRECTORY_ DataDirectory[16];    //96
};                     //size 224

struct IMAGE_OPTIONAL_HEADER64_ {
   //
   // Standard fields.
   //
   uint16_t   Magic;                   //0
   uint8_t    MajorLinkerVersion;      //2
   uint8_t    MinorLinkerVersion;      //3
   uint32_t   SizeOfCode;              //4
   uint32_t   SizeOfInitializedData;   //8
   uint32_t   SizeOfUninitializedData; //12
   uint32_t   AddressOfEntryPoint;     //16
   uint32_t   BaseOfCode;              //20
   //
   // NT additional fields.
   //
   uint64_t   ImageBase;                   //24
   uint32_t   SectionAlignment;            //32
   uint32_t   FileAlignment;               //36
   uint16_t   MajorOperatingSystemVersion; //40
   uint16_t   MinorOperatingSystemVersion; //42
   uint16_t   MajorImageVersion;           //44
   uint16_t   MinorImageVersion;           //46
   uint16_t   MajorSubsystemVersion;       //48
   uint16_t   MinorSubsystemVersion;       //50
   uint32_t   Win32VersionValue;           //52
   uint32_t   SizeOfImage;                 //56
   uint32_t   SizeOfHeaders;               //60
   uint32_t   CheckSum;                    //64
   uint16_t   Subsystem;                   //68
   uint16_t   DllCharacteristics;          //70
   uint64_t   SizeOfStackReserve;          //72
   uint64_t   SizeOfStackCommit;           //80
   uint64_t   SizeOfHeapReserve;           //88
   uint64_t   SizeOfHeapCommit;            //96
   uint32_t   LoaderFlags;                 //104
   uint32_t   NumberOfRvaAndSizes;         //108
   IMAGE_DATA_DIRECTORY_ DataDirectory[16];    //112
};                     //size 240

struct IMAGE_NT_HEADERS32_ {
   uint32_t Signature;
   IMAGE_FILE_HEADER_ FileHeader;
   IMAGE_OPTIONAL_HEADER32_ OptionalHeader;
};

struct IMAGE_NT_HEADERS64_ {
   uint32_t Signature;
   IMAGE_FILE_HEADER_ FileHeader;
   IMAGE_OPTIONAL_HEADER64_ OptionalHeader;
};

struct IMAGE_SECTION_HEADER_ {
   uint8_t    Name[8];              //0
   uint32_t   VirtualSize;            //8
   uint32_t   VirtualAddress;         //12
   uint32_t   SizeOfRawData;          //16
   uint32_t   PointerToRawData;       //20
   uint32_t   PointerToRelocations;   //24
   uint32_t   PointerToLinenumbers;   //28
   uint16_t   NumberOfRelocations;    //32
   uint16_t   NumberOfLinenumbers;    //34
   uint32_t   Characteristics;        //36
};                   //size 40

#endif

