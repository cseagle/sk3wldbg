/*
   Source for Sk3wlDbg IdaPro plugin
   Copyright (c) 2016 Chris Eagle

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include "loader.h"
#include <ida.hpp>
#include <llong.hpp>
#include <nalt.hpp>
#include <segment.hpp>

#include "elf_local.h"
#include "pe_local.h"
#include "teb32.h"
#include "heap.h"

#pragma pack(push, 1)
struct SegmentDescriptor {
   union {
      struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
         unsigned short limit0;
         unsigned short base0;
         unsigned char base1;
         unsigned char type:4;
         unsigned char system:1;      /* S flag */
         unsigned char dpl:2;
         unsigned char present:1;     /* P flag */
         unsigned char limit1:4;
         unsigned char avail:1;
         unsigned char is_64_code:1;  /* L flag */
         unsigned char db:1;          /* DB flag */
         unsigned char granularity:1; /* G flag */
         unsigned char base2;
#else
         unsigned char base2;
         unsigned char granularity:1; /* G flag */
         unsigned char db:1;          /* DB flag */
         unsigned char is_64_code:1;  /* L flag */
         unsigned char avail:1;
         unsigned char limit1:4;
         unsigned char present:1;     /* P flag */
         unsigned char dpl:2;
         unsigned char system:1;      /* S flag */
         unsigned char type:4;
         unsigned char base1;
         unsigned short base0;
         unsigned short limit0;
#endif
      };
      uint64_t desc;
   };
};

struct InterruptDescriptor32 {
   union {
      struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
         unsigned short offset0;
         unsigned short sel;
         unsigned char zero;
         unsigned char d:5;
         unsigned char dpl:2;
         unsigned char present:1;     /* P flag */
         unsigned short offset1;
#else
         unsigned short offset1;
         unsigned char present:1;     /* P flag */
         unsigned char dpl:2;
         unsigned char d:5;
         unsigned char zero;
         unsigned short sel;
         unsigned short offset0;
#endif
      };
      uint64_t desc;
   };
};

struct InterruptDescriptor64 {
   union {
      struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
         unsigned short offset0;
         unsigned short sel;
         unsigned char ist:3;
         unsigned char pad0:5;
         unsigned char type:4;
         unsigned char pad1:1;
         unsigned char dpl:2;
         unsigned char present:1;     /* P flag */
         unsigned short offset1;
         uint32_t offset2;
         uint32_t pad2;
#else
         uint32_t pad1;
         uint32_t offset2;
         unsigned short offset1;
         unsigned char present:1;     /* P flag */
         unsigned char dpl:2;
         unsigned char pad1:1;
         unsigned char type:4;
         unsigned char pad0:5;
         unsigned char ist:3;
         unsigned short sel;
         unsigned short offset0;
#endif
      };
      struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
         uint64_t desc0;
         uint64_t desc1;
#else
         uint64_t desc1;
         uint64_t desc0;
#endif
      };
   };
};
#pragma pack(pop)

#define SEGBASE(d) ((uint32_t)((((d).desc >> 16) & 0xffffff) | (((d).desc >> 32) & 0xff000000)))
#define SEGLIMIT(d) ((d).limit0 | (((unsigned int)(d).limit1) << 16))

#define ISROFFS(d) ((uint32_t)((((d).desc >> 32) & 0xfffff0000) | ((d).offset0)))
#define ISROFFS64(d) ((uint64_t)((((d).desc1 & 0xffffffff) << 32) | (((d).desc0 >> 32) & 0xfffff0000) | ((d).offset0)))
#define ISRSEG(d) ((d).sel)

/*    Unicorn perms                    IDA perms
0     UC_PROT_NONE                     0
1     UC_PROT_READ                     SEGPERM_EXEC
2     UC_PROT_WRITE                    SEGPERM_WRITE
3     UC_PROT_WRITE | UC_PROT_READ     SEGPERM_WRITE | SEGPERM_EXEC
4     UC_PROT_EXEC                     SEGPERM_READ
5     UC_PROT_EXEC | UC_PROT_READ      SEGPERM_READ | SEGPERM_EXEC
6     UC_PROT_EXEC | UC_PROT_WRITE     SEGPERM_READ | SEGPERM_WRITE
7     UC_PROT_ALL                      SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC
*/

uint32_t ida_to_uc_perms_map[] = {
   UC_PROT_NONE, UC_PROT_EXEC, UC_PROT_WRITE, UC_PROT_EXEC | UC_PROT_WRITE,
   UC_PROT_READ, UC_PROT_EXEC | UC_PROT_READ, UC_PROT_READ | UC_PROT_WRITE, UC_PROT_ALL
};

uint32_t ida_to_uc_perms_map_win[] = {
   UC_PROT_NONE, UC_PROT_EXEC, UC_PROT_READ, UC_PROT_EXEC | UC_PROT_READ,
   UC_PROT_WRITE, UC_PROT_EXEC | UC_PROT_WRITE, UC_PROT_READ | UC_PROT_WRITE, UC_PROT_ALL
};

uint32_t uc_to_ida_perms_map[] = {
   0, SEGPERM_READ, SEGPERM_WRITE, SEGPERM_READ | SEGPERM_WRITE,
   SEGPERM_EXEC, SEGPERM_EXEC | SEGPERM_READ, SEGPERM_EXEC | SEGPERM_WRITE, SEGPERM_EXEC | SEGPERM_WRITE | SEGPERM_READ
};

const char *win_xp_env[] = {
   "ALLUSERSPROFILE=C:\\Documents and Settings\\All Users",
   "APPDATA=C:\\Documents and Settings\\$USER\\Application Data",
   "CLIENTNAME=Console",
   "CommonProgramFiles=C:\\Program Files\\Common Files",
   "COMPUTERNAME=$HOST",
   "ComSpec=C:\\WINDOWS\\system32\\cmd.exe",
   "FP_NO_HOST_CHECK=NO",
   "HOMEDRIVE=C:",
   "HOMEPATH=\\Documents and Settings\\$USER",
   "LOGONSERVER=\\\\$HOST",
   "NUMBER_OF_PROCESSORS=1",
   "OS=Windows_NT",
   "Path=C:\\WINDOWS\\system32;C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem",
   "PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH",
   "PROCESSOR_ARCHITECTURE=x86",
   "PROCESSOR_IDENTIFIER=x86 Family 6 Model 23 Stepping 10, GenuineIntel",
   "PROCESSOR_LEVEL=6",
   "PROCESSOR_REVISION=170a",
   "ProgramFiles=C:\\Program Files",
   "PROMPT=$P$G",
   "SESSIONNAME=Console",
   "SystemDrive=C:",
   "SystemRoot=C:\\WINDOWS",
   "TEMP=C:\\DOCUME~1\\$DOSUSER\\LOCALS~1\\Temp",
   "TMP=C:\\DOCUME~1\\$DOSUSER\\LOCALS~1\\Temp",
   "USERDOMAIN=$HOST",
   "USERNAME=$USER",
   "USERPROFILE=C:\\Documents and Settings\\$USER",
   "windir=C:\\WINDOWS",
   NULL
};

const char *linux_env[] = {
   "HOSTNAME=$HOST",
   "TERM=vt100",
   "SHELL=/bin/bash",
   "HISTSIZE=1000",
   "USER=$USER",
   "MAIL=/var/spool/mail/$USER",
   "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
   "PWD=/home/$USER",
   "LANG=en_US.UTF-8",
   "HISTCONTROL=ignoredups",
   "SHLVL=1",
   "HOME=/home/$USER",
   "LOGNAME=$USER",
   "LESSOPEN=|/usr/bin/lesspipe.sh %s",
   "G_BROKEN_FILENAMES=1",
   "OLDPWD=/tmp",
   NULL
};

qstring *make_env(const char *env[], const char *userName, const char *hostName, bool windows = true) {
   qstring *res = new qstring();
   for (int i = 0; env[i]; i++) {
      qstring ev(env[i]);
      ev.replace("$USER", userName);
      ev.replace("$HOST", hostName);
      if (windows) {
         if (strlen(userName) > 8) {
            char buf[10];
            ::qstrncpy(buf, userName, 6);
            ::qstrncpy(buf + 6, "~1", 3);
            ev.replace("$DOSUSER", buf);
         }
         else {
            ev.replace("$DOSUSER", userName);
         }
      }
      *res += ev;
      *res += '\x00';
   }
   *res += '\x00';
   return res;
}

#define BITS_16 0
#define BITS_32 1
#define BITS_64 2

//VERY basic descriptor init function, sets many fields to user space sane defaults
static void init_intr_descriptor(InterruptDescriptor32 *desc, uint32_t offset, uint16_t sel, uint8_t dpl, uint8_t size) {
   desc->desc = 0;  //clear the descriptor
   desc->sel = sel;
   desc->offset0 = (uint16_t)offset;
   desc->offset1 = offset >> 16;
   desc->dpl = dpl;
   desc->present = 1;
   desc->d = size ? 0xe : 6;     //interrupt gate (trap gate would be 0xf : 7)
}

//VERY basic descriptor init function, sets many fields to user space sane defaults
static void init_intr_descriptor(InterruptDescriptor64 *desc, uint64_t offset, uint16_t sel, uint8_t dpl) {
   desc->desc0 = 0;  //clear the descriptor
   desc->desc1 = 0;  //clear the descriptor
   desc->sel = sel;
   desc->offset0 = (uint16_t)offset;
   desc->offset1 = (uint16_t)(offset >> 16);
   desc->offset2 = (uint32_t)(offset >> 32);
   desc->dpl = dpl;
   desc->present = 1;
   desc->type = 0xe;    //interrupt gate, trap gate is 0xf
}

//VERY basic descriptor init function, sets many fields to user space sane defaults
static void init_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code, int bitness = BITS_32) {
   desc->desc = 0;  //clear the descriptor
   desc->base0 = base & 0xffff;
   desc->base1 = (base >> 16) & 0xff;
   desc->base2 = base >> 24;
   if (limit > 0xfffff) {
      //need Giant granularity
      limit >>= 12;
      desc->granularity = 1;
   }
   desc->limit0 = limit & 0xffff;
   desc->limit1 = limit >> 16;

   //some sane defaults
   desc->dpl = 3;
   desc->present = 1;
   if (is_code) {
      if (bitness == 1) {
         desc->db = 1;   //32 bit
      }
      else if (bitness == 2) {
         desc->is_64_code = 1;   //64 bit
      }
   }
   else {
      desc->db = 1;   //32 bit
   }
   desc->type = is_code ? 0xb : 3;
   desc->system = 1;  //code or data
}

#define DESC_IDX(reg) (reg >> 3)

void build_sane_gdt(sk3wldbg *uc, uint32_t fs_base, uint64_t init_pc, uint64_t user_sp) {
   uc_err err;
   uc_x86_mmr gdtr = {0, 0, 0, 0};

   uint64_t gdt_address = 0x80000000;
   
   //unicorn starts w/ cpl == 0 
   
   //initial sp, this will point to iret data to get us to ring 3
   uint64_t init_sp = gdt_address + 0xf00;
   
   //initial pc, this will point to an iret to kick us up to ring 3
   uint64_t kernel_pc = gdt_address + 0xc00;

   int cpl0_cs = 0x10; //ring 0 cs we will iret from
   int cpl0_ss = 0x18; //ring 0 ss we will iret from
   int user_cs_32 = 0x23; //32-bit ring 3 cs we will iret to
   int user_cs_64 = 0x33; //64-bit ring 3 cs
   int user_ss = 0x2b; //ring 3 ss we will iret to, need this because we can't set a ring 3 ss directly in unicorn
   int r_ds = 0x2b;
   int r_es = 0x2b;
   int r_fs = 0x53;    //32-bit teb 
   int r_gs = 0x2b;    //64-bit teb, need to configure w/ wrmsr in ring 0 before transistion to ring 3

   int max_desc = 0x53;
   int ndescs = (max_desc >> 3) + 1;
   uint32_t gdt_size = sizeof(SegmentDescriptor) * ndescs;

   // map GDT
   uint8_t *block = (uint8_t*)uc->map_mem_zero(gdt_address, gdt_address + 0x1000, UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC, SDB_MAP_FIXED);
   SegmentDescriptor *gdt = (SegmentDescriptor *)block;
   
   //store the iret opcode into memory (initial pc will point here)
   block[0xc00] = 0xcf;   //iret

   //setup stack for iret
   *(uint32_t*)(block + 0xf00) = (uint32_t)init_pc;   //initial ring 3 eip
   *(uint32_t*)(block + 0xf04) = user_cs_32;             //rpl 3 cs
   *(uint32_t*)(block + 0xf08) = (0 << 12) | 0x202;   //iitial eflags, w/ IOPL 0
   *(uint32_t*)(block + 0xf0c) = (uint32_t)user_sp;   //initial ring 3 esp
   *(uint32_t*)(block + 0xf10) = user_ss;             //rpl 3 ss

   err = uc_reg_write(uc->uc, UC_X86_REG_ESP, &init_sp);
   err = uc_reg_write(uc->uc, UC_X86_REG_EIP, &kernel_pc);

   gdtr.base = gdt_address;
   gdtr.limit = gdt_size - 1;

   //setup dpl 0 descriptor for initial rpl 0 cs
   init_descriptor(&gdt[DESC_IDX(cpl0_cs)], 0, 0xfffff000, 1);  //code segment
   gdt[DESC_IDX(cpl0_cs)].dpl = 0;  //set descriptor privilege level

   //setup dpl 3 descriptor for eventual rpl 3 cs
   init_descriptor(&gdt[DESC_IDX(user_cs_32)], 0, 0xfffff000, 1);  //code segment

   //setup dpl 3 descriptor for 64-bit
   init_descriptor(&gdt[DESC_IDX(user_cs_64)], 0, 0xfffff000, 1, BITS_64);  //code segment

   init_descriptor(&gdt[DESC_IDX(r_fs)], fs_base, 0xfff, 0);  //one page data segment simulate fs

   // when setting SS, need rpl == cpl && dpl == cpl
   // unicorn starts with cpl == 0, so we need a dpl 0 descriptor and rpl 0 selector
   // We get to ring 3 using an iret
   init_descriptor(&gdt[DESC_IDX(cpl0_ss)], 0, 0xfffff000, 0);  //ring 0 data
   gdt[DESC_IDX(cpl0_ss)].dpl = 0;  //set descriptor privilege level

   //setup dpl 3 descriptor for eventual rpl 3 ss (also ds, es, gs)
   init_descriptor(&gdt[DESC_IDX(user_ss)], 0, 0xfffff000, 0);  //data segment

   //set up a GDT BEFORE you manipulate any segment registers
   err = uc_reg_write(uc->uc, UC_X86_REG_GDTR, &gdtr);

   // when setting SS, need rpl == cpl && dpl == cpl
   // unicorn starts with cpl == 0, so we need a dpl 0 descriptor and rpl 0 selector
   // this precludes us from initially using a rpl 3 seg_reg such as 0x2b for ss
   err = uc_reg_write(uc->uc, UC_X86_REG_SS, &cpl0_ss);

   err = uc_reg_write(uc->uc, UC_X86_REG_CS, &cpl0_cs);

   //for these we must pass: if (dpl < cpl || dpl < rpl) {
   /*
    if (dpl < cpl || dpl < rpl) {
       raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    }
   */
   //we're fine with dpl == rpl
   err = uc_reg_write(uc->uc, UC_X86_REG_DS, &r_ds);
   err = uc_reg_write(uc->uc, UC_X86_REG_ES, &r_es);
   err = uc_reg_write(uc->uc, UC_X86_REG_FS, &r_fs);
   err = uc_reg_write(uc->uc, UC_X86_REG_GS, &r_gs);
}

//var must have been allocated using qalloc

ea_t load_pe_sections(sk3wldbg *uc, void *img, ea_t base, size_t hdr_sz, IMAGE_SECTION_HEADER_ *sections, uint32_t nsect) {
   //load the PE headers
   void *buf = uc->map_mem_zero(base, base + hdr_sz, UC_PROT_READ | UC_PROT_WRITE, SDB_MAP_FIXED);
   ea_t  max = ((base + hdr_sz) + 0xfff) & ~0xfff;
   msg("Copying bytes 0x%x:0x%x into block\n", 0, hdr_sz);
   memcpy(buf, img, hdr_sz);

   //Now load the sections
   for (uint32_t s = 0; s < nsect; s++) {
      ea_t vaddr = base + sections[s].VirtualAddress;
      uint32_t perms = sections[s].Characteristics >> 29;
      uint32_t file_off = sections[s].PointerToRawData;
      uint32_t filesz = sections[s].SizeOfRawData;
      void *block = uc->map_mem_zero(vaddr, vaddr + sections[s].VirtualSize, ida_to_uc_perms_map_win[perms], SDB_MAP_FIXED);
      if (filesz) {
         msg("Copying bytes 0x%x:0x%x into block\n", file_off, file_off + filesz);
         memcpy(block, file_off + (char*)img, filesz);
//         uc_err err = uc_mem_write(uc->uc, vaddr, file_off + (char*)img, filesz);
      }
      max = ((vaddr + sections[s].VirtualSize) + 0xfff) & ~0xfff;
   }
   return max;
}

bool loadPE64(sk3wldbg *uc, void *img, size_t /*sz*/, const char * /*args*/, uint64_t init_pc) {
   IMAGE_DOS_HEADER_ *dos = (IMAGE_DOS_HEADER_*)img;
   if (dos->e_magic != DOS_MAGIC) {
      msg("bad MZ magic\n");
      return false;
   }
   IMAGE_NT_HEADERS64_ *pe = (IMAGE_NT_HEADERS64_*)(dos->e_lfanew + (char*)dos);
   if (pe->Signature != PE_MAGIC) {
      msg("bad PE signature\n");
      return false;
   }
   if (init_pc == BADADDR) {
      init_pc = pe->OptionalHeader.AddressOfEntryPoint + pe->OptionalHeader.ImageBase;
   }
   uc->init_memmgr(0x130000 - 0x100000, 0x800000000000ll);
   IMAGE_SECTION_HEADER_ *sections = (IMAGE_SECTION_HEADER_*)(sizeof(pe->Signature) + sizeof(IMAGE_FILE_HEADER_) +
                                                              pe->FileHeader.SizeOfOptionalHeader +(char*)pe);

   ea_t image_end = load_pe_sections(uc, img, (ea_t)pe->OptionalHeader.ImageBase, pe->OptionalHeader.SizeOfHeaders,
                                     sections, pe->FileHeader.NumberOfSections);

   //PE stack
   uint32_t stack_top = 0x130000;
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, SDB_MAP_FIXED);

   stack_top -= 16;
   uc->set_sp(stack_top);

   ea_t heap_addr = image_end + 0x1000;
   void *heap_mem = uc->map_mem_zero(heap_addr, heap_addr + 0x100000, UC_PROT_READ | UC_PROT_WRITE, SDB_MAP_FIXED);
   heap<uint64_t> *_heap = new heap<uint64_t>(heap_mem, heap_addr, 0x100000);
   _heap->malloc(30);

   return true;
}

TEB_ *create_teb_peb32(sk3wldbg *uc, PEB_ **ppeb) {
   uint32_t rnd;
   uc->getRandomBytes(&rnd, sizeof(rnd));
   rnd %= (0x100000 - 0x3000);
   rnd &= ~0xfff;
   uint32_t teb = 0x203000 + rnd;
   uint32_t peb = teb - 0x3000;
   TEB_ *pteb = (TEB_*)uc->map_mem_zero(teb, teb + sizeof(TEB_), UC_PROT_READ | UC_PROT_WRITE, SDB_MAP_FIXED);
   *ppeb = (PEB_*)uc->map_mem_zero(peb, peb + sizeof(PEB_), UC_PROT_READ | UC_PROT_WRITE, SDB_MAP_FIXED);
   pteb->Self = (TEB_p)teb;
   pteb->ProcessEnvironmentBlock = (PEB_p)peb;

   return pteb;
}

bool loadPE32(sk3wldbg *uc, void *img, size_t /*sz*/, const char * /*args*/, uint64_t init_pc) {
   IMAGE_DOS_HEADER_ *dos = (IMAGE_DOS_HEADER_*)img;
   if (dos->e_magic != DOS_MAGIC) {
      msg("bad MZ magic\n");
      return false;
   }
   IMAGE_NT_HEADERS32_ *pe = (IMAGE_NT_HEADERS32_*)(dos->e_lfanew + (char*)dos);
   if (pe->Signature != PE_MAGIC) {
      msg("bad PE signature\n");
      return false;
   }

   if (init_pc == BADADDR) {
      init_pc = pe->OptionalHeader.AddressOfEntryPoint + pe->OptionalHeader.ImageBase;
   }

   uc->init_memmgr(0x130000 - 0x100000, 0x80010000);

   PEB_ *peb;
   TEB_ *teb = create_teb_peb32(uc, &peb);
   ea_t teb_addr = (ea_t)teb->Self;
   ea_t peb_addr = (ea_t)teb->ProcessEnvironmentBlock;

//   msg("peb addr: 0x%x, peb->ImageBase addr: 0x%x, peb->Mutant addr: 0x%x\n", (uint32_t)peb, (uint32_t)&peb->ImageBaseAddress, (uint32_t)&peb->Mutant);

   IMAGE_SECTION_HEADER_ *sections = (IMAGE_SECTION_HEADER_*)(sizeof(pe->Signature) + sizeof(IMAGE_FILE_HEADER_) +
                                                              pe->FileHeader.SizeOfOptionalHeader +(char*)pe);

   ea_t image_end = load_pe_sections(uc, img, pe->OptionalHeader.ImageBase, pe->OptionalHeader.SizeOfHeaders,
                                     sections, pe->FileHeader.NumberOfSections);

   //PE stack
   uint32_t stack_top = 0x130000;
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, SDB_MAP_FIXED);

   stack_top -= 16;
   uc->set_sp(stack_top);

   teb->StackBase = (voidp)stack_top;
   teb->StackLimit = (voidp)(stack_top - 0x100000);

   uint32_t heap_addr = (uint32_t)image_end + 0x1000;
   void *heap_mem = uc->map_mem_zero(heap_addr, heap_addr + 0x100000, UC_PROT_READ | UC_PROT_WRITE, SDB_MAP_FIXED);
   heap<uint32_t> *_heap = new heap<uint32_t>(heap_mem, heap_addr, 0x100000);

   peb->ImageBaseAddress = (voidp)pe->OptionalHeader.ImageBase;
   peb->ProcessHeap = (voidp)heap_addr;
   peb->NumberOfHeaps = 1;
   peb->MaximumNumberOfHeaps = 16;

   //the following two fields are in ntdll's bss   **** TODO build a page in ntdll to hold these
   peb->ProcessHeaps = (voidp)heap_addr;   //array of MaximumNumberOfHeaps heap pointers
                                            //first entry in this array is ProcessHeap
   peb->Ldr = (PEB_LDR_DATA_p)heap_addr;    //PEB_LDR_DATA_

   uint16_t pid;
   uc->getRandomBytes(&pid, sizeof(pid));
   pid = (pid % 3000) + 1000;

   teb->ClientId.ProcessId = pid;

   uint16_t tid;
   uc->getRandomBytes(&tid, sizeof(tid));
   tid = (tid % 3000) + 1000;

   teb->ClientId.ThreadId = tid;

   qstring *env = make_env(win_xp_env, "bgates", "apollo");

   //copy env into process heap

   delete env;

   build_sane_gdt(uc, teb_addr, init_pc, stack_top);

   return true;
}

//IDA only runs on little-endian platforms
uint16_t get_elf_16(void *pdata, bool big_endian) {
   uint16_t *d = (uint16_t*)pdata;
   return big_endian ? swap16(*d) : *d;
}

uint32_t get_elf_32(void *pdata, bool big_endian) {
   uint32_t *d = (uint32_t*)pdata;
   return big_endian ? swap32(*d) : *d;
}

uint64_t get_elf_64(void *pdata, bool big_endian) {
   uint64_t *d = (uint64_t*)pdata;
   return big_endian ? swap64((ulonglong)*d) : *d;
}

static uint64_t uc_push_8(sk3wldbg *uc, uint64_t sp, uint8_t val) {
   sp -= 1;
   uc_mem_write(uc->uc, sp, &val, 1);
   return sp;
}

static uint64_t uc_push_32(sk3wldbg *uc, uint64_t sp, uint32_t val, bool big_endian) {
   sp -= sizeof(val);
   if (big_endian) {
      val = swap32(val);
   }
   uc_mem_write(uc->uc, sp, &val, sizeof(val));
   return sp;
}

static uint64_t uc_push_64(sk3wldbg *uc, uint64_t sp, uint64_t val, bool big_endian) {
   sp -= sizeof(val);
   if (big_endian) {
      val = swap64((ulonglong)val);
   }
   uc_mem_write(uc->uc, sp, &val, sizeof(val));
   return sp;
}

static uint64_t uc_push(sk3wldbg *uc, uint64_t sp, uint64_t val, bool is_64, bool big_endian) {
   if (is_64) {
      return uc_push_64(uc, sp, val, big_endian);
   }
   return uc_push_32(uc, sp, (uint32_t)val, big_endian);
}

static uint64_t uc_push_buf(sk3wldbg *uc, uint64_t sp, void *val, uint32_t sz) {
   sp -= sz;
   uc_mem_write(uc->uc, sp, val, sz);
   return sp;
}

static uint64_t uc_push_str(sk3wldbg *uc, uint64_t sp, const char *val, bool with_null = true) {
   size_t sz = strlen(val);
   if (with_null) {
      sz++;
   }
   return uc_push_buf(uc, sp, (void*)val, (uint32_t)sz);
}

void build_sane_elf64_gdt(sk3wldbg *uc, uint64_t fs_base, uint64_t init_pc, uint64_t user_sp) {
   uc_err err;
   uc_x86_mmr gdtr = {0, 0, 0, 0};
   uc_x86_mmr idtr = {0, 0, 0, 0};

   uint64_t gdt_address = 0xFFFF800000000000;
   uint64_t idt_address = gdt_address + 0x400;
   
   //unicorn starts w/ cpl == 0 
   
   //initial sp, this will point to iret data to get us to ring 3
   uint64_t init_sp = gdt_address + 0xf00;
   
   //initial pc, this will point to an iret to kick us up to ring 3
   uint64_t kernel_pc = gdt_address + 0xc00;

   uint64_t int3_pc = gdt_address + 0x800;

   int cpl0_cs = 0x10; //ring 0 cs we will iret from
   int cpl0_ss = 0x18; //ring 0 ss we will iret from
   int user_cs_32 = 0x23; //32-bit ring 3 cs we will iret to
   int user_cs_64 = 0x33; //64-bit ring 3 cs
   int user_ss = 0x2b; //ring 3 ss we will iret to, need this because we can't set a ring 3 ss directly in unicorn
   int r_ds = 0;
   int r_es = 0;
   int r_fs = 0;
   int r_gs = 0;       //this is 0x63 in 32-bit code used for tls info, need to set w/ wrmsr
   int intr_seg = 0x40;

   uint64_t ia32_star = cpl0_cs;
   ia32_star <<= 32;

   int max_desc = 0x53;
   int ndescs = (max_desc >> 3) + 1;
   uint32_t gdt_size = sizeof(SegmentDescriptor) * ndescs;

   // map GDT
   uint8_t *block = (uint8_t*)uc->map_mem_zero(gdt_address, gdt_address + 0x1000, UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC, SDB_MAP_FIXED);
   
   qstring sname;
   sname.sprnt("debug_%p", gdt_address);
   createNewSegment(sname.c_str(), gdt_address, 0x1000, uc_to_ida_perms_map[UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC], 2);

   //a small kernel space stack
   uint8_t *kstack = (uint8_t*)uc->map_mem_zero(gdt_address + 0x1000, gdt_address + 0x2000, UC_PROT_WRITE | UC_PROT_READ, SDB_MAP_FIXED);
   sname.sprnt("debug_%p", gdt_address + 0x1000);
   createNewSegment(sname.c_str(), gdt_address + 0x1000, 0x1000, uc_to_ida_perms_map[UC_PROT_WRITE | UC_PROT_READ], 2);

   SegmentDescriptor *gdt = (SegmentDescriptor *)block;
   InterruptDescriptor64 *idt = (InterruptDescriptor64 *)(block + 0x400);

   //some ring 0 code to both kick us up to ring 3 after unicorn launch and handle
   //any syscall instructions encountered in ring 3.
   char kern[] =
      "\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41\xe8\x26\x00\x00\x00\x48"
      "\x8d\x05\x80\x00\x00\x00\xe8\x70\x00\x00\x00\x48\xb8\x00\x00\x00"
      "\x00\x10\x00\x23\x00\xe8\x56\x00\x00\x00\x48\x31\xc0\x48\x31\xd2"
      "\x48\x31\xc9\x48\xcf\xb9\x00\x01\x00\xc0\xe8\x34\x00\x00\x00\xc3"
      "\xb9\x00\x01\x00\xc0\xe8\x33\x00\x00\x00\x48\xc1\xe0\x20\x48\x0f"
      "\xac\xd0\x20\xc3\xb9\x01\x01\x00\xc0\xe8\x15\x00\x00\x00\xc3\xb9"
      "\x01\x01\x00\xc0\xe8\x14\x00\x00\x00\x48\xc1\xe0\x20\x48\x0f\xac"
      "\xd0\x20\xc3\x48\x89\xc2\x48\xc1\xea\x20\x0f\x30\xc3\x0f\x32\xc3"
      "\xb9\x81\x00\x00\xc0\xe8\xe9\xff\xff\xff\xc3\xb9\x82\x00\x00\xc0"
      "\xe8\xde\xff\xff\xff\xc3\x48\x89\x25\x5b\x13\x00\x00\x48\x8d\x25"
      "\x54\x13\x00\x00\x51\x41\x53\x57\x56\x52\x41\x52\x41\x50\x41\x51"
      "\x3d\x9e\x00\x00\x00\x75\x57\x81\xff\x02\x10\x00\x00\x75\x0a\x48"
      "\x89\xf0\xe8\x6e\xff\xff\xff\xeb\x40\x81\xff\x03\x10\x00\x00\x75"
      "\x0a\xe8\x6a\xff\xff\xff\x48\x89\x06\xeb\x2e\x81\xff\x01\x10\x00"
      "\x00\x75\x0a\x48\x89\xf0\xe8\x69\xff\xff\xff\xeb\x1c\x81\xff\x04"
      "\x10\x00\x00\x75\x0a\xe8\x65\xff\xff\xff\x48\x89\x06\xeb\x0a\xb8"
      "\x16\x00\x00\x00\x48\xf7\xd8\xeb\x06\x48\x31\xc0\xeb\x01\x90\x41"
      "\x59\x41\x58\x41\x5a\x5a\x5e\x5f\x41\x5b\x59\x5c\x48\x0f\x07\x90";

   *(uint64_t*)(kern + 2) = 0x00007FFFFFEFC880;   //fs_base;

   memcpy(block + 0xc00, kern, sizeof(kern));   //setup fs msr and iret

   //setup stack for iret
   *(uint64_t*)(block + 0xf00) = init_pc;             //initial ring 3 eip
   *(uint64_t*)(block + 0xf08) = user_cs_64;          //rpl 3 cs
   *(uint64_t*)(block + 0xf10) = (0 << 12) | 0x202;   //iitial eflags, w/ IOPL 0
   *(uint64_t*)(block + 0xf18) = user_sp;             //initial ring 3 esp
   *(uint64_t*)(block + 0xf20) = user_ss;             //rpl 3 ss

   err = uc_reg_write(uc->uc, UC_X86_REG_RSP, &init_sp);
   err = uc_reg_write(uc->uc, UC_X86_REG_RIP, &kernel_pc);

   gdtr.base = gdt_address;
   gdtr.limit = gdt_size - 1;

   //setup dpl 0 descriptor for initial rpl 0 cs
   init_descriptor(&gdt[DESC_IDX(cpl0_cs)], 0, 0xfffff000, 1);  //code segment
   gdt[DESC_IDX(cpl0_cs)].dpl = 0;  //set descriptor privilege level

   //setup dpl 3 descriptor for eventual rpl 3 cs
   init_descriptor(&gdt[DESC_IDX(user_cs_32)], 0, 0xfffff000, 1);  //code segment

   //setup dpl 3 descriptor for 64-bit
   init_descriptor(&gdt[DESC_IDX(user_cs_64)], 0, 0xfffff000, 1, BITS_64);  //code segment

   // when setting SS, need rpl == cpl && dpl == cpl
   // unicorn starts with cpl == 0, so we need a dpl 0 descriptor and rpl 0 selector
   // We get to ring 3 using an iret
   init_descriptor(&gdt[DESC_IDX(cpl0_ss)], 0, 0xfffff000, 0);  //ring 0 data
   gdt[DESC_IDX(cpl0_ss)].dpl = 0;  //set descriptor privilege level

   //setup dpl 3 descriptor for eventual rpl 3 ss (also ds, es, gs)
   init_descriptor(&gdt[DESC_IDX(user_ss)], 0, 0xfffff000, 0);  //data segment

   //set up a GDT BEFORE you manipulate any segment registers
   err = uc_reg_write(uc->uc, UC_X86_REG_GDTR, &gdtr);

   //beginnings of an IDT. TODO: finish this up. Need to setup tss for this to work
   int num_intr = 16;
   uint32_t idt_size = sizeof(InterruptDescriptor64) * num_intr;
   idtr.base = idt_address;
   idtr.limit = idt_size - 1;
   init_intr_descriptor(&idt[3], int3_pc, cpl0_cs, 0);

//   err = uc_reg_write(uc->uc, UC_X86_REG_IDTR, &idtr);    //TODO: not ready for this yet

   // when setting SS, need rpl == cpl && dpl == cpl
   // unicorn starts with cpl == 0, so we need a dpl 0 descriptor and rpl 0 selector
   // this precludes us from initially using a rpl 3 seg_reg such as 0x2b for ss
   err = uc_reg_write(uc->uc, UC_X86_REG_SS, &cpl0_ss);

   err = uc_reg_write(uc->uc, UC_X86_REG_CS, &cpl0_cs);

   //for these we must pass: if (dpl < cpl || dpl < rpl) {
   /*
    if (dpl < cpl || dpl < rpl) {
       raise_exception_err(env, EXCP0D_GPF, selector & 0xfffc);
    }
   */
   //we're fine with dpl == rpl
   err = uc_reg_write(uc->uc, UC_X86_REG_DS, &r_ds);
   err = uc_reg_write(uc->uc, UC_X86_REG_ES, &r_es);
   err = uc_reg_write(uc->uc, UC_X86_REG_FS, &r_fs);
   err = uc_reg_write(uc->uc, UC_X86_REG_GS, &r_gs);
}

static uint64_t create_elf_env(sk3wldbg *uc, uint64_t sp, elf_aux *av, const char *args, bool is_64, bool big_endian) {
   char bin[256];
   qvector<uint64_t> env;
   qvector<uint64_t> argv;
   qvector<qstring> arguments;
   ssize_t bin_len = get_root_filename(bin, sizeof(bin));
   sp = uc_push(uc, sp, 0, is_64, big_endian);
   sp = uc_push_str(uc, sp, bin);
   sp = uc_push_str(uc, sp, "_=./", false);
   uint64_t at_execfn = sp + 2;
   env.push_back(sp);
   sp = uc_push_str(uc, sp, "HOME=/home/user");
   env.push_back(sp);
   sp = uc_push_str(uc, sp, "PWD=/home/user");
   env.push_back(sp);
   sp = uc_push_str(uc, sp, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
   env.push_back(sp);
   sp = uc_push_str(uc, sp, "SHELL=/bin/bash");
   env.push_back(sp);

   qstring argv_0 = "./";
   argv_0 += bin;
   arguments.push_back(argv_0);
   const char *p1 = args;
   while (true) {
      while (isspace(*p1)) p1++;
      qstring arg;
      if (*p1) {
         char quote = 0;
         if (*p1 == '"' || *p1 == '\'') {
            quote = *p1++;
         }
         while (*p1) {
            if (*p1 == '\\') {
               //need better escape handling, only handling escaped quotes for now
               p1++;
               if (*p1 == 0) {
                  p1--;
               }
            }
            else if (quote) {
               if (*p1 == quote) {
                  p1++;
                  break;
               }
            }
            else if (isspace(*p1)) {
               break;
            }
            arg += *p1++;
         }
         if (arg.length() > 0) {
            arguments.push_back(arg);
         }
      }
      else {
         break;
      }
   }

   while (arguments.size() > 0) {
      qstring &a = arguments.back();
      sp = uc_push_str(uc, sp, a.c_str());
      argv.push_back(sp);
      arguments.pop_back();
   }

   sp &= is_64 ? ~7 : ~3;   //align sp to 4 or 8 bytes

   sp = uc_push_str(uc, sp, "x86_64");
   uint64_t at_platform = sp;
   uint8_t at_random_buf[16];
   uc->getRandomBytes(at_random_buf, sizeof(at_random_buf));
   sp = uc_push_buf(uc, sp, at_random_buf, sizeof(at_random_buf));   
   uint64_t at_random = sp;

   sp &= is_64 ? ~7 : ~3;   //align sp to 4 or 8 bytes

   //need to build an AUX vector here
   qvector<uint64_t> aux;
   aux.push_back(_AT_SYSINFO_EHDR);
   aux.push_back(av->vdso);

   aux.push_back(_AT_HWCAP);
   aux.push_back(0xfabfbff);

   aux.push_back(_AT_PAGESZ);
   aux.push_back(0x1000);

   aux.push_back(_AT_CLKTCK);
   aux.push_back(0x64);

   aux.push_back(_AT_PHDR);
   aux.push_back(av->phdr);

   aux.push_back(_AT_PHENT);
   aux.push_back(av->phent);

   aux.push_back(_AT_PHNUM);
   aux.push_back(av->phnum);

   aux.push_back(_AT_BASE);      //base address of ELF interpreter (ld-linux)
   aux.push_back(0);

   aux.push_back(_AT_FLAGS);
   aux.push_back(0);

   aux.push_back(_AT_ENTRY);
   aux.push_back(av->entry);

   aux.push_back(_AT_UID);
   aux.push_back(av->uid);

   aux.push_back(_AT_EUID);
   aux.push_back(av->euid);

   aux.push_back(_AT_GID);
   aux.push_back(av->gid);

   aux.push_back(_AT_EGID);
   aux.push_back(av->egid);

   aux.push_back(_AT_SECURE);
   aux.push_back(0);

   aux.push_back(_AT_RANDOM);
   aux.push_back(at_random);

   aux.push_back(_AT_EXECFN);
   aux.push_back(at_execfn);

   aux.push_back(_AT_PLATFORM);
   aux.push_back(at_platform);

   aux.push_back(_AT_NULL);  //AT_NULL entry
   aux.push_back(0);  //AT_NULL value

   for (int i = aux.size(); i > 0; i--) {
      sp = uc_push(uc, sp, aux[i - 1], is_64, big_endian);
   }

   //null terminate envp array
   sp = uc_push(uc, sp, 0, is_64, big_endian);
   //push envp pointers
   for (qvector<uint64_t>::iterator i = env.begin(); i != env.end(); i++) {
      sp = uc_push(uc, sp, *i, is_64, big_endian);
   }

   //null terminate argv array
   sp = uc_push(uc, sp, 0, is_64, big_endian);
   //remember argc
   uint32_t argc = (uint32_t)argv.size();

   //push argv pointers
   for (qvector<uint64_t>::iterator i = argv.begin(); i != argv.end(); i++) {
      sp = uc_push(uc, sp, *i, is_64, big_endian);
   }
   //push argc
   sp = uc_push(uc, sp, argc, is_64, big_endian);

   return sp;
}

bool loadElf64(sk3wldbg *uc, void *img, uint64_t sz, const char *args, uint64_t init_pc) {
   Elf64_Ehdr *elf = (Elf64_Ehdr*)img;
   uint32_t exec_stack = UC_PROT_EXEC;
   bool big_endian = false;

   if (memcmp(elf->e_ident, "\x7f" "ELF", 4) != 0) {
      msg("bad ELF magic: 0x%x\n", *(uint32_t*)elf->e_ident);
      return false;
   }
   if (elf->e_ident[EI_DATA] == 2) {
      big_endian = true;
   }
   uint64_t e_phoff = get_elf_64(&elf->e_phoff, big_endian);
   if (e_phoff > (sz - sizeof(Elf64_Phdr))) {
      msg("bad e_phoff\n");
      return false;
   }

   if (init_pc == BADADDR) {
      init_pc = elf->e_entry;
   }

   Elf64_Phdr *phdr = (Elf64_Phdr*)(e_phoff + (char*)img);
   Elf64_Phdr *h = phdr;
   uint16_t e_phnum = get_elf_16(&elf->e_phnum, big_endian);

   //check for execstack so we can map the stack first
   //also find base address of binary
   uint64_t elf_base = 0xffffffffffffffffll;
   for (uint16_t i = 0; i < e_phnum; i++, h++) {
      uint32_t p_type = get_elf_32(&h->p_type, big_endian);
      uint32_t p_flags = get_elf_32(&h->p_flags, big_endian);
      if (p_type == PT_GNU_STACK) {
         if ((p_flags & PF_X) == 0) {
            //stack marked NX
            exec_stack = 0;
         }
      }
      else if (p_type == PT_LOAD) {
         uint64_t p_vaddr = get_elf_64(&phdr->p_vaddr, big_endian) & ~0xfff;
         if (p_vaddr < elf_base) {
            elf_base = p_vaddr;
         }
      }
   }
   //ELF stack
   uint64_t stack_max = 0x7ffffffff000ll;
   uint64_t stack_min = 0x7ffffffff000ll - 0x100000;
   uint64_t fs_base = stack_min - 0x3000;
   uint64_t vdso_base = stack_min - 0x4000;
   uc->init_memmgr(0, 0xffff800000002000);  //allow mapping zero page
   uc->map_mem_zero(stack_min, stack_max, UC_PROT_READ | UC_PROT_WRITE | exec_stack);
   msg("elf_fs mapped to %p\n", fs_base);
   uint8_t *elf_fs = (uint8_t*)uc->map_mem_zero(fs_base, fs_base + 0x2000, UC_PROT_READ | UC_PROT_WRITE, SDB_MAP_FIXED);

   uint8_t *vdso = (uint8_t*)uc->map_mem_zero(vdso_base, vdso_base + 0x1000, UC_PROT_READ | UC_PROT_EXEC, SDB_MAP_FIXED);

   elf_aux av;
   av.entry = get_elf_64(&elf->e_entry, big_endian);
   av.vdso = vdso_base;
   av.phdr = elf_base + e_phoff;
   av.phent = get_elf_16(&elf->e_phentsize, big_endian);
   av.phnum = e_phnum;
   av.uid = 1000;
   av.euid = 1000;
   av.gid = 1000;
   av.egid = 1000;

   uint64_t stack_top = create_elf_env(uc, stack_max, &av, args, true, big_endian);
   uc->set_sp(stack_top);

   uc->getRandomBytes(elf_fs + 0x29, 7);   //canary, low byte remains 0
   build_sane_elf64_gdt(uc, fs_base, init_pc, stack_top);

   uint64_t brk = 0;
   for (uint16_t i = 0; i < e_phnum; i++) {
      uint32_t p_type = get_elf_32(&phdr->p_type, big_endian);
      uint32_t p_flags = get_elf_32(&phdr->p_flags, big_endian);
      msg("phdr->p_type: %d\n", p_type);
      if (p_type == PT_LOAD) {
         uint64_t p_vaddr = get_elf_64(&phdr->p_vaddr, big_endian);
         uint64_t p_memsz = get_elf_64(&phdr->p_memsz, big_endian);
         uint64_t p_offset = get_elf_64(&phdr->p_offset, big_endian);
         uint64_t p_filesz = get_elf_64(&phdr->p_filesz, big_endian);
         brk = (p_vaddr + p_memsz + 0xfff) & ~0xfff;
/*
         uint64_t begin = p_vaddr & ~0xfff;
         uint64_t end = (p_vaddr + p_memsz + 0xfff) & ~0xfff;
*/
         msg("ELF64 loader mapping %p bytes at %p, from file offset %p\n",
               (uint64_t)p_memsz, (uint64_t)p_vaddr, (uint64_t)p_offset);
         void *block = uc->map_mem_zero(p_vaddr & ~0xfff, p_vaddr + p_memsz, ida_to_uc_perms_map[p_flags & 7], SDB_MAP_FIXED);
         uint64_t endoff = p_offset + p_filesz;
         uint64_t offset = p_offset & ~0xfff;
         if ((p_flags & PF_W) == 0) { //not writeable, assume entire page is mmapped
            endoff = (endoff + 0xfff) & ~0xfff;
         }
         if (endoff > sz) {
            endoff = sz;
         }
         msg("Copying bytes %p:%p into block\n", (uint64_t)offset, (uint64_t)endoff);
         memcpy(block, offset + (char*)img, (size_t)(endoff - offset));
/*
         uc_err err = uc_mem_write(uc->uc, begin, offset + (char*)img, (size_t)(endoff - offset));
         if (err != UC_ERR_OK) {
            msg("uc_mem_write failed with error: %d\n", err);
         }
*/
      }
      phdr++;
   }

   netnode kernel_nn("$ kernel", 0, true);
   kernel_nn.altset(KERNEL_BRK, (nodeidx_t)brk);
   kernel_nn.altset(KERNEL_MMAP_TOP, (nodeidx_t)vdso_base);

   return true;
}

bool loadElf32(sk3wldbg *uc, void *img, size_t sz, const char *args, uint64_t init_pc) {
   Elf32_Ehdr *elf = (Elf32_Ehdr*)img;
   uint32_t exec_stack = UC_PROT_EXEC;
   bool big_endian = false;

   if (memcmp(elf->e_ident, "\x7f" "ELF", 4) != 0 && memcmp(elf->e_ident, "\x7f" "CGC", 4) != 0) {
      msg("bad ELF magic: 0x%x\n", *(uint32_t*)elf->e_ident);
      return false;
   }
   if (elf->e_ident[EI_DATA] == 2) {
      big_endian = true;
   }
   uint32_t e_phoff = get_elf_32(&elf->e_phoff, big_endian);
   if (e_phoff > (sz - sizeof(Elf32_Phdr))) {
      msg("bad e_phoff\n");
      return false;
   }

   if (init_pc == BADADDR) {
      init_pc = elf->e_entry;
   }

   Elf32_Phdr *phdr = (Elf32_Phdr*)(e_phoff + (char*)img);
   Elf32_Phdr *h = phdr;
   uint16_t e_phnum = get_elf_16(&elf->e_phnum, big_endian);

   uint64_t elf_base = 0xffffffffffffffff;
   //check for execstack so we can map the stack first
   for (uint16_t i = 0; i < e_phnum; i++, h++) {
      uint32_t p_type = get_elf_32(&h->p_type, big_endian);
      uint32_t p_flags = get_elf_32(&h->p_flags, big_endian);
      if (p_type == PT_GNU_STACK) {
         if ((p_flags & PF_X) == 0) {
            //stack marked NX
            exec_stack = 0;
         }
      }
      else if (p_type == PT_LOAD) {
         uint64_t p_vaddr = get_elf_32(&phdr->p_vaddr, big_endian) & ~0xfff;
         if (p_vaddr < elf_base) {
            elf_base = p_vaddr;
         }
      }
   }
   //ELF stack
   uint32_t stack_top = 0xffffe000;
   uint32_t stack_min = stack_top - 0x100000;
   uint32_t fs_base = stack_min - 0x3000;
   uint32_t vdso_base = stack_min - 0x4000;
   uc->init_memmgr(0, stack_top);   //allow mapping zero page
   uc->map_mem_zero(stack_min, stack_top, UC_PROT_READ | UC_PROT_WRITE | exec_stack);

   uint8_t *vdso = (uint8_t*)uc->map_mem_zero(vdso_base, vdso_base + 0x1000, UC_PROT_READ | UC_PROT_EXEC, SDB_MAP_FIXED);

   elf_aux av;
   av.entry = get_elf_32(&elf->e_entry, big_endian);
   av.vdso = vdso_base;
   av.phdr = elf_base + e_phoff;
   av.phent = get_elf_16(&elf->e_phentsize, big_endian);
   av.phnum = e_phnum;
   av.uid = 1000;
   av.euid = 1000;
   av.gid = 1000;
   av.egid = 1000;

   stack_top = (uint32_t)create_elf_env(uc, stack_top, &av, args, false, big_endian);
   uc->set_sp(stack_top);

   uint32_t brk = 0;
   for (uint16_t i = 0; i < e_phnum; i++) {
      uint32_t p_type = get_elf_32(&phdr->p_type, big_endian);
      uint32_t p_flags = get_elf_32(&phdr->p_flags, big_endian);
      msg("phdr->p_type: %d\n", p_type);
      if (p_type == PT_LOAD) {
         uint32_t p_vaddr = get_elf_32(&phdr->p_vaddr, big_endian);
         uint32_t p_memsz = get_elf_32(&phdr->p_memsz, big_endian);
         uint32_t p_offset = get_elf_32(&phdr->p_offset, big_endian);
         uint32_t p_filesz = get_elf_32(&phdr->p_filesz, big_endian);
         brk = (p_vaddr + p_memsz + 0xfff) & ~0xfff;

         msg("ELF32 loader mapping %p bytes at %p, from file offset %p\n",
               (uint64_t)p_memsz, (uint64_t)p_vaddr, (uint64_t)p_offset);
         void *block = uc->map_mem_zero(p_vaddr & ~0xfff, p_vaddr + p_memsz, ida_to_uc_perms_map[p_flags & 7], SDB_MAP_FIXED);
         uint64_t endoff = p_offset + p_filesz;
         uint64_t offset = p_offset & ~0xfff;
         if ((p_flags & PF_W) == 0) { //not writeable, assume entire page is mmapped
            endoff = (endoff + 0xfff) & ~0xfff;
         }
         if (endoff > sz) {
            endoff = sz;
         }
         msg("Copying bytes %p:%p into block\n", (uint64_t)offset, (uint64_t)endoff);
         memcpy(block, offset + (char*)img, (size_t)(endoff - offset));

/*
         uc_err err = uc_mem_write(uc->uc, begin, offset + (char*)img, endoff - offset);
         if (err != UC_ERR_OK) {
            msg("uc_mem_write failed with error: %d\n", err);
         }
*/
      }
      phdr++;
   }

   netnode kernel_nn("$ kernel", 0, true);
   kernel_nn.altset(KERNEL_BRK, (nodeidx_t)brk);
   kernel_nn.altset(KERNEL_MMAP_TOP, (nodeidx_t)vdso_base);

   return true;
}

bool loadImage(sk3wldbg *uc, void *img, size_t sz, const char *args, uint64_t init_pc) {
   bool result = false;
   switch (uc->filetype) {
      case f_PE:
         if (inf.lflags & LFLG_64BIT) {
            msg("loadPE64\n");
            result = loadPE64(uc, img, sz, args, init_pc);
         }
         else {
            msg("loadPE32\n");
            result = loadPE32(uc, img, sz, args, init_pc);
         }
         break;
      case f_ELF: {
         if (inf.lflags & LFLG_64BIT) {
            msg("loadElf64\n");
            result = loadElf64(uc, img, (uint64_t)sz, args, init_pc);
         }
         else {
            msg("loadElf32\n");
            result = loadElf32(uc, img, sz, args, init_pc);
         }
         netnode kernel_nn("$ kernel", 0, true);
         kernel_nn.altset(KERNEL_UID, 1000);
         kernel_nn.altset(KERNEL_EUID, 1000);
         kernel_nn.altset(KERNEL_GID, 1000);
         kernel_nn.altset(KERNEL_EGID, 1000);
         kernel_nn.altset(KERNEL_PID, 1234);
         kernel_nn.altset(KERNEL_PPID, 1232);
         kernel_nn.altset(KERNEL_TID, 54321);
         break;
      }
      default:
         //we don't know how to load this
         //TODO: iterate over IDA sections, and copy content into unicorn
         //need to account for bss stuff which IDA fills with ?? which reads as 0xff
         break;
   }
   return result;
}
