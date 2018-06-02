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

void load_pe_sections(sk3wldbg *uc, void *img, ea_t base, size_t hdr_sz, IMAGE_SECTION_HEADER_ *sections, uint32_t nsect) {
   //load the PE headers
   void *buf = uc->map_mem_zero(base, base + hdr_sz, UC_PROT_READ | UC_PROT_WRITE);
   msg("Copying bytes 0x%x:0x%x into block\n", 0, hdr_sz);
   memcpy(buf, img, hdr_sz);

   //Now load the sections
   for (uint32_t s = 0; s < nsect; s++) {
      ea_t vaddr = base + sections[s].VirtualAddress;
      uint32_t perms = sections[s].Characteristics >> 29;
      uint32_t file_off = sections[s].PointerToRawData;
      uint32_t filesz = sections[s].SizeOfRawData;
      void *block = uc->map_mem_zero(vaddr, vaddr + sections[s].VirtualSize, ida_to_uc_perms_map_win[perms]);
      if (filesz) {
         msg("Copying bytes 0x%x:0x%x into block\n", file_off, file_off + filesz);
         memcpy(block, file_off + (char*)img, filesz);
//         uc_err err = uc_mem_write(uc->uc, vaddr, file_off + (char*)img, filesz);
      }
   }
}

bool loadPE64(sk3wldbg *uc, void *img, size_t /*sz*/, const char * /*args*/) {
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
   uc->init_memmgr(0x130000 - 0x100000, 0x80000000);
   IMAGE_SECTION_HEADER_ *sections = (IMAGE_SECTION_HEADER_*)(sizeof(pe->Signature) + sizeof(IMAGE_FILE_HEADER_) + 
                                                              pe->FileHeader.SizeOfOptionalHeader +(char*)pe);

   load_pe_sections(uc, img, pe->OptionalHeader.ImageBase, pe->OptionalHeader.SizeOfHeaders,
                    sections, pe->FileHeader.NumberOfSections);

   //PE stack
   uint32_t stack_top = 0x130000;
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);

   stack_top -= 16;
   uc->set_sp(stack_top);

   return true;
}

bool loadPE32(sk3wldbg *uc, void *img, size_t /*sz*/, const char * /*args*/) {
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
   uc->init_memmgr(0x130000 - 0x100000, 0x80000000);
   IMAGE_SECTION_HEADER_ *sections = (IMAGE_SECTION_HEADER_*)(sizeof(pe->Signature) + sizeof(IMAGE_FILE_HEADER_) + 
                                                              pe->FileHeader.SizeOfOptionalHeader +(char*)pe);

   load_pe_sections(uc, img, pe->OptionalHeader.ImageBase, pe->OptionalHeader.SizeOfHeaders,
                    sections, pe->FileHeader.NumberOfSections);

   //PE stack
   uint32_t stack_top = 0x130000;
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);

   stack_top -= 16;
   uc->set_sp(stack_top);

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

static uint64_t create_elf_env(sk3wldbg *uc, uint64_t sp, const char *args, bool is_64, bool big_endian) {
   char bin[256];
   qvector<uint64_t> env;
   qvector<uint64_t> argv;
   qvector<qstring> arguments;
   ssize_t bin_len = get_root_filename(bin, sizeof(bin));
   sp = uc_push(uc, sp, 0, is_64, big_endian);
   sp = uc_push_str(uc, sp, bin);
   sp = uc_push_str(uc, sp, "_=./", false);
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

   //need to build an AUX vector here
   //For now we just write an AT_NULL entry
   sp = uc_push(uc, sp, 0, is_64, big_endian);
   sp = uc_push(uc, sp, 0, is_64, big_endian);

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

bool loadElf64(sk3wldbg *uc, void *img, uint64_t sz, const char *args) {
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
   Elf64_Phdr *phdr = (Elf64_Phdr*)(e_phoff + (char*)img);
   Elf64_Phdr *h = phdr;
   uint16_t e_phnum = get_elf_16(&elf->e_phnum, big_endian);

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
   }
   //ELF stack
   uint64_t stack_top = 0x7ffffffff000ll;
   uc->init_memmgr(0x1000, stack_top);
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE | exec_stack);

   stack_top = create_elf_env(uc, stack_top, args, true, big_endian);
   uc->set_sp(stack_top);

   for (uint16_t i = 0; i < e_phnum; i++) {
      uint32_t p_type = get_elf_32(&phdr->p_type, big_endian);
      uint32_t p_flags = get_elf_32(&phdr->p_flags, big_endian);
      msg("phdr->p_type: %d\n", p_type);
      if (p_type == PT_LOAD) {
         uint64_t p_vaddr = get_elf_64(&phdr->p_vaddr, big_endian);
         uint64_t p_memsz = get_elf_64(&phdr->p_memsz, big_endian);
         uint64_t p_offset = get_elf_64(&phdr->p_offset, big_endian);
         uint64_t p_filesz = get_elf_64(&phdr->p_filesz, big_endian);
/*
         uint64_t begin = p_vaddr & ~0xfff;
         uint64_t end = (p_vaddr + p_memsz + 0xfff) & ~0xfff;
*/
         msg("ELF64 loader mapping 0x%llx bytes at 0x%llx, from file offset 0x%llx\n", 
               (uint64_t)p_memsz, (uint64_t)p_vaddr, (uint64_t)p_offset);
         void *block = uc->map_mem_zero(p_vaddr & ~0xfff, p_vaddr + p_memsz, ida_to_uc_perms_map[p_flags & 7]);
         uint64_t offset = p_offset & ~0xfff;
         uint64_t endoff = (p_offset + p_filesz + 0xfff) & ~0xfff;
         if (endoff > sz) {
            endoff = p_offset + p_filesz;
         }
         msg("Copying bytes 0x%llx:0x%llx into block\n", (uint64_t)offset, (uint64_t)endoff);
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

   return true;
}

bool loadElf32(sk3wldbg *uc, void *img, size_t sz, const char *args) {
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
   Elf32_Phdr *phdr = (Elf32_Phdr*)(e_phoff + (char*)img);
   Elf32_Phdr *h = phdr;
   uint16_t e_phnum = get_elf_16(&elf->e_phnum, big_endian);

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
   }
   //ELF stack
   uint32_t stack_top = 0xffffe000;
   uc->init_memmgr(0x1000, stack_top);
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE | exec_stack);

   stack_top = (uint32_t)create_elf_env(uc, stack_top, args, false, big_endian);
   uc->set_sp(stack_top);

   for (uint16_t i = 0; i < e_phnum; i++) {
      uint32_t p_type = get_elf_32(&phdr->p_type, big_endian);
      uint32_t p_flags = get_elf_32(&phdr->p_flags, big_endian);
      msg("phdr->p_type: %d\n", p_type);
      if (p_type == PT_LOAD) {
         uint32_t p_vaddr = get_elf_32(&phdr->p_vaddr, big_endian);
         uint32_t p_memsz = get_elf_32(&phdr->p_memsz, big_endian);
         uint32_t p_offset = get_elf_32(&phdr->p_offset, big_endian);
         uint32_t p_filesz = get_elf_32(&phdr->p_filesz, big_endian);

         ea_t begin = p_vaddr & ~0xfff;
         ea_t end = (p_vaddr + p_memsz + 0xfff) & ~0xfff;
         msg("ELF32 loader mapping 0x%x bytes at 0x%x, from file offset 0x%x\n", p_memsz, p_vaddr, p_offset);
         void *block = uc->map_mem_zero(begin, end, ida_to_uc_perms_map[p_flags & 7]);
         size_t offset = p_offset & ~0xfff;
         size_t endoff = (p_offset + p_filesz + 0xfff) & ~0xfff;
         if (endoff > sz) {
            endoff = p_offset + p_filesz;
         }
         msg("Copying bytes 0x%llx:0x%llx into block\n", (uint64_t)offset, (uint64_t)endoff);
         memcpy(block, offset + (char*)img, endoff - offset);
/*
         uc_err err = uc_mem_write(uc->uc, begin, offset + (char*)img, endoff - offset);
         if (err != UC_ERR_OK) {
            msg("uc_mem_write failed with error: %d\n", err);
         }
*/
      }
      phdr++;
   }

   return true;
}

bool loadImage(sk3wldbg *uc, void *img, size_t sz, const char *args) {
   bool result = false;
   switch (uc->filetype) {
      case f_PE:
         if (inf.lflags & LFLG_64BIT) {
            msg("loadPE64\n");
            result = loadPE64(uc, img, sz, args);
         }
         else {
            msg("loadPE32\n");
            result = loadPE32(uc, img, sz, args);
         }
         break;
      case f_ELF:
         if (inf.lflags & LFLG_64BIT) {
            msg("loadElf64\n");
            result = loadElf64(uc, img, (uint64_t)sz, args);
         }
         else {
            msg("loadElf32\n");
            result = loadElf32(uc, img, sz, args);
         }
         break;
      default:
         //we don't know how to load this
         //TODO: iterate over IDA sections, and copy content into unicorn
         //need to account for bss stuff which IDA fills with ?? which reads as 0xff
         break;
   }
   return result;
}
