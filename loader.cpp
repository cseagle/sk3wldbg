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

#include <ida.hpp>
#include "loader.h"

struct ELF32_Ehdr {
   uint8_t  e_ident[16];
#define ELF_IDENT  "\177ELF\x01\x01\x01"
   uint16_t e_type;         /* Must be 2 for executable */
   uint16_t e_machine;      /* Must be 3 for i386 */
   uint32_t e_version;      /* Must be 1 */
   uint32_t e_entry;        /* Virtual address entry point */
   uint32_t e_phoff;        /* Program Header offset */
   uint32_t e_shoff;        /* Section Header offset */
   uint32_t e_flags;        /* Must be 0 */
   uint16_t e_ehsize;       /* ELF header's size */
   uint16_t e_phentsize;    /* Program header entry size */
   uint16_t e_phnum;        /* # program header entries */
   uint16_t e_shentsize;    /* Section header entry size */
   uint16_t e_shnum;        /* # section header entries */
   uint16_t e_shstrndx;     /* sect header # of str table */
};

struct ELF32_Phdr {
   uint32_t        p_type;         /* Section type */
#define PT_LOAD     1               /* Segment loaded into mem */
   uint32_t        p_offset;       /* Offset into the file */
   uint32_t        p_vaddr;        /* Virtual program address */
   uint32_t        p_paddr;        /* Set to zero */
   uint32_t        p_filesz;       /* Section bytes in file */
   uint32_t        p_memsz;        /* Section bytes in memory */
   uint32_t        p_flags;        /* section flags */
#define PF_X        (1<<0)          /* Mapped executable */
#define PF_W        (1<<1)          /* Mapped writable */
#define PF_R        (1<<2)          /* Mapped readable */
   uint32_t        p_align;        /* Only used by core dumps */
};

struct Elf64_Ehdr {
  uint8_t    e_ident[16];     /* Magic number and other info */
  uint16_t   e_type;                 /* Object file type */
  uint16_t   e_machine;              /* Architecture */
  uint32_t   e_version;              /* Object file version */
  uint64_t   e_entry;                /* Entry point virtual address */
  uint64_t   e_phoff;                /* Program header table file offset */
  uint64_t   e_shoff;                /* Section header table file offset */
  uint32_t   e_flags;                /* Processor-specific flags */
  uint16_t   e_ehsize;               /* ELF header size in bytes */
  uint16_t   e_phentsize;            /* Program header table entry size */
  uint16_t   e_phnum;                /* Program header table entry count */
  uint16_t   e_shentsize;            /* Section header table entry size */
  uint16_t   e_shnum;                /* Section header table entry count */
  uint16_t   e_shstrndx;             /* Section header string table index */
};

struct Elf64_Phdr {
  uint32_t   p_type;                 /* Segment type */
  uint32_t   p_flags;                /* Segment flags */
  uint64_t   p_offset;               /* Segment file offset */
  uint64_t   p_vaddr;                /* Segment virtual address */
  uint64_t   p_paddr;                /* Segment physical address */
  uint64_t   p_filesz;               /* Segment size in file */
  uint64_t   p_memsz;                /* Segment size in memory */
  uint64_t   p_align;                /* Segment alignment */
};

static unsigned int ida_to_uc_perms_map[] = {
   UC_PROT_NONE, UC_PROT_EXEC, UC_PROT_WRITE, UC_PROT_EXEC | UC_PROT_WRITE,
   UC_PROT_READ, UC_PROT_EXEC | UC_PROT_READ, UC_PROT_READ | UC_PROT_WRITE, UC_PROT_ALL
};

static unsigned int ida_to_uc_perms_map_win[] = {
   UC_PROT_NONE, UC_PROT_EXEC, UC_PROT_READ, UC_PROT_EXEC | UC_PROT_READ,
   UC_PROT_WRITE, UC_PROT_EXEC | UC_PROT_WRITE, UC_PROT_READ | UC_PROT_WRITE, UC_PROT_ALL
};

bool loadPE64(sk3wldbg *uc, void *img, size_t /*sz*/) {
   //TODO implement this loader!
   if (memcmp(img, "MZ", 2) != 0) {
      msg("bad MZ magic\n");
      return false;      
   }
   unsigned char *pe = (unsigned char*)(*(int*)(0x3c + (char*)img) + (char*)img);
   if (memcmp(pe, "PE\x00\x00", 4) != 0) {
      msg("bad PE signature\n");
      return false;      
   }
   unsigned int nsect = *(unsigned short*)(pe + 6);
   unsigned int ohdr = *(unsigned short*)(pe + 20);
   ea_t image_base = *(ea_t*)(pe + 24 + 24);
   unsigned char *sections = pe + 24 + ohdr;
   for (unsigned int s = 0; s < nsect; s++) {
      ea_t vaddr = image_base + *(unsigned int*)(sections + 12);
      unsigned int vsize = *(unsigned int*)(sections + 8);
      unsigned int perms = (*(unsigned int*)(sections + 36)) >> 29;
      unsigned int file_off = *(unsigned int*)(sections + 20);
      unsigned int filesz = *(unsigned int*)(sections + 16);
      uc->map_mem_zero(vaddr & ~0xfff, (vaddr + vsize + 0xfff) & ~0xfff, ida_to_uc_perms_map_win[perms]);
      if (filesz) {
         msg("Copying bytes 0x%x:0x%x into block\n", file_off, file_off + filesz);
         uc_err err = uc_mem_write(uc->uc, vaddr, file_off + (char*)img, filesz);
      }
      sections += 40;
   }

   //PE stack
   unsigned int stack_top = 0x130000;
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE);

   stack_top -= 16;
   uc->set_sp(stack_top);

   return true;
}

bool loadPE32(sk3wldbg *uc, void *img, size_t /*sz*/) {
   if (memcmp(img, "MZ", 2) != 0) {
      msg("bad MZ magic\n");
      return false;      
   }
   unsigned char *pe = (unsigned char*)(*(int*)(0x3c + (char*)img) + (char*)img);
   if (memcmp(pe, "PE\x00\x00", 4) != 0) {
      msg("bad PE signature\n");
      return false;      
   }
   unsigned int nsect = *(unsigned short*)(pe + 6);
   unsigned int ohdr = *(unsigned short*)(pe + 20);
   unsigned int image_base = *(unsigned int*)(pe + 24 + 28);
   unsigned char *sections = pe + 24 + ohdr;
   for (unsigned int s = 0; s < nsect; s++) {
      unsigned int vaddr = image_base + *(unsigned int*)(sections + 12);
      unsigned int vsize = *(unsigned int*)(sections + 8);
      unsigned int perms = (*(unsigned int*)(sections + 36)) >> 29;
      unsigned int file_off = *(unsigned int*)(sections + 20);
      unsigned int filesz = *(unsigned int*)(sections + 16);
      uc->map_mem_zero(vaddr & ~0xfff, (vaddr + vsize + 0xfff) & ~0xfff, ida_to_uc_perms_map_win[perms]);
      if (filesz) {
         msg("Copying bytes 0x%x:0x%x into block\n", file_off, file_off + filesz);
         uc_err err = uc_mem_write(uc->uc, vaddr, file_off + (char*)img, filesz);
      }
      sections += 40;
   }

   //PE stack
   unsigned int stack_top = 0x130000;
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE);

   stack_top -= 16;
   uc->set_sp(stack_top);

   return true;
}

bool loadElf64(sk3wldbg *uc, void *img, uint64_t sz) {
   Elf64_Ehdr *elf = (Elf64_Ehdr*)img;
   if (memcmp(elf->e_ident, "\x7f" "ELF", 4) != 0) {
      msg("bad ELF magic: 0x%x\n", *(uint32_t*)elf->e_ident);
      return false;
   }
   if (elf->e_phoff > (sz - sizeof(Elf64_Phdr))) {
      msg("bad e_phoff\n");
      return false;
   }
   Elf64_Phdr *phdr = (Elf64_Phdr*)(elf->e_phoff + (char*)img);
   for (uint16_t i = 0; i < elf->e_phnum; i++) {
      msg("phdr->p_type: %d\n", phdr->p_type);
      if (phdr->p_type == PT_LOAD) {
         uint64_t begin = phdr->p_vaddr & ~0xfff;
         uint64_t end = (phdr->p_vaddr + phdr->p_memsz + 0xfff) & ~0xfff;
         msg("ELF64 loader mapping 0x%llx bytes at 0x%llx, from file offset 0x%llx\n", (uint64_t)phdr->p_memsz,
             (uint64_t)phdr->p_vaddr, (uint64_t)phdr->p_offset);
         uc->map_mem_zero(begin, end, ida_to_uc_perms_map[phdr->p_flags & 7]);
         uint64_t offset = phdr->p_offset & ~0xfff;
         uint64_t endoff = (phdr->p_offset + phdr->p_filesz + 0xfff) & ~0xfff;
         if (endoff > sz) {
            endoff = phdr->p_offset + phdr->p_filesz;
         }
         msg("Copying bytes 0x%llx:0x%llx into block\n", (uint64_t)offset, (uint64_t)endoff);
         uc_err err = uc_mem_write(uc->uc, begin, offset + (char*)img, (size_t)(endoff - offset));
         if (err != UC_ERR_OK) {
            msg("uc_mem_write failed with error: %d\n", err);
         }
      }
      phdr++;
   }   

   //ELF stack
   uint64_t stack_top = 0x7ffffffff000ll;
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE);

   stack_top -= 16;
   uc->set_sp(stack_top);

   return true;
}

bool loadElf32(sk3wldbg *uc, void *img, size_t sz) {
   ELF32_Ehdr *elf = (ELF32_Ehdr*)img;
   if (memcmp(elf->e_ident, "\x7f" "ELF", 4) != 0) {
      msg("bad ELF magic: 0x%x\n", *(uint32_t*)elf->e_ident);
      return false;
   }
   if (elf->e_phoff > (sz - sizeof(ELF32_Phdr))) {
      msg("bad e_phoff\n");
      return false;
   }
   ELF32_Phdr *phdr = (ELF32_Phdr*)(elf->e_phoff + (char*)img);
   for (uint16_t i = 0; i < elf->e_phnum; i++) {
      msg("phdr->p_type: %d\n", phdr->p_type);
      if (phdr->p_type == PT_LOAD) {
         ea_t begin = phdr->p_vaddr & ~0xfff;
         ea_t end = (phdr->p_vaddr + phdr->p_memsz + 0xfff) & ~0xfff;
         msg("ELF32 loader mapping 0x%x bytes at 0x%x, from file offset 0x%x\n", phdr->p_memsz, phdr->p_vaddr, phdr->p_offset);
         uc->map_mem_zero(begin, end, ida_to_uc_perms_map[phdr->p_flags & 7]);
         size_t offset = phdr->p_offset & ~0xfff;
         size_t endoff = (phdr->p_offset + phdr->p_filesz + 0xfff) & ~0xfff;
         if (endoff > sz) {
            endoff = phdr->p_offset + phdr->p_filesz;
         }
         msg("Copying bytes 0x%llx:0x%llx into block\n", (uint64_t)offset, (uint64_t)endoff);
         uc_err err = uc_mem_write(uc->uc, begin, offset + (char*)img, endoff - offset);
         if (err != UC_ERR_OK) {
            msg("uc_mem_write failed with error: %d\n", err);
         }
      }
      phdr++;
   }   

   //ELF stack
   unsigned int stack_top = 0xC0000000;
   uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE);

   stack_top -= 16;
   uc->set_sp(stack_top);

   return true;
}

bool loadImage(sk3wldbg *uc, void *img, size_t sz) {
   bool result = false;
   switch (uc->filetype) {
      case f_PE:
         if (inf.lflags & LFLG_64BIT) {
            msg("loadPE64\n");
            result = loadPE64(uc, img, sz);
         }
         else {
            msg("loadPE32\n");
            result = loadPE32(uc, img, sz);
         }
         break;
      case f_ELF:
         if (inf.lflags & LFLG_64BIT) {
            msg("loadElf64\n");
            result = loadElf64(uc, img, (uint64_t)sz);
         }
         else {
            msg("loadElf32\n");
            result = loadElf32(uc, img, sz);
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
