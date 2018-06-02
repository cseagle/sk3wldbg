#ifndef __ELF_LOCAL
#define __ELF_LOCAL

#include <stdint.h>

struct Elf32_Ehdr {
   uint8_t  e_ident[16];
#define ELF_IDENT  "\177ELF\x01\x01\x01"
#define EI_DATA 5           // endian-ness   1 == little-endian, 2 == big-endian
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

enum ptype {
   PT_NULL,
   PT_LOAD,
   PT_DYNAMIC,
   PT_INTERP,
   PT_NOTE,
   PT_SHLIB,
   PT_PHDR,
   PT_TLS,
   PT_NUM
};

struct Elf32_Phdr {
   uint32_t        p_type;         /* Section type */

#define PT_LOOS      0x60000000
#define PT_HIOS      0x6fffffff
#define PT_LOPROC    0x70000000
#define PT_HIPROC    0x7fffffff
#define PT_GNU_STACK (PT_LOOS + 0x474e551)

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

#endif
