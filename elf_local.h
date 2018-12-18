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

/* from linux/auxvec.h */
#define _AT_NULL   0     /* end of vector */
#define _AT_IGNORE 1     /* entry should be ignored */
#define _AT_EXECFD 2     /* file descriptor of program */
#define _AT_PHDR   3     /* program headers for program */
#define _AT_PHENT  4     /* size of program header entry */
#define _AT_PHNUM  5     /* number of program headers */
#define _AT_PAGESZ 6     /* system page size */
#define _AT_BASE   7     /* base address of interpreter */
#define _AT_FLAGS  8     /* flags */
#define _AT_ENTRY  9     /* entry point of program */
#define _AT_NOTELF 10    /* program is not ELF */
#define _AT_UID    11    /* real uid */
#define _AT_EUID   12    /* effective uid */
#define _AT_GID    13    /* real gid */
#define _AT_EGID   14    /* effective gid */
#define _AT_PLATFORM 15  /* string identifying CPU for optimizations */
#define _AT_HWCAP  16    /* arch dependent hints at CPU capabilities */
#define _AT_CLKTCK 17    /* frequency at which times() increments */
/* AT_* values 18 through 22 are reserved */
#define _AT_SECURE 23   /* secure mode boolean */
#define _AT_BASE_PLATFORM 24     /* string identifying real platform, may
                                 * differ from AT_PLATFORM. */
#define _AT_RANDOM 25    /* address of 16 random bytes */
#define _AT_HWCAP2 26    /* extension of AT_HWCAP */

#define _AT_EXECFN  31   /* filename of program */

#define _AT_SYSINFO_EHDR 33 /* base of vdso */

typedef struct _elf_aux {
   uint64_t entry;
   uint64_t vdso;
   uint64_t phdr;
   uint64_t phnum;
   uint64_t phent;
   uint32_t uid;
   uint32_t euid;
   uint32_t gid;
   uint32_t egid;
} elf_aux;

//altval indicies for kernel netnode
#define KERNEL_BRK 0
#define KERNEL_PID 1
#define KERNEL_PPID 2
#define KERNEL_UID 3
#define KERNEL_EUID 4
#define KERNEL_GID 5
#define KERNEL_EGID 6
#define KERNEL_TID 7
#define KERNEL_TID_ADDRESS 8
#define KERNEL_ROBUST_LIST 9
#define KERNEL_ROBUST_LIST_SIZE 10
#define KERNEL_MMAP_TOP 11




#endif
