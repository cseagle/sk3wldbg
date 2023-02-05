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

#include "sk3wldbg_x86.h"
#include <unicorn/x86.h>
#include <segment.hpp>

#define LINUX_X86_EXIT       1
#define LINUX_X86_FORK       2
#define LINUX_X86_READ       3
#define LINUX_X86_WRITE      4
#define LINUX_X86_OPEN       5
#define LINUX_X86_CLOSE      6
#define LINUX_X86_PTRACE     26
#define LINUX_X86_ALARM      27
#define LINUX_X86_BRK        42
#define LINUX_X86_SIGNAL     48
#define LINUX_X86_MMAP       90
#define LINUX_X86_MUNMAP     91
#define LINUX_X86_SOCKETCALL 102
#define LINUX_X86_MPROTECT   125
#define LINUX_X86_EXIT_GROUP 252

static const char *x86_regclasses[] = {
    "General registers",
    "Segment registers",
    "FPU registers",
    "MMX registers",
    "XMM registers",
    NULL
};

enum X86RegClass {
    X86_GENERAL = 1,
    X86_SEGMENT = 2,
    X86_FPU = 4,
    X86_MMX = 8,
    X86_XMM = 16
};

static const char *flag_bits_16[32] = {
    "CF", NULL, "PF", NULL, "AF", NULL, "ZF", "SF", "TF", "IF", "DF", "OF"
};

static const char *flag_bits[32] = {
    "CF", NULL, "PF", NULL, "AF", NULL, "ZF", "SF", "TF", "IF", "DF", "OF",
    "IOPL", "IOPL", "NT", NULL, "RF", "VM", "AC", "VIF", "VIP", "ID"
};

static struct register_info_t x86_16_regs[] = {
    {"EAX", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"ECX", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EDX", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EBX", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"ESP", REGISTER_SP | REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EBP", REGISTER_FP | REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"ESI", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EDI", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EIP", REGISTER_IP | REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EFL", 0, X86_GENERAL, dt_dword, flag_bits, 0xdd5},
    {"CS", REGISTER_CS, X86_SEGMENT, dt_word, NULL, 0},
    {"DS", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"SS", REGISTER_SS, X86_SEGMENT, dt_word, NULL, 0},
    {"ES", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"FS", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"GS", 0, X86_SEGMENT, dt_word, NULL, 0},
};

static int32_t x86_16_reg_map[] = {
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS, UC_X86_REG_CS, UC_X86_REG_DS,
    UC_X86_REG_SS, UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS
};

static struct register_info_t x86_regs[] = {
    {"EAX", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"ECX", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EDX", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EBX", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"ESP", REGISTER_SP | REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EBP", REGISTER_FP | REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"ESI", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EDI", REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EIP", REGISTER_IP | REGISTER_ADDRESS, X86_GENERAL, dt_dword, NULL, 0},
    {"EFL", 0, X86_GENERAL, dt_dword, flag_bits, 0xdd5},
    {"CS", REGISTER_CS, X86_SEGMENT, dt_word, NULL, 0},
    {"DS", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"SS", REGISTER_SS, X86_SEGMENT, dt_word, NULL, 0},
    {"ES", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"FS", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"GS", 0, X86_SEGMENT, dt_word, NULL, 0}
};

static int32_t x86_reg_map[] = {
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS, UC_X86_REG_CS, UC_X86_REG_DS,
    UC_X86_REG_SS, UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS
};

static struct register_info_t x64_regs[] = {
    {"RAX", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"RCX", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"RDX", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"RBX", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"RSP", REGISTER_SP | REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"RBP", REGISTER_FP | REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"RSI", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"RDI", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"R8", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"R9", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"R10", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"R11", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"R12", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"R13", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"R14", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"R15", REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"RIP", REGISTER_IP | REGISTER_ADDRESS, X86_GENERAL, dt_qword, NULL, 0},
    {"EFL", 0, X86_GENERAL, dt_dword, flag_bits, 0xdd5},
    {"CS", REGISTER_CS, X86_SEGMENT, dt_word, NULL, 0},
    {"DS", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"SS", REGISTER_SS, X86_SEGMENT, dt_word, NULL, 0},
    {"ES", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"FS", 0, X86_SEGMENT, dt_word, NULL, 0},
    {"GS", 0, X86_SEGMENT, dt_word, NULL, 0},
};

static int32_t x64_reg_map[] = {
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
    UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP, UC_X86_REG_EFLAGS, UC_X86_REG_CS, UC_X86_REG_DS,
    UC_X86_REG_SS, UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS
};

sk3wldbg_x86_16::sk3wldbg_x86_16(void) : sk3wldbg("metapc", UC_ARCH_X86, UC_MODE_16) {
    //reset any overridden function pointers and setup register name fields
    regclasses = x86_regclasses;
    default_regclasses = X86_GENERAL;  ///< Mask of default printed register classes
    registers = x86_16_regs;                ///< Array of registers. Use registers() to access it
    nregs = qnumber(x86_16_regs);   ///< Number of registers
    reg_map = x86_16_reg_map;
    bpt_bytes = (const uchar *)"\xcc";  ///< Array of bytes for a breakpoint instruction
    bpt_size = 1;                    ///< Size of this array

    flags |= DBG_FLAG_USE_SREGS;
}

bool sk3wldbg_x86_16::save_ret_addr(uint64_t retaddr) {
    uint64_t new_sp = get_sp() - sizeof(uint16_t);
    uc_mem_write(uc, new_sp, &retaddr, sizeof(uint64_t));
    set_sp(new_sp);
    return true;
}

bool sk3wldbg_x86_16::set_pc(uint64_t pc) {
    segment_t *s = getseg(pc);
    if (s) {
        uint32_t offset = (uint16_t)(pc - s->sel * 16);
        uint16_t cs = (uint16_t)s->sel;
        uc_err err = uc_reg_write(uc, UC_X86_REG_CS, &cs);
        if (err != UC_ERR_OK) {
            return false;
        }
        err = uc_reg_write(uc, UC_X86_REG_EIP, &offset);
        if (err != UC_ERR_OK) {
            return false;
        }
        msg("set_pc: 0x%x:0x%x\n", cs, offset);
        return true;
    } else {
        msg("Attempting to set PC outside of any segment: %p\n", (void*)pc);
    }
    return false;    
}

// Unicorn is broken in 16-bit mode and may return an offset OR a linear address
// when querying EIP depending on the context from which reg_read is called
uint64_t sk3wldbg_x86_16::get_pc(void) {
    uint64_t pc;
    uint32_t offset;
    uint16_t cs;
    qstring msgbuf;
    
    uc_err err = uc_reg_read(uc, UC_X86_REG_CS, &cs);
    if (err != UC_ERR_OK) {
        return -1ll;
    }
    err = uc_reg_read(uc, UC_X86_REG_EIP, &offset);
    if (err != UC_ERR_OK) {
        return -1ll;
    }
    if (which_hook == UC_HOOK_CODE) {
        pc = offset;
    } else {
        pc = cs;
        pc = pc * 16 + offset;    
    }
    msg("get_pc: 0x%x:0x%x (%p)\n", cs, offset, pc);
    return pc;
}

void sk3wldbg_x86_16::init_session(void) {
    dos_irq_table.clear();
}

void sk3wldbg_x86_16::handle_dos_int21(void) {
    uint8_t al;
    uint8_t ah;
    uint16_t ax;
    uint16_t ds;
    uint16_t dx;
    uint32_t tmp;
    ea_t addr;
    uc_reg_read(uc, UC_X86_REG_AH, &ah);
    switch (ah) {
        case 0x25: //set interrupt vector
            uc_reg_read(uc, UC_X86_REG_AL, &al);
            uc_reg_read(uc, UC_X86_REG_DS, &ds);
            uc_reg_read(uc, UC_X86_REG_DX, &dx);
            tmp = ds;
            dos_irq_table[al] = dx | tmp << 16;
            break;
        case 0x30: //get version
            ax = 5;
            uc_reg_write(uc, UC_X86_REG_AX, &ax);
            break;
        case 0x35: //get interrupt vector
            uc_reg_read(uc, UC_X86_REG_AL, &al);
            if (dos_irq_table.find(al) != dos_irq_table.end()) {
                tmp = dos_irq_table[al];
                dx = tmp;
                ds = tmp >> 16;
            } else {
                dx = ds = 0;
            }
            uc_reg_write(uc, UC_X86_REG_ES, &ds);
            uc_reg_write(uc, UC_X86_REG_BX, &dx);
            break;
        case 0x4a: //adjust memory block size
            break;
        case 0x4c: //exit
            uc_emu_stop(uc);
            break;
        default:
            msg("%p: Unhandled dos int 0x21 AH:0x%x\n", get_pc(), ah);
            break;
    }
}

void sk3wldbg_x86_16::intr_hook(uint32_t intno) {
    if (filetype == f_EXE && intno == 0x21) {
        //minimal emulation of dos int 0x21
        handle_dos_int21();
    }
}

sk3wldbg_x86_32::sk3wldbg_x86_32(void) : sk3wldbg("metapc", UC_ARCH_X86, UC_MODE_32) {
    //reset any overridden function pointers and setup register name fields

    regclasses = x86_regclasses;
    default_regclasses = X86_GENERAL;  ///< Mask of default printed register classes
    registers = x86_regs;                ///< Array of registers. Use registers() to access it
    nregs = qnumber(x86_regs);   ///< Number of registers
    reg_map = x86_reg_map;
    bpt_bytes = (const uchar *)"\xcc";    ///< Array of bytes for a breakpoint instruction
    bpt_size = 1;                         ///< Size of this array

    flags |= DBG_FLAG_USE_SREGS;
}

bool sk3wldbg_x86_32::save_ret_addr(uint64_t retaddr) {
    uint64_t new_sp = get_sp() - sizeof(uint32_t);
    uc_mem_write(uc, new_sp, &retaddr, sizeof(uint32_t));
    set_sp(new_sp);
    return true;
}

bool sk3wldbg_x86_32::is_system_call(uint8_t *inst, uint32_t size) {
    //need to check OS flavor
    if (size == 2 && 0x80cd == *(uint16_t*)inst) {
        return true;
    }
    return false;
}

void sk3wldbg_x86_32::handle_system_call(uint8_t *inst, uint32_t size) {
    //need to check OS flavor
    if (size == 2 && 0x80cd == *(uint16_t*)inst) {
        uint32_t eax;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        switch (eax) {
            case LINUX_X86_EXIT:
                uc_emu_stop(uc);
                break;
            case LINUX_X86_FORK:
                break;
            case LINUX_X86_READ:
                break;
            case LINUX_X86_WRITE:
                break;
            case LINUX_X86_OPEN:
                break;
            case LINUX_X86_CLOSE:
                break;
            case LINUX_X86_PTRACE:
                break;
            case LINUX_X86_ALARM:
                break;
            case LINUX_X86_BRK:
                break;
            case LINUX_X86_SIGNAL:
                break;
            case LINUX_X86_MMAP:
                break;
            case LINUX_X86_MUNMAP:
                break;
            case LINUX_X86_SOCKETCALL:
                break;
            case LINUX_X86_MPROTECT:
                break;
            case LINUX_X86_EXIT_GROUP:
                break;
            default:
                break;
        }
    }
}

void x86_32_bkpt(uc_engine *uc, sk3wldbg_x86_32 *dbg) {
    uc_emu_stop(uc);
    dbg->emu_state = RS_PAUSE;
    debug_event_t brk;

    brk.set_eid(::BREAKPOINT);
    bptaddr_t &bpt = brk.bpt();

    brk.pid = dbg->the_process;
    brk.tid = dbg->the_threads.front();
    brk.ea = (ea_t)dbg->get_pc();
    msg("x86 breakpoint hit at: %p\n", (uint64_t)brk.ea);
    brk.handled = true;
    bpt.hea = bpt.kea = brk.ea;
    dbg->enqueue_debug_evt(brk);
}

void x86_32_code_hook(uc_engine *uc, uint64_t address, uint32_t /*size*/, sk3wldbg_x86_32 *dbg) {
    static uint64_t last_pc;
//   msg("x86 code hit at: %p\n", address);
    if (last_pc != address && dbg->breakpoints.find((ea_t)address) != dbg->breakpoints.end()) {
        uc_emu_stop(uc);
//        dbg->emu_state = RS_PAUSE;
        dbg->queue_bpt_event(false);
    }
    last_pc = address;
}

void x86_32_trace(uc_engine * /*uc*/, uint64_t /*address*/, uint32_t /*size*/, void *user_data) {
    sk3wldbg_x86_32 *emu = (sk3wldbg_x86_32*)user_data;
    //record trace data and continue?
    //might need to check for breakpoints in here if other methods fail
}

/*
void sk3wldbg_x86_32::install_initial_hooks(void) {
    uc_hook hh;
    uc_err err = uc_hook_add(uc, &hh, UC_HOOK_CODE, x86_32_code_hook, this, 1, 0);
    if (err) {
        msg("Failed on uc_hook_add(x86_32_code_hook) with error returned: %u\n", err);
    }
}
*/

sk3wldbg_x86_64::sk3wldbg_x86_64(void) : sk3wldbg("metapc", UC_ARCH_X86, UC_MODE_64) {
    //reset any overridden function pointers and setup register name fields
    regclasses = x86_regclasses;
    default_regclasses = X86_GENERAL;  ///< Mask of default printed register classes
    registers = x64_regs;                ///< Array of registers. Use registers() to access it
    nregs = qnumber(x64_regs);   ///< Number of registers
    reg_map = x64_reg_map;
    bpt_bytes = (const uchar *)"\xcc";  ///< Array of bytes for a breakpoint instruction
    bpt_size = 1;                    ///< Size of this array

    flags |= DBG_FLAG_USE_SREGS;
}

bool sk3wldbg_x86_64::save_ret_addr(uint64_t retaddr) {
    uint64_t new_sp = get_sp() - sizeof(uint64_t);
    uc_mem_write(uc, new_sp, &retaddr, sizeof(uint64_t));
    set_sp(new_sp);
    return true;
}
