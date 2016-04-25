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

static const char *x86_register_classes[] = {
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

static const char *flag_bits[32] = {
   "CF", NULL, "PF", NULL, "AF", NULL, "ZF", "SF", "TF", "IF", "DF", "OF",
   "IOPL", "IOPL", "NT", NULL, "RF", "VM", "AC", "VIF", "VIP", "ID"
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

sk3wldbg_x86_32::sk3wldbg_x86_32() : sk3wldbg("metapc", UC_ARCH_X86, UC_MODE_32) {
   //reset any overridden function pointers and setup register name fields

   register_classes = x86_register_classes;
   register_classes_default = X86_GENERAL;  ///< Mask of default printed register classes
   _registers = x86_regs;                ///< Array of registers. Use registers() to access it
   registers_size = qnumber(x86_regs);   ///< Number of registers
   reg_map = x86_reg_map;
   bpt_bytes = (const uchar *)"\xcc";    ///< Array of bytes for a breakpoint instruction
   bpt_size = 1;                         ///< Size of this array

}

bool sk3wldbg_x86_32::save_ret_addr(uint64_t retaddr) {
   uint64_t new_sp = get_sp() - sizeof(uint32_t);
   uc_mem_write(uc, new_sp, &retaddr, sizeof(uint32_t));
   set_sp(new_sp);
   return true;
}

void x86_32_bkpt(uc_engine *uc, sk3wldbg_x86_32 *dbg) {
   uc_emu_stop(uc);
   dbg->emu_state = RS_PAUSE;
   debug_event_t brk;
   brk.eid = BREAKPOINT;
   brk.pid = dbg->the_process;
   brk.tid = dbg->the_threads.front();
   brk.ea = (ea_t)dbg->get_pc();
   msg("x86 breakpoint hit at: 0x%llx\n", (uint64_t)brk.ea);
   brk.handled = true;
   brk.bpt.hea = brk.bpt.kea = brk.ea;
   dbg->enqueue_debug_evt(brk);
}

void x86_32_code_hook(uc_engine *uc, uint64_t address, uint32_t /*size*/, sk3wldbg_x86_32 *dbg) {
   static uint64_t last_pc;
//   msg("x86 code hit at: 0x%llx\n", address);
   if (last_pc != address && dbg->breakpoints.find((ea_t)address) != dbg->breakpoints.end()) {
      uc_emu_stop(uc);
//      dbg->emu_state = RS_PAUSE;
      dbg->queue_dbg_event(false);
   }
   last_pc = address;
}

void x86_32_trace(uc_engine * /*uc*/, uint64_t /*address*/, uint32_t /*size*/, void *user_data) {
   sk3wldbg_x86_32 *emu = (sk3wldbg_x86_32*)user_data;
   //record trace data and continue?
   //might need to check for breakpoints in here if other methods fail
}

/*
void sk3wldbg_x86_32::install_initial_hooks() {
   uc_hook hh;
   uc_err err = uc_hook_add(uc, &hh, UC_HOOK_CODE, x86_32_code_hook, this, 1, 0);
   if (err) {
      msg("Failed on uc_hook_add(x86_32_code_hook) with error returned: %u\n", err);
   }
}
*/

sk3wldbg_x86_64::sk3wldbg_x86_64() : sk3wldbg("metapc", UC_ARCH_X86, UC_MODE_64) {
   //reset any overridden function pointers and setup register name fields

   register_classes = x86_register_classes;
   register_classes_default = X86_GENERAL;  ///< Mask of default printed register classes
   _registers = x64_regs;                ///< Array of registers. Use registers() to access it
   registers_size = qnumber(x64_regs);   ///< Number of registers
   reg_map = x64_reg_map;
   bpt_bytes = (const uchar *)"\xcc";  ///< Array of bytes for a breakpoint instruction
   bpt_size = 1;                    ///< Size of this array

}

bool sk3wldbg_x86_64::save_ret_addr(uint64_t retaddr) {
   uint64_t new_sp = get_sp() - sizeof(uint64_t);
   uc_mem_write(uc, new_sp, &retaddr, sizeof(uint64_t));
   set_sp(new_sp);
   return true;
}
