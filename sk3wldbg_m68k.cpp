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

#include "sk3wldbg_m68k.h"

static const char *m68k_register_classes[] = {
   "General registers",
   NULL
};

enum M68kRegClass {
   M68K_GENERAL = 1
};

static const char* m68k_flags[] = {
  "C", "V", "Z", "N", "X", NULL, NULL, NULL,
  "I", "I", "I", NULL, "M", "S", "T", "T"
};

static struct register_info_t m68k_regs[] = {
   {"D0", 0, M68K_GENERAL, dt_dword, NULL, 0},
   {"D1", 0, M68K_GENERAL, dt_dword, NULL, 0},
   {"D2", 0, M68K_GENERAL, dt_dword, NULL, 0},
   {"D3", 0, M68K_GENERAL, dt_dword, NULL, 0},
   {"D4", 0, M68K_GENERAL, dt_dword, NULL, 0},
   {"D5", 0, M68K_GENERAL, dt_dword, NULL, 0},
   {"D6", 0, M68K_GENERAL, dt_dword, NULL, 0},
   {"D7", 0, M68K_GENERAL, dt_dword, NULL, 0},
   {"A0", REGISTER_ADDRESS, M68K_GENERAL, dt_dword, NULL, 0},
   {"A1", REGISTER_ADDRESS, M68K_GENERAL, dt_dword, NULL, 0},
   {"A2", REGISTER_ADDRESS, M68K_GENERAL, dt_dword, NULL, 0},
   {"A3", REGISTER_ADDRESS, M68K_GENERAL, dt_dword, NULL, 0},
   {"A4", REGISTER_ADDRESS, M68K_GENERAL, dt_dword, NULL, 0},
   {"A5", REGISTER_ADDRESS, M68K_GENERAL, dt_dword, NULL, 0},
   {"A6", REGISTER_ADDRESS, M68K_GENERAL, dt_dword, NULL, 0},
   {"SP", REGISTER_ADDRESS | REGISTER_SP, M68K_GENERAL, dt_dword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, M68K_GENERAL, dt_dword, NULL, 0},
   {"CCR", 0, M68K_GENERAL, dt_word, m68k_flags, 0xF71F},
};

static int32_t m68k_reg_map[] = {
   UC_M68K_REG_D0, UC_M68K_REG_D1, UC_M68K_REG_D2, UC_M68K_REG_D3, UC_M68K_REG_D4,
   UC_M68K_REG_D5, UC_M68K_REG_D6, UC_M68K_REG_D7, UC_M68K_REG_A0,
   UC_M68K_REG_A1, UC_M68K_REG_A2, UC_M68K_REG_A3, UC_M68K_REG_A3,
   UC_M68K_REG_A4, UC_M68K_REG_A5, UC_M68K_REG_A6, UC_M68K_REG_A7,
   UC_M68K_REG_PC, UC_M68K_REG_SR
};

sk3wldbg_m68k::sk3wldbg_m68k() : sk3wldbg("68000", UC_ARCH_M68K, UC_MODE_32) {
   //reset any overridden function pointers and setup register name fields

   register_classes = m68k_register_classes;
   register_classes_default = 1;    ///< Mask of default printed register classes
   _registers = m68k_regs;               ///< Array of registers. Use registers() to access it
   registers_size = qnumber(m68k_regs);  ///< Number of registers
   reg_map = m68k_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array
}

bool sk3wldbg_m68k::save_ret_addr(uint64_t retaddr) {
   uint64_t new_sp = get_sp() - sizeof(uint32_t);
   uc_mem_write(uc, new_sp, &retaddr, sizeof(uint32_t));
   set_sp(new_sp);
   return true;
}
