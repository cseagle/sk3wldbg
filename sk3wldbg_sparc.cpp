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

#include "sk3wldbg_sparc.h"

static const char *sparc_register_classes[] = {
   "General registers",
   NULL
};

enum SparcRegClass {
   SPARC_GENERAL = 1
};

static const char* sparc_flags[] = {
  "CWP", "CWP", "CWP", "CWP", "CWP", "ET", "PS", "S", "PIL", "PIL", "PIL", "PIL",
  "EF", "EC", NULL, NULL, NULL, NULL, NULL, NULL, "C", "V", "Z", "N",
  "VER", "VER", "VER", "VER", "IMPL", "IMPL", "IMPL", "IMPL"
};

static struct register_info_t sparc_regs[] = {
   {"g0", 0, SPARC_GENERAL, dt_dword, NULL, 0},
   {"g1", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"g2", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"g3", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"g4", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"g5", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"g6", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"g7", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"o0", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"o1", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"o2", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"o3", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"o4", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"o5", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"sp", REGISTER_ADDRESS | REGISTER_SP, SPARC_GENERAL, dt_dword, NULL, 0},
   {"o7", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"l0", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"l1", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"l2", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"l3", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"l4", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"l5", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"l6", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"l7", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"i0", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"i1", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"i2", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"i3", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"i4", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"i5", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"fp", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"i7", REGISTER_ADDRESS, SPARC_GENERAL, dt_dword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, SPARC_GENERAL, dt_dword, NULL, 0},
   {"PSR", 0, SPARC_GENERAL, dt_dword, sparc_flags, 0xFFF03FFF},
};

#define SPARC_LR 15

static int32_t sparc_reg_map[] = {
   UC_SPARC_REG_G0, UC_SPARC_REG_G1, UC_SPARC_REG_G2, UC_SPARC_REG_G3,
   UC_SPARC_REG_G4, UC_SPARC_REG_G5, UC_SPARC_REG_G6, UC_SPARC_REG_G7,
   UC_SPARC_REG_O0, UC_SPARC_REG_O1, UC_SPARC_REG_O2, UC_SPARC_REG_O3,
   UC_SPARC_REG_O4, UC_SPARC_REG_O5, UC_SPARC_REG_SP, UC_SPARC_REG_O7,
   UC_SPARC_REG_L0, UC_SPARC_REG_L1, UC_SPARC_REG_L2, UC_SPARC_REG_L3,
   UC_SPARC_REG_L4, UC_SPARC_REG_L5, UC_SPARC_REG_L6, UC_SPARC_REG_L7,
   UC_SPARC_REG_I0, UC_SPARC_REG_I1, UC_SPARC_REG_I2, UC_SPARC_REG_I3,
   UC_SPARC_REG_I4, UC_SPARC_REG_I5, UC_SPARC_REG_FP, UC_SPARC_REG_I7,
   UC_SPARC_REG_PC, UC_SPARC_REG_ICC
};

#define sparc64_reg_map sparc_reg_map

sk3wldbg_sparc::sk3wldbg_sparc() : sk3wldbg("sparcl", UC_ARCH_SPARC, UC_MODE_32) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "sparcb";
   }

   register_classes = sparc_register_classes;
   register_classes_default = SPARC_GENERAL;    ///< Mask of default printed register classes
   _registers = sparc_regs;               ///< Array of registers. Use registers() to access it
   registers_size = qnumber(sparc_regs);  ///< Number of registers
   reg_map = sparc_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_sparc::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[SPARC_LR], &retaddr);
   return true;
}

sk3wldbg_sparc64::sk3wldbg_sparc64() : sk3wldbg("sparcl", UC_ARCH_SPARC, UC_MODE_64) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "sparcb";
   }

   register_classes = sparc_register_classes;
   register_classes_default = SPARC_GENERAL;    ///< Mask of default printed register classes
   _registers = sparc_regs;               ///< Array of registers. Use registers() to access it
   registers_size = qnumber(sparc_regs);  ///< Number of registers
   reg_map = sparc64_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_sparc64::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[SPARC_LR], &retaddr);
   return true;
}

