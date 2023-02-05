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

#include "sk3wldbg_mips.h"
#include <idp.hpp>

static const char *mips_regclasses[] = {
   "General registers",
   "Floating point registers",
   NULL
};

enum MipsRegClass {
   MIPS_GENERAL = 1,
   MIPS_FPU = 2
};

static struct register_info_t mips_regs[] = {
   {"zero", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"at", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"v0", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"v1", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"a0", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"a1", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"a2", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"a3", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t0", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t1", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t2", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t3", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t4", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t5", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t6", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t7", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"s0", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"s1", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"s2", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"s3", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"s4", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"s5", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"s6", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"s7", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t8", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"t9", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"k0", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"k1", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"gp", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"sp", REGISTER_SP | REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"fp", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"ra", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"FP0", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP1", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP2", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP3", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP4", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP5", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP6", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP7", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP8", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP9", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP10", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP11", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP12", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP13", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP14", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP15", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP16", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP17", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP18", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP19", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP20", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP21", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP22", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP23", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP24", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP25", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP26", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP27", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP28", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP29", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP30", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP31", 0, MIPS_FPU, dt_double, NULL, 0},
//   {"LR", REGISTER_ADDRESS, MIPS_GENERAL, dt_dword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, MIPS_GENERAL, dt_dword, NULL, 0}
};

#define MIPS_RA 31

static int32_t mips_reg_map[] = {
   UC_MIPS_REG_0, UC_MIPS_REG_1, UC_MIPS_REG_2, UC_MIPS_REG_3, UC_MIPS_REG_4,
   UC_MIPS_REG_5, UC_MIPS_REG_6, UC_MIPS_REG_7, UC_MIPS_REG_8,
   UC_MIPS_REG_9, UC_MIPS_REG_10, UC_MIPS_REG_11, UC_MIPS_REG_12,
   UC_MIPS_REG_13, UC_MIPS_REG_14, UC_MIPS_REG_15, UC_MIPS_REG_16, UC_MIPS_REG_17,
   UC_MIPS_REG_18, UC_MIPS_REG_19, UC_MIPS_REG_20, UC_MIPS_REG_21,
   UC_MIPS_REG_22, UC_MIPS_REG_23, UC_MIPS_REG_24, UC_MIPS_REG_25,
   UC_MIPS_REG_26, UC_MIPS_REG_27, UC_MIPS_REG_28,
   UC_MIPS_REG_SP, UC_MIPS_REG_FP, UC_MIPS_REG_RA,
   UC_MIPS_REG_F0, UC_MIPS_REG_F1, UC_MIPS_REG_F2, UC_MIPS_REG_F3, UC_MIPS_REG_F4,
   UC_MIPS_REG_F5, UC_MIPS_REG_F6, UC_MIPS_REG_F7, UC_MIPS_REG_F8,
   UC_MIPS_REG_F9, UC_MIPS_REG_F10, UC_MIPS_REG_F11, UC_MIPS_REG_F12,
   UC_MIPS_REG_F13, UC_MIPS_REG_F14, UC_MIPS_REG_F15, UC_MIPS_REG_F16, UC_MIPS_REG_F17,
   UC_MIPS_REG_F18, UC_MIPS_REG_F19, UC_MIPS_REG_F20, UC_MIPS_REG_F21,
   UC_MIPS_REG_F22, UC_MIPS_REG_F23, UC_MIPS_REG_F24, UC_MIPS_REG_F25,
   UC_MIPS_REG_F26, UC_MIPS_REG_F27, UC_MIPS_REG_F28, UC_MIPS_REG_F29,
   UC_MIPS_REG_F30, UC_MIPS_REG_F31,
   UC_MIPS_REG_PC
};

static struct register_info_t mips_regs64[] = {
   {"zero", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"at", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"v0", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"v1", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"a0", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"a1", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"a2", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"a3", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t0", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t1", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t2", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t3", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t4", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t5", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t6", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t7", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"s0", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"s1", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"s2", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"s3", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"s4", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"s5", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"s6", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"s7", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t8", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"t9", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"k0", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"k1", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"gp", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"sp", REGISTER_SP | REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"fp", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"ra", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"FP0", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP1", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP2", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP3", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP4", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP5", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP6", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP7", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP8", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP9", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP10", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP11", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP12", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP13", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP14", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP15", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP16", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP17", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP18", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP19", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP20", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP21", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP22", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP23", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP24", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP25", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP26", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP27", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP28", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP29", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP30", 0, MIPS_FPU, dt_double, NULL, 0},
   {"FP31", 0, MIPS_FPU, dt_double, NULL, 0},
//   {"LR", REGISTER_ADDRESS, MIPS_GENERAL, dt_qword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, MIPS_GENERAL, dt_qword, NULL, 0}
};

#define MIPS64_RA 31

static int32_t mips64_reg_map[] = {
   UC_MIPS_REG_0, UC_MIPS_REG_1, UC_MIPS_REG_2, UC_MIPS_REG_3, UC_MIPS_REG_4,
   UC_MIPS_REG_5, UC_MIPS_REG_6, UC_MIPS_REG_7, UC_MIPS_REG_8,
   UC_MIPS_REG_9, UC_MIPS_REG_10, UC_MIPS_REG_11, UC_MIPS_REG_12,
   UC_MIPS_REG_13, UC_MIPS_REG_14, UC_MIPS_REG_15, UC_MIPS_REG_16, UC_MIPS_REG_17,
   UC_MIPS_REG_18, UC_MIPS_REG_19, UC_MIPS_REG_20, UC_MIPS_REG_21,
   UC_MIPS_REG_22, UC_MIPS_REG_23, UC_MIPS_REG_24, UC_MIPS_REG_25,
   UC_MIPS_REG_26, UC_MIPS_REG_27, UC_MIPS_REG_28,
   UC_MIPS_REG_SP, UC_MIPS_REG_FP, UC_MIPS_REG_RA,
   UC_MIPS_REG_F0, UC_MIPS_REG_F1, UC_MIPS_REG_F2, UC_MIPS_REG_F3, UC_MIPS_REG_F4,
   UC_MIPS_REG_F5, UC_MIPS_REG_F6, UC_MIPS_REG_F7, UC_MIPS_REG_F8,
   UC_MIPS_REG_F9, UC_MIPS_REG_F10, UC_MIPS_REG_F11, UC_MIPS_REG_F12,
   UC_MIPS_REG_F13, UC_MIPS_REG_F14, UC_MIPS_REG_F15, UC_MIPS_REG_F16, UC_MIPS_REG_F17,
   UC_MIPS_REG_F18, UC_MIPS_REG_F19, UC_MIPS_REG_F20, UC_MIPS_REG_F21,
   UC_MIPS_REG_F22, UC_MIPS_REG_F23, UC_MIPS_REG_F24, UC_MIPS_REG_F25,
   UC_MIPS_REG_F26, UC_MIPS_REG_F27, UC_MIPS_REG_F28, UC_MIPS_REG_F29,
   UC_MIPS_REG_F30, UC_MIPS_REG_F31,
   UC_MIPS_REG_PC
};

sk3wldbg_mips::sk3wldbg_mips() : sk3wldbg("mipsl", UC_ARCH_MIPS, UC_MODE_MIPS32) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "mipsb";
   }

   regclasses = mips_regclasses;
   default_regclasses = MIPS_GENERAL;    ///< Mask of default printed register classes
   registers = mips_regs;               ///< Array of registers. Use registers() to access it
   nregs = qnumber(mips_regs);              ///< Number of registers
   reg_map = mips_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_mips::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[MIPS_RA], &retaddr);
   return true;
}

sk3wldbg_mips64::sk3wldbg_mips64() : sk3wldbg("mipsl", UC_ARCH_MIPS, UC_MODE_MIPS64) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "mipsb";
   }

   regclasses = NULL;
   default_regclasses = 0;    ///< Mask of default printed register classes
   registers = NULL;               ///< Array of registers. Use registers() to access it
   nregs = 0;              ///< Number of registers
   reg_map = mips64_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_mips64::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[MIPS64_RA], &retaddr);
   return true;
}
