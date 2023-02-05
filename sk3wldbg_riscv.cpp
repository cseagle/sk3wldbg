/*
   Source for Sk3wlDbg IdaPro plugin
   Copyright (c) 2022 Chris Eagle

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

#include "sk3wldbg_riscv.h"

static const char *riscv_regclasses[] = {
   "General registers",
   "Floating point registers",
   NULL
};

enum riscvRegClass {
   RISCV_GENERAL = 1,
   RISCV_FPU = 2
};

static const char* riscv_flags[] = {
  "CR0", "CR0", "CR0", "CR0",
  "CR1", "CR1", "CR1", "CR1",
  "CR2", "CR2", "CR2", "CR2",
  "CR3", "CR3", "CR3", "CR3",
  "CR4", "CR4", "CR4", "CR4",
  "CR5", "CR5", "CR5", "CR5",
  "CR6", "CR6", "CR6", "CR6",
  "CR7", "CR7", "CR7", "CR7"
};

static const char* riscv_xer_flags[] = {
  "SO", "OV", "CA", NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL,
  "COUNT", "COUNT", "COUNT", "COUNT", "COUNT"
};

static const char* riscv_fpu_flags[] = {
  "FX", "FEX", "VX", "OX",
  "UX", "ZX", "XX", "VXSNAN",
  "VXISI", "VXIDI", "VXZDZ", "VXIMZ",
  "VXVC", "FR", "FI", "FPRF",
  "FPRF", "FPRF", "FPRF", "FPRF",
  NULL, "VXSOFT", "VXSQRT", "VXCVI",
  "VE", "OE", "UE", "ZE",
  "XE", "NI", "RN", "RN"
};

static struct register_info_t riscv_regs[] = {
   {"GPR0", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR1", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR2", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR3", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR4", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR5", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR6", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR7", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR8", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR9", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR10", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR11", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR12", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR13", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR14", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR15", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR16", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR17", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR18", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR19", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR20", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR21", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR22", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR23", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR24", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR25", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR26", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR27", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR28", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR29", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR30", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"GPR31", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"FPR0", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR1", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR2", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR3", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR4", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR5", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR6", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR7", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR8", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR9", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR10", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR11", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR12", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR13", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR14", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR15", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR16", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR17", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR18", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR19", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR20", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR21", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR22", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR23", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR24", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR25", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR26", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR27", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR28", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR29", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR30", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR31", 0, RISCV_FPU, dt_double, NULL, 0},
   {"LR", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"CTR", REGISTER_ADDRESS, RISCV_GENERAL, dt_dword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, RISCV_GENERAL, dt_dword, NULL, 0},
   {"CR", 0, RISCV_GENERAL, dt_dword, riscv_flags, 0xFFFFFFFF},
   {"XER", 0, RISCV_GENERAL, dt_dword, riscv_xer_flags, 0xF8000007},
   {"FPSCR", 0, RISCV_FPU, dt_dword, riscv_fpu_flags, 0xFFEFFFFF},
};

#define riscv_LR 64

static struct register_info_t riscv_regs64[] = {
   {"GPR0", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR1", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR2", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR3", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR4", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR5", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR6", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR7", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR8", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR9", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR10", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR11", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR12", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR13", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR14", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR15", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR16", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR17", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR18", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR19", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR20", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR21", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR22", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR23", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR24", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR25", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR26", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR27", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR28", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR29", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR30", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"GPR31", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"FPR0", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR1", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR2", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR3", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR4", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR5", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR6", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR7", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR8", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR9", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR10", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR11", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR12", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR13", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR14", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR15", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR16", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR17", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR18", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR19", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR20", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR21", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR22", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR23", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR24", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR25", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR26", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR27", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR28", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR29", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR30", 0, RISCV_FPU, dt_double, NULL, 0},
   {"FPR31", 0, RISCV_FPU, dt_double, NULL, 0},
   {"LR", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"CTR", REGISTER_ADDRESS, RISCV_GENERAL, dt_qword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, RISCV_GENERAL, dt_qword, NULL, 0},
   {"CR", 0, RISCV_GENERAL, dt_dword, riscv_flags, 0xFFF03FFF},
   {"XER", 0, RISCV_GENERAL, dt_dword, riscv_xer_flags, 0xF8000007},
   {"FPSCR", 0, RISCV_FPU, dt_dword, riscv_fpu_flags, 0xFFEFFFFF},
};

#define RISCV64_LR 64

sk3wldbg_riscv::sk3wldbg_riscv() : sk3wldbg("riscv", UC_ARCH_RISCV, UC_MODE_32) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "riscv";
   }

   regclasses = riscv_regclasses;
   default_regclasses = RISCV_GENERAL;    ///< Mask of default printed register classes
   registers = riscv_regs;               ///< Array of registers. Use registers() to access it
   nregs = qnumber(riscv_regs);  ///< Number of registers
//   reg_map = riscv_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_riscv::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[RISCV64_LR], &retaddr);
   return true;
}

sk3wldbg_riscv64::sk3wldbg_riscv64() : sk3wldbg("riscv", UC_ARCH_RISCV, UC_MODE_64) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "riscv";
   }

   regclasses = riscv_regclasses;
   default_regclasses = RISCV_GENERAL;    ///< Mask of default printed register classes
   registers = riscv_regs64;               ///< Array of registers. Use registers() to access it
   nregs = qnumber(riscv_regs64);  ///< Number of registers
//   reg_map = riscv64_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_riscv64::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[RISCV64_LR], &retaddr);
   return true;
}

