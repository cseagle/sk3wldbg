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

#include "sk3wldbg_ppc.h"

static const char *ppc_register_classes[] = {
   "General registers",
   "Floating point registers",
   NULL
};

enum PpcRegClass {
   PPC_GENERAL = 1,
   PPC_FPU = 2
};

static const char* ppc_flags[] = {
  "CR0", "CR0", "CR0", "CR0",
  "CR1", "CR1", "CR1", "CR1",
  "CR2", "CR2", "CR2", "CR2",
  "CR3", "CR3", "CR3", "CR3",
  "CR4", "CR4", "CR4", "CR4",
  "CR5", "CR5", "CR5", "CR5",
  "CR6", "CR6", "CR6", "CR6",
  "CR7", "CR7", "CR7", "CR7"
};

static const char* ppc_xer_flags[] = {
  "SO", "OV", "CA", NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL,
  "COUNT", "COUNT", "COUNT", "COUNT", "COUNT"
};

static const char* ppc_fpu_flags[] = {
  "FX", "FEX", "VX", "OX",
  "UX", "ZX", "XX", "VXSNAN",
  "VXISI", "VXIDI", "VXZDZ", "VXIMZ",
  "VXVC", "FR", "FI", "FPRF",
  "FPRF", "FPRF", "FPRF", "FPRF",
  NULL, "VXSOFT", "VXSQRT", "VXCVI",
  "VE", "OE", "UE", "ZE",
  "XE", "NI", "RN", "RN"
};

static struct register_info_t ppc_regs[] = {
   {"GPR0", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR1", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR2", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR3", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR4", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR5", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR6", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR7", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR8", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR9", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR10", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR11", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR12", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR13", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR14", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR15", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR16", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR17", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR18", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR19", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR20", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR21", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR22", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR23", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR24", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR25", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR26", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR27", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR28", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR29", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR30", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"GPR31", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"FPR0", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR1", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR2", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR3", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR4", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR5", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR6", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR7", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR8", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR9", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR10", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR11", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR12", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR13", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR14", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR15", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR16", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR17", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR18", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR19", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR20", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR21", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR22", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR23", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR24", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR25", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR26", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR27", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR28", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR29", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR30", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR31", 0, PPC_FPU, dt_double, NULL, 0},
   {"LR", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"CTR", REGISTER_ADDRESS, PPC_GENERAL, dt_dword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, PPC_GENERAL, dt_dword, NULL, 0},
   {"CR", 0, PPC_GENERAL, dt_dword, ppc_flags, 0xFFFFFFFF},
   {"XER", 0, PPC_GENERAL, dt_dword, ppc_xer_flags, 0xF8000007},
   {"FPSCR", 0, PPC_FPU, dt_dword, ppc_fpu_flags, 0xFFEFFFFF},
};

#define PPC_LR 64

static struct register_info_t ppc_regs64[] = {
   {"GPR0", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR1", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR2", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR3", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR4", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR5", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR6", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR7", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR8", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR9", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR10", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR11", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR12", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR13", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR14", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR15", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR16", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR17", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR18", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR19", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR20", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR21", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR22", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR23", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR24", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR25", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR26", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR27", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR28", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR29", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR30", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"GPR31", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"FPR0", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR1", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR2", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR3", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR4", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR5", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR6", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR7", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR8", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR9", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR10", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR11", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR12", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR13", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR14", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR15", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR16", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR17", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR18", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR19", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR20", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR21", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR22", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR23", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR24", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR25", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR26", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR27", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR28", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR29", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR30", 0, PPC_FPU, dt_double, NULL, 0},
   {"FPR31", 0, PPC_FPU, dt_double, NULL, 0},
   {"LR", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"CTR", REGISTER_ADDRESS, PPC_GENERAL, dt_qword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, PPC_GENERAL, dt_qword, NULL, 0},
   {"CR", 0, PPC_GENERAL, dt_dword, ppc_flags, 0xFFF03FFF},
   {"XER", 0, PPC_GENERAL, dt_dword, ppc_xer_flags, 0xF8000007},
   {"FPSCR", 0, PPC_FPU, dt_dword, ppc_fpu_flags, 0xFFEFFFFF},
};

#define PPC64_LR 64

sk3wldbg_ppc::sk3wldbg_ppc() : sk3wldbg("PPCL", UC_ARCH_PPC, UC_MODE_32) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "PPC";
   }

   register_classes = ppc_register_classes;
   register_classes_default = PPC_GENERAL;    ///< Mask of default printed register classes
   _registers = ppc_regs;               ///< Array of registers. Use registers() to access it
   registers_size = qnumber(ppc_regs);  ///< Number of registers
//   reg_map = ppc_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_ppc::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[PPC_LR], &retaddr);
   return true;
}

sk3wldbg_ppc64::sk3wldbg_ppc64() : sk3wldbg("PPCL", UC_ARCH_PPC, UC_MODE_64) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "PPC";
   }

   register_classes = ppc_register_classes;
   register_classes_default = PPC_GENERAL;    ///< Mask of default printed register classes
   _registers = ppc_regs64;               ///< Array of registers. Use registers() to access it
   registers_size = qnumber(ppc_regs64);  ///< Number of registers
//   reg_map = ppc64_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_ppc64::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[PPC64_LR], &retaddr);
   return true;
}

