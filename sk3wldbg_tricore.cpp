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

#include "sk3wldbg_tricore.h"

static const char *tricore_regclasses[] = {
   "General registers",
   "Floating point registers",
   NULL
};

enum TricoreRegClass {
   TRICORE_GENERAL = 1,
   TRICORE_FPU = 2
};

static const char* tricore_flags[] = {
  "CR0", "CR0", "CR0", "CR0",
  "CR1", "CR1", "CR1", "CR1",
  "CR2", "CR2", "CR2", "CR2",
  "CR3", "CR3", "CR3", "CR3",
  "CR4", "CR4", "CR4", "CR4",
  "CR5", "CR5", "CR5", "CR5",
  "CR6", "CR6", "CR6", "CR6",
  "CR7", "CR7", "CR7", "CR7"
};

static const char* tricore_xer_flags[] = {
  "SO", "OV", "CA", NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL,
  NULL, NULL,
  "COUNT", "COUNT", "COUNT", "COUNT", "COUNT"
};

static const char* TRICORE_FPU_flags[] = {
  "FX", "FEX", "VX", "OX",
  "UX", "ZX", "XX", "VXSNAN",
  "VXISI", "VXIDI", "VXZDZ", "VXIMZ",
  "VXVC", "FR", "FI", "FPRF",
  "FPRF", "FPRF", "FPRF", "FPRF",
  NULL, "VXSOFT", "VXSQRT", "VXCVI",
  "VE", "OE", "UE", "ZE",
  "XE", "NI", "RN", "RN"
};

static struct register_info_t tricore_regs[] = {
   {"d0", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d1", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d2", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d3", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d4", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d5", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d6", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d7", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d8", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d9", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d10", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d11", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d12", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d13", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d14", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d15", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a0", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a1", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a2", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a3", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a4", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a5", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a6", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a7", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a8", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a9", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"sp", REGISTER_SP | REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a11", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},    // link register
   {"a12", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a13", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a14", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a15", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"pc", REGISTER_IP | REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"psw", 0, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"pcxi", 0, TRICORE_GENERAL, dt_dword, NULL, 0},
/*
   {"e0", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"e2", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"e4", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"e6", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"e8", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"e10", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"e12", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"e14", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a0/a1", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a2/a3", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a4/a5", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a6/a7", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a8/a9", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a10/a11", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a12/a13", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"a14/a15", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d0l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d1l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d2l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d3l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d4l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d5l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d6l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d7l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d8l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d9l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d10l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d11l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d12l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d13l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d14l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d15l", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d0u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d1u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d2u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d3u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d4u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d5u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d6u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d7u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d8u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d9u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d10u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d11u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d12u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d13u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d14u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d15u", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d0ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d1ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d2ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d3ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d4ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d5ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d6ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d7ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d8ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d9ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d10ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d11ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d12ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d13ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d14ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d15ll", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d0lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d1lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d2lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d3lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d4lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d5lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d6lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d7lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d8lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d9lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d10lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d11lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d12lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d13lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d14lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d15lu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d0ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d1ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d2ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d3ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d4ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d5ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d6ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d7ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d8ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d9ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d10ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d11ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d12ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d13ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d14ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d15ul", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d0uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d1uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d2uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d3uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d4uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d5uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d6uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d7uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d8uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d9uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d10uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d11uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d12uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d13uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d14uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
   {"d15uu", REGISTER_ADDRESS, TRICORE_GENERAL, dt_dword, NULL, 0},
*/
};

#define tricore_LR 27

sk3wldbg_tricore::sk3wldbg_tricore() : sk3wldbg("TRICORE", UC_ARCH_TRICORE, UC_MODE_32) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "TRICORE";
   }

   regclasses = tricore_regclasses;
   default_regclasses = TRICORE_GENERAL;    ///< Mask of default printed register classes
   registers = tricore_regs;               ///< Array of registers. Use registers() to access it
   nregs = qnumber(tricore_regs);  ///< Number of registers
//   reg_map = tricore_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

bool sk3wldbg_tricore::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[tricore_LR], &retaddr);
   return true;
}

