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

#include "sk3wldbg_arm.h"
#include <idp.hpp>
#include <segment.hpp>
#include <srarea.hpp>

static const char *arm_register_classes[] = {
   "General registers",
   NULL
};

enum ArmRegClass {
   ARM_GENERAL = 1
};

static const char* arm_flags[] = {
  "MODE", "MODE", "MODE", "MODE", "MODE", "T", "F", "I",
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  "Q", "V", "C", "Z", "N"
};

static struct register_info_t arm_regs[] = {
   {"R0", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R1", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R2", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R3", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R4", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R5", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R6", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R7", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R8", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R9", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R10", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R11", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"R12", REGISTER_ADDRESS, ARM_GENERAL, dt_dword, NULL, 0},
   {"SP", REGISTER_ADDRESS | REGISTER_SP, ARM_GENERAL, dt_dword, NULL, 0},
   {"LR", REGISTER_ADDRESS, ARM_GENERAL,  dt_dword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, ARM_GENERAL, dt_dword, NULL, 0},
   {"PSR", 0, ARM_GENERAL, dt_dword, arm_flags, 0xF80000FF},
};

#define ARM_LR 14

static int32_t arm_reg_map[] = {
   UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
   UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
   UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR
};

static struct register_info_t aarch64_regs[] = {
   {"X0", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X1", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X2", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X3", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X4", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X5", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X6", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X7", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X8", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X9", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X10", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X11", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X12", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X13", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X14", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X15", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X16", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X17", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X18", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X19", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X20", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X21", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X22", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X23", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X24", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X25", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X26", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X27", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X28", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"X29", REGISTER_ADDRESS, ARM_GENERAL, dt_qword, NULL, 0},
   {"LR", REGISTER_ADDRESS, ARM_GENERAL,  dt_qword, NULL, 0},
   {"SP", REGISTER_ADDRESS | REGISTER_SP, ARM_GENERAL, dt_qword, NULL, 0},
   {"PC", REGISTER_ADDRESS | REGISTER_IP, ARM_GENERAL, dt_qword, NULL, 0},
   {"PSR", 0, ARM_GENERAL, dt_dword, arm_flags, 0xF80000FF},
};

#define ARM64_LR 30

static int32_t arm64_reg_map[] = {
   UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4,
   UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7, UC_ARM64_REG_X8,
   UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11, UC_ARM64_REG_X12,
   UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15, UC_ARM64_REG_X16, UC_ARM64_REG_X17,
   UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
   UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24, UC_ARM64_REG_X25,
   UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29,
   UC_ARM64_REG_LR, UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_NZCV
};

sk3wldbg_arm::sk3wldbg_arm() : sk3wldbg("ARM", UC_ARCH_ARM, UC_MODE_ARM) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "ARMB";
   }

   //TODO: test the IDA "T" register to see if this is thumb code before creating emulator instance

   register_classes = arm_register_classes;
   register_classes_default = 1;        ///< Mask of default printed register classes
   _registers = arm_regs;               ///< Array of registers. Use registers() to access it
   registers_size = qnumber(arm_regs);  ///< Number of registers
   reg_map = arm_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

void sk3wldbg_arm::check_mode(ea_t addr) {
   sel_t thumb = get_segreg(addr, 20);   //20 is ARM T reg
   if (thumb) {
      debug_mode = (uc_mode)((int)UC_MODE_THUMB | (int)debug_mode);
   }
}

bool sk3wldbg_arm::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[ARM_LR], &retaddr);
   return true;
}

sk3wldbg_aarch64::sk3wldbg_aarch64() : sk3wldbg("ARM", UC_ARCH_ARM64, UC_MODE_ARM) {
   //reset any overridden function pointers and setup register name fields

   if (debug_mode & UC_MODE_BIG_ENDIAN) {
      processor = "ARMB";
   }

   register_classes = arm_register_classes;
   register_classes_default = 1;          ///< Mask of default printed register classes
   _registers = aarch64_regs;             ///< Array of registers. Use registers() to access it
   registers_size = qnumber(aarch64_regs); ///< Number of registers
   reg_map = arm64_reg_map;
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

}

void sk3wldbg_aarch64::check_mode(ea_t addr) {
   sel_t thumb = get_segreg(addr, 20);   //20 is ARM T reg
   if (thumb) {
      debug_mode = (uc_mode)((int)UC_MODE_THUMB | (int)debug_mode);
   }
}

bool sk3wldbg_aarch64::save_ret_addr(uint64_t retaddr) {
   uc_reg_write(uc, reg_map[ARM64_LR], &retaddr);
   return true;
}

