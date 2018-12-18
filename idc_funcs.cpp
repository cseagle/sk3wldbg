/*
   Scripting support for the sk3wldbg IdaPro plugin
   Copyright (c) 2017 Chris Eagle
   
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

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif

#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS 1
#endif

#include <ida.hpp>
#include <expr.hpp>
#include <segment.hpp>
#include <diskio.hpp>
#include <fpro.h>
#include <loader.hpp>

#include "sk3wldbg.h"
#include "loader.h"
#include "idc_funcs.h"

static sk3wldbg *uc;

#ifdef _WIN32
#define snprintf _snprintf
#endif

#if IDA_SDK_VERSION >= 700

bool set_idc_func_ex(const char *name, idc_func_t *fp, const char *args, int extfunc_flags) {
   ext_idcfunc_t func;
   func.name = name;
   func.fptr = fp;
   func.args = args;
   //hidden default arg used to pass sk3wldbg pointer into each function
   func.defvals = NULL;
   func.ndefvals = 0;
   func.flags = extfunc_flags;
   bool res = add_idc_func(func);
   msg("Installing idc func (%s) %s\n", name, res ? "succeeded" : "failed");
   return res;
}

#endif

void zero_fill(ea_t base, size_t size) {
   //Ida patch_xxx is very SLOW!!!!!
   //workaround is to create temp file containing all your zeros
   //then load that temp file as an additional binary file
   char ftmp[1024];
   qtmpnam(ftmp, sizeof(ftmp));
   size_t block = size;
   if (block > 0x10000) {
      block = 0x10000;
   }
   void *zeros = calloc(block, 1);
   FILE *f = fopen(ftmp, "wb");
   for (size_t done = 0; done < size; done += block) {
      block = size - done;
      if (block > 0x10000) {
         block = 0x10000;
      }
      fwrite(zeros, block, 1, f);
   }
   free(zeros);
   fclose(f);
   linput_t *fin = open_linput(ftmp, false);
   load_binary_file(ftmp, fin, 0, 0, 0, base, size);
   close_linput(fin);
#ifdef __NT__
   DeleteFile(ftmp);   
#else
   unlink(ftmp);
#endif
}

void createNewSegment(const char *name, ea_t base, uint32_t size, uint32_t perms, uint32_t bitness) {
   //create the new segment
   segment_t s;
   s.startEA = base;
   s.endEA = base + size;
   s.align = saRelPara;
   s.comb = scPub;
   s.perm = (uint8_t)perms;
   s.bitness = (uint8_t)bitness;
   bool is_code = (perms & SEGPERM_EXEC) != 0;
   if (is_code) {
      s.type = SEG_CODE;
   }
   else {
      s.type = SEG_DATA;
   }
   s.flags = SFL_DEBUG;
   
   msg("Creating segment %s with bitness %d and perms %d\n", name, s.bitness, s.perm);
   if (add_segm_ex(&s, name, is_code ? "CODE" : "DATA", ADDSEG_QUIET | ADDSEG_NOSREG)) {
      //zero out the newly created segment
      zero_fill(base, size);
   }
   else {
      msg("createNewSegment failed\n");
   }
}

/*
 * native implementation of sk3wl_mmap.
 * long sk3wl_mmap(long base, long size, lonf perms)
 */
static error_t idaapi idc_mmap(idc_value_t *argv, idc_value_t *res) {
   res->vtype = VT_INT64;
   res->i64 = -1;
   if (argv[0].vtype == VT_INT64 && argv[1].vtype == VT_LONG && argv[2].vtype == VT_LONG) {
      uint64_t base = (uint64_t)argv[0].i64;
      unsigned int sz = (unsigned int)argv[1].num;
      unsigned int perms = (unsigned int)argv[2].num & SEGPERM_MAXVAL;
      if (uc->map_mem_zero(base, base + sz, ida_to_uc_perms_map[perms])) {
         qstring seg_name = "mmap_";
         map_block *mb = uc->memmgr->find_block(base);
         seg_name.sprnt("mmap_%p", mb->guest);
         uint32_t bitness = 1;  //default to 32
         if (uc->debug_mode & UC_MODE_16) {
            bitness = 0;
         }
         else if (uc->debug_mode & UC_MODE_64) {
            bitness = 2;
         }
         createNewSegment(seg_name.c_str(), (ea_t)base, sz, perms, bitness);
         res->i64 = mb->guest;
      }
   }
   return eOk;
}

/*
 * native implementation of sk3wl_munmap.
 * sk3wl_munmap(long base, long size)
 */
static error_t idaapi idc_munmap(idc_value_t *argv, idc_value_t *res) {
   res->vtype = VT_LONG;
   res->num = 0;
   if (argv[0].vtype == VT_INT64 && argv[1].vtype == VT_LONG) {
      uint64_t base = (uint64_t)argv[0].i64;
      unsigned int sz = (unsigned int)argv[1].num;
      uc->memmgr->munmap(base, sz);
      add_segm(0, (ea_t)base, (ea_t)base + sz, "delsegxxx", "DATA", ADDSEG_QUIET | ADDSEG_NOAA);
      del_segm((ea_t)base, SEGMOD_KILL);
   }
   else {
      res->num = -1;
   }
   return eOk;
}

/*
 * Register new IDC functions for use with the debugger
 */
void register_funcs(sk3wldbg *_uc) {
   static const char idc_long_long[] = { VT_INT64, VT_LONG, 0 };
   static const char idc_long_long_long[] = { VT_INT64, VT_LONG, VT_LONG, 0 };
   uc = _uc;
   set_idc_func_ex("sk3wl_mmap", idc_mmap, idc_long_long_long, EXTFUN_BASE);
   set_idc_func_ex("sk3wl_munmap", idc_munmap, idc_long_long, EXTFUN_BASE);
}

/*
 * Unregister IDC functions when the plugin is unloaded
 */
void unregister_funcs() {
   set_idc_func_ex("sk3wl_mmap", NULL, NULL, 0);
   set_idc_func_ex("sk3wl_munmap", NULL, NULL, 0);
}
