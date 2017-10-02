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

#include <ida.hpp>
#include <expr.hpp>

#include "sk3wldbg.h"
#include "idc_funcs.h"

static sk3wldbg *uc;

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
   return add_idc_func(func);
}

#endif

/*
 * native implementation of sk3wl_mmap.
 */
static error_t idaapi idc_mmap(idc_value_t *argv, idc_value_t *res) {
   res->vtype = VT_INT64;
   res->num = 0;
   if (argv[0].vtype == VT_INT64 && argv[1].vtype == VT_LONG && argv[2].vtype == VT_LONG) {
      uint64_t base = (uint64_t)argv[0].i64;
      unsigned int sz = (unsigned int)argv[1].num;
      unsigned int perms = (unsigned int)argv[2].num;
      map_block *mb = uc->memmgr->mmap(base, sz, perms);
      res->i64 = mb->guest;
   }
   else {
      res->i64 = -1;
   }
   return eOk;
}

/*
 * native implementation of sk3wl_munmap.
 */
static error_t idaapi idc_munmap(idc_value_t *argv, idc_value_t *res) {
   res->vtype = VT_LONG;
   res->num = 0;
   if (argv[0].vtype == VT_INT64 && argv[1].vtype == VT_LONG) {
      uint64_t base = (uint64_t)argv[0].i64;
      unsigned int sz = (unsigned int)argv[1].num;
      uc->memmgr->munmap(base, sz);
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
   static const char idc_long_long[] = { VT_LONG, VT_LONG, 0 };
   static const char idc_long_long_long[] = { VT_LONG, VT_LONG, VT_LONG, 0 };
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
