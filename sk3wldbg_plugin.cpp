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

/*
 *  This is the Sk3wlDbg plugin module
 *
 *  It is known to compile with
 *
 *  - Visual Studio 2010, Linux g++, OS X - clang
 *
 */

#ifdef PACKED
#undef PACKED
#endif

#include <unicorn/unicorn.h>

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <srarea.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <entry.hpp>
#include <dbg.hpp>
#include <idd.hpp>
#include <ua.hpp>

#include "sk3wldbg_x86.h"
#include "sk3wldbg_arm.h"
#include "sk3wldbg_mips.h"
#include "sk3wldbg_sparc.h"
#include "sk3wldbg_ppc.h"
#include "sk3wldbg_m68k.h"

static bool hooked = false;

static mem_map_action_handler mem_map_handler;

static action_desc_t mem_map_action = {
   sizeof(action_desc_t),
   "sk3wldbg:mem_map",
   "Map memory...",
   &mem_map_handler,
   NULL,
   NULL,
   NULL,
   0
};

static bool registered = false;

static int idaapi ui_hook(void *user_data, int notification_code, va_list va) {
   switch (notification_code) {
      case ui_debugger_menu_change: {
         bool enable = va_arg(va, int) != 0;
         msg("ui_debugger_menu_change received, enable = %u\n", enable);
/*
         if (enable) {
            register_action(mem_map_action);
            attach_action_to_menu("Debugger/Take memory snapshot", "sk3wldbg:mem_map", SETMENU_APP);
            registered = true;
         }
         else if (registered) {
            detach_action_from_menu("Debugger/Take memory snapshot", "sk3wldbg:mem_map");
            unregister_action("sk3wldbg:mem_map");            
            registered = false;
         }
*/
         return 1;
      }
   }
   return 0;
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
int idaapi plugin_init(void) {
   msg("sk3wldbg trying to init\n");
   int debug_mode = UC_MODE_32;
   if (inf.lflags & LFLG_64BIT) {
      debug_mode = UC_MODE_64;
   }
   else if (inf.lflags & LFLG_PC_FLAT) {
      debug_mode = UC_MODE_32;
   }
   else {
      msg("sk3wldbg: can't detect file bitness\n");
      return PLUGIN_SKIP;
   }
   switch (ph.id) {
      case PLFM_386:
         if (debug_mode == UC_MODE_32) {
            dbg = new sk3wldbg_x86_32();
         }
         else {
            dbg = new sk3wldbg_x86_64();
         }
         break;
      case PLFM_68K:
         dbg = new sk3wldbg_m68k();
         break;
      case PLFM_ARM:
         if (debug_mode == UC_MODE_32) {
            dbg = new sk3wldbg_arm();
         }
         else {
            dbg = new sk3wldbg_aarch64();
         }
         break;
      case PLFM_MIPS:
         if (debug_mode == UC_MODE_32) {
            dbg = new sk3wldbg_mips();
         }
         else {
            dbg = new sk3wldbg_mips64();
         }
         break;
      case PLFM_SPARC:
         if (debug_mode == UC_MODE_32) {
            dbg = new sk3wldbg_sparc();
         }
         else {
            dbg = new sk3wldbg_sparc64();
         }
         break;
      case PLFM_PPC:
         if (debug_mode == UC_MODE_32) {
            dbg = new sk3wldbg_ppc();
         }
         else {
            dbg = new sk3wldbg_ppc64();
         }
         break;
      default:
         msg("sk3wldbg: unsupported processor\n");
         return PLUGIN_SKIP;
   }
//   hook_to_notification_point(::HT_UI, ui_hook, dbg);
//   hooked = true;
   register_action(mem_map_action);
   registered = true;
   msg(PLUGIN_NAME" keeping sk3wldbg\n");
   return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

#ifndef DEBUG
#define DEBUG
#endif

void idaapi plugin_term(void) {
#ifdef DEBUG
   msg(PLUGIN_NAME": term entered\n");
#endif

   if (hooked) {
      unhook_from_notification_point(::HT_UI, ui_hook);
      hooked = false;
   }
   if (registered) {
      //This call is currently causing IDA to crash so something is 
      //not being done correctly.
      //Wrong place to unregister? Wrong thread to unregister from?
//      unregister_action("sk3wldbg:mem_map");            
   }

#ifdef DEBUG
   msg(PLUGIN_NAME": term exiting\n");
#endif
}

void idaapi plugin_run(int /*arg*/) {
   return;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_DBG | PLUGIN_HIDE,   // plugin flags

  plugin_init,                 // initialize

  plugin_term,                 // terminate. this pointer may be NULL.

  plugin_run,                  // invoke plugin

  "Sk3wlDbg",                   // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  "Sk3wlDbg",                   // multiline help about the plugin

  "Sk3wlDbg",            // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
