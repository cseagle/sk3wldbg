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

#ifndef __UNICORN_H
#define __UNICORN_H

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS
#endif

#ifdef __NT__

#ifdef _WIN32
#include <windows.h>
#ifndef _MSC_VER
//#include <windows.h>
#endif
//#include <winsock2.h>
#endif

#include <winnt.h>
#include <wincrypt.h>
#else
//#ifndef __NT__
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#endif

#include <unicorn/unicorn.h>

#include <pro.h>
#include <ida.hpp>
#include <idd.hpp>
#include <kernwin.hpp>

#include <vector>
#include <set>

#include "mem_mgr.h"

using std::set;
using std::vector;

#ifndef PLUGIN_NAME
#define PLUGIN_NAME "sk3wldbg"
#endif

typedef qlist<debug_event_t> evt_list_t;
typedef qlist<thid_t> thread_list;

void createNewSegment(const char *name, ea_t base, uint32_t size, uint32_t perms, uint32_t bitness);

#define UC_HOOK_NONE 0

enum run_state {
   RS_INIT = 1,
   RS_RUN,
   RS_STEP_OVER,
   RS_STEP_INTO,
   RS_STEP_OUT,
   RS_PAUSE,
   RS_BREAK,
   RS_TERM
};

struct sk3wldbg : public debugger_t {

#ifdef __NT__
   HCRYPTPROV hProv;
#else
   int hProv;
#endif

   uint32_t thumb;
   uint32_t the_process;
   
   thread_list the_threads;

   set<uint64_t> breakpoints;
   set<uint64_t> tbreaks;
   vector<void*> memmap;
   mem_mgr *memmgr;

   uc_arch debug_arch;
   uc_mode debug_mode;
   qstring cpu_model;

   uc_engine *uc;
   uc_context *ctx;  //somtimes we need to save/restore state
   bool do_suspend;
   bool finished;
   bool single_step;
   bool registered_menu;
   meminfo_vec_t memory;
   evt_list_t dbg_evt_list;
   qmutex_t evt_mutex;
   qsemaphore_t run_sem;
   qsemaphore_t pause_sem;
   run_state emu_state;
   run_state resume_mode;
   qthread_t process_thread;
   regval_t *saved;
   
   uc_hook h_code_hook;
   uc_hook h_mem_fault_hook;
   uc_hook h_ihook;
   
   int which_hook;
   
   event_id_t last_eid;
   
   int32_t *reg_map;  //map of internal unicorn reg enums to dbg->_register index values

   sk3wldbg(const char *procname, uc_arch arch, uc_mode mode, const char *cpu_model = NULL);
   ~sk3wldbg(void);   
   
   virtual void install_initial_hooks(void);
   virtual bool is_system_call(uint8_t *inst, uint32_t size) {return false;};
   virtual void handle_system_call(uint8_t *inst, uint32_t size) {};
   virtual void check_mode(ea_t addr) {};
   virtual void code_hook(uint64_t address, uint32_t size);
   virtual bool mem_fault_hook(uc_mem_type type, uint64_t address,
                               int size, int64_t value);
   virtual void intr_hook(uint32_t intno);
    
   void queue_step_event(uint64_t _pc);
   void enqueue_debug_evt(debug_event_t &evt);
   bool dequeue_debug_evt(debug_event_t *out);
   size_t debug_queue_len(void) {return dbg_evt_list.size();}
   
   bool is_stepping(void) {return single_step;}
   void clear_stepping(void) {single_step = false;}
   void set_stepping(void) {single_step = true;}

   void runtime_exception(uc_err err, uint64_t pc);
   bool queue_exception_event(uint32_t code, uint64_t mem_addr, const char *msg);
   bool queue_bpt_event(bool is_hardware);
   
   void close(void);
   virtual void init_session(void) {};
   virtual void start(uint64_t initial_pc);
   void pause(void);
   void resume(void);
   bool open(void);
   void clear_memory(void) {memory.clear();}
   void init_memmgr(uint64_t map_min, uint64_t map_max);
   void *map_mem_zero(uint64_t startAddr, uint64_t endAddr, unsigned int perms, uint32_t flags = 0);
   void map_mem_copy(uint64_t startAddr, uint64_t endAddr, unsigned int perms, void *src);
   void getRandomBytes(void *buf, unsigned int len);

   void add_bpt(uint64_t bpt_addr);
   void del_bpt(uint64_t bpt_addr);

   bool read_register(int regidx, regval_t *values);
   bool save_registers(void);
   bool restore_registers(void);
   
   virtual bool call_changes_sp(void) {return false;};
   //emulate what this processor does when a function is called
   //some processors push, some processors save it in a register
   //emulate the right thing here. This is to support appcall
   virtual bool save_ret_addr(uint64_t retaddr) = 0;
   
   bool done(void) {return finished;}
   
   // return a linear address for use by ida
   virtual uint64_t get_pc(void);
   
   // set the PC from a provided linear address
   virtual bool set_pc(uint64_t);
   virtual uint64_t get_sp(void);
   virtual bool set_sp(uint64_t);

   run_state get_state(void);
   void set_state(run_state new_state);
};

struct mem_map_action_handler : public action_handler_t {
   int idaapi activate(action_activation_ctx_t *ctx);
   action_state_t idaapi update(action_update_ctx_t *ctx);
};

#endif
