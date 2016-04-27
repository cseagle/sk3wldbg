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

#ifdef __NT__
#include <windows.h>
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

#include <set>

using std::set;

#ifndef PLUGIN_NAME
#define PLUGIN_NAME "sk3wldbg"
#endif

typedef qlist<debug_event_t> evt_list_t;
typedef qlist<thid_t> thread_list;

enum run_state {
   RS_INIT = 1,
   RS_RUN,
   RS_STEP_OVER,
   RS_STEP_INTO,
   RS_STEP_OUT,
   RS_PAUSE,
   RS_TERM
};

struct sk3wldbg : public debugger_t {

#ifdef __NT__
   HCRYPTPROV hProv;
#else
   int hProv;
#endif

   uint32_t the_process;
   
   thread_list the_threads;

   set<uint64_t> breakpoints;

   uc_arch debug_arch;
   uc_mode debug_mode;
   qstring cpu_model;

   uc_engine *uc;
   bool do_suspend;
   bool finished;
   bool single_step;
   uint64_t suspend_pc;
   meminfo_vec_t memory;
   evt_list_t dbg_evt_list;
   qmutex_t evt_mutex;
   qsemaphore_t run_sem;
   run_state emu_state;
   qthread_t process_thread;
   regval_t *saved;
   
   uc_hook code_hook;
   uc_hook mem_fault_hook;
   
   event_id_t last_eid;
   
   int32_t *reg_map;  //map of internal unicorn reg enums to dbg->_register index values

   sk3wldbg(const char *procname, uc_arch arch, uc_mode mode, const char *cpu_model = NULL);
   ~sk3wldbg();   
   
   virtual void install_initial_hooks();
   virtual void check_mode(ea_t addr) {};
   
   void enqueue_debug_evt(debug_event_t &evt);
   bool dequeue_debug_evt(debug_event_t *out);
   size_t debug_queue_len() {return dbg_evt_list.size();}

   bool queue_exception_event(uint32_t code, uint64_t mem_addr, const char *msg);
   bool queue_dbg_event(bool is_hardware);
   
   void close();
   void start(uint64_t initial_pc);
   void pause();
   void resume();
   void step(uint64_t initial_pc);
   bool open();
   void clear_memory() {memory.clear();}
   void map_mem_zero(uint64_t startAddr, uint64_t endAddr, unsigned int perms);
   void map_mem_copy(uint64_t startAddr, uint64_t endAddr, unsigned int perms, void *src);
   void getRandomBytes(void *buf, unsigned int len);

   void add_bpt(uint64_t bpt_addr);
   void del_bpt(uint64_t bpt_addr);

   bool read_register(int regidx, regval_t *values);
   bool save_registers();
   bool restore_registers();
   
   virtual bool call_changes_sp() {return false;};
   //emulate what this processor does when a function is called
   //some processors push, some processors save it in a register
   //emulate the right thing here. This is to support appcall
   virtual bool save_ret_addr(uint64_t retaddr) = 0;
   
   bool done() {return finished;}
   uint64_t get_pc();
   bool set_pc(uint64_t);
   uint64_t get_sp();
   bool set_sp(uint64_t);
};

#endif
