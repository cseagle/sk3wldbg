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
#ifndef _MSC_VER
#include <windows.h>
#endif
#include <winsock2.h>
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

#if IDA_SDK_VERSION >= 710
#define register_classes regclasses
#define register_classes_default default_regclasses
#define _registers registers
#define registers_size nregs
#define PROCESS_START PROCESS_STARTED
#define PROCESS_EXIT PROCESS_EXITED
#define THREAD_START THREAD_STARTED
#define THREAD_EXIT THREAD_EXITED
#define LIBRARY_LOAD LIB_LOADED
#define LIBRARY_UNLOAD LIB_UNLOADED
#define PROCESS_ATTACH PROCESS_ATTACHED
#define PROCESS_DETACH PROCESS_DETACHED
#define PROCESS_SUSPEND PROCESS_SUSPENDED
#endif

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
   run_state emu_state;
   run_state resume_mode;
   qthread_t process_thread;
   regval_t *saved;
   
   uc_hook code_hook;
   uc_hook mem_fault_hook;
   uc_hook ihook;
   
   event_id_t last_eid;
   
   int32_t *reg_map;  //map of internal unicorn reg enums to dbg->_register index values

   sk3wldbg(const char *procname, uc_arch arch, uc_mode mode, const char *cpu_model = NULL);
   ~sk3wldbg();   
   
   virtual void install_initial_hooks();
   virtual bool is_system_call(uint8_t *inst, uint32_t size) {return false;};
   virtual void handle_system_call(uint8_t *inst, uint32_t size) {};
   virtual void check_mode(ea_t addr) {};
   
   void queue_step_event(uint64_t _pc);
   void enqueue_debug_evt(debug_event_t &evt);
   bool dequeue_debug_evt(debug_event_t *out);
   size_t debug_queue_len() {return dbg_evt_list.size();}
   
   bool is_stepping() {return single_step;}
   void clear_stepping() {single_step = false;}
   void set_stepping() {single_step = true;}

   void runtime_exception(uc_err err, uint64_t pc);
   bool queue_exception_event(uint32_t code, uint64_t mem_addr, const char *msg);
   bool queue_dbg_event(bool is_hardware);
   
   void close();
   void start(uint64_t initial_pc);
   void pause();
   void resume();
   bool open();
   void clear_memory() {memory.clear();}
   void init_memmgr(uint64_t map_min, uint64_t map_max);
   void *map_mem_zero(uint64_t startAddr, uint64_t endAddr, unsigned int perms, uint32_t flags = 0);
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

   run_state get_state();
   void set_state(run_state new_state);
};

struct mem_map_action_handler : public action_handler_t {
   int idaapi activate(action_activation_ctx_t *ctx);
   action_state_t idaapi update(action_update_ctx_t *ctx);
};

//Some idasdk70 transition macros
#if IDA_SDK_VERSION >= 700

#define startEA start_ea 
#define endEA end_ea 

#define minEA min_ea
#define maxEA max_ea
#define ominEA omin_ea
#define omaxEA omax_ea
#define procName procname

#define get_flags_novalue(ea) get_flags(ea)
#define isEnum0(f) is_enum0(f)
#define isEnum1(f) is_enum1(f)
#define isStroff0(f) is_stroff0(f)
#define isStroff1(f) is_stroff1(f)
#define isOff0(f) is_off0(f)
#define isOff1(f) is_off1(f)
#define isOff(f, n) is_off(f, n)
#define isEnum(f, n) is_enum(f, n)
#define isStroff(f, n) is_stroff(f, n)
#define isUnknown(f) is_unknown(f)
#define getFlags(f) get_flags(f)

#define isStruct(f) is_struct(f)
#define isASCII(f) is_strlit(f)
#define do_unknown(a, f) del_items(a, f)
#define do_unknown_range(a, s, f) del_items(a, f, s)
#define isCode(f) is_code(f)

#define get_member_name2 get_member_name

#define put_many_bytes(a, b, s) put_bytes(a, b, s)
#define patch_many_bytes(a, b, s) patch_bytes(a, b, s)
#define get_many_bytes(a, b, s) get_bytes(b, s, a)

#define do_data_ex(a, d, s, t) create_data(a, d, s, t)
#define doDwrd(a, l) create_dword(a, l)
#define doStruct(a, l, t) create_struct(a, l, t)
#define get_long(a) get_dword(a)

#define dwrdflag dword_flag

#define isEnabled(a) is_mapped(a)
#define isLoaded(a) is_loaded(a)

#define switchto_tform(w, f) activate_widget(w, f)
#define find_tform(c) find_widget(c)

#define get_segreg(a, r) get_sreg(a, r)
#define AskUsingForm_c ask_form

#else //Some idasdk70 transition macros, we are pre 7.0 below

#define start_ea startEA
#define end_ea endEA

#define ev_add_cref add_cref
#define ev_add_dref add_dref
#define ev_del_cref del_cref
#define ev_del_dref del_dref
#define ev_oldfile oldfile
#define ev_newfile newfile
#define ev_auto_queue_empty auto_queue_empty

#define set_func_start func_setstart 
#define set_func_end func_setend

#define get_sreg(a, r) get_segreg(a, r)
#define get_dword(a) get_long(a)

#define ask_form AskUsingForm_c

#endif //Some idasdk70 transition macros

#endif
