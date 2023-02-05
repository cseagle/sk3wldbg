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
#define USE_DANGEROUS_FUNCTIONS

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

#ifdef PACKED
#undef PACKED
#endif

#define USE_STANDARD_FILE_FUNCTIONS

#include <unicorn/unicorn.h>

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <entry.hpp>
#include <dbg.hpp>
#include <idd.hpp>
#include <ua.hpp>

#include "sk3wldbg.h"
#include "loader.h"

#ifdef DEBUG
#undef DEBUG
#else
#undef DEBUG
#endif

//#define DEBUG

static ssize_t idaapi idd_hook(void * /* ud */, int notification_code, va_list va);

struct safe_msg : public exec_request_t {
    qstring the_msg;
    safe_msg(qstring &msg) : the_msg(msg) {};
    int idaapi execute(void);
};

int idaapi safe_msg::execute(void) {
    msg("%s", the_msg.c_str());
    return 0;
}

//Not certain this is necessary, but included to provide for message printing from
//the unicorn thread
void do_safe_msg(const char *msg) {
    qstring m(msg);
    safe_msg req(m);
    execute_sync(req, MFF_FAST);
}

qstring *get_process_name(void) {
    char buf[1024];
    ssize_t sz = get_root_filename(buf, sizeof(buf));
    return new qstring(buf);
}

static ssize_t idaapi idb_hook(void *user_data, int notification_code, va_list va) {
    sk3wldbg *uc = (sk3wldbg*)user_data;
    switch (notification_code) {
        case idb_event::segm_added: {
            segment_t *seg = va_arg(va, segment_t *);
            uintptr_t start = seg->start_ea;
            uintptr_t end = seg->end_ea;
            //msg("idb_hook uc == %p\n", uc);
            //msg("offset to uc->memmgr == 0x%x\n", ((char*)&uc->memmgr) - (char*)uc);
            //msg("uc->memmgr == %p\n", uc->memmgr);
            msg("segm_added mapping, %p:%p\n", (void*)start, (void*)end);
            if (uc->memmgr->find_block(start) == NULL) {
                msg("segm_added mapping, %p:%p\n", (void*)start, (void*)end);
                uc->map_mem_zero(start, end, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, SDB_MAP_FIXED);
                msg("segm_added mapped, %p:%p\n", (void*)start, (void*)end);
            } else {
                msg("segm_added already mapped\n");
            }
            return 1;
        }
    }
    return 0;
}

/// Initialize debugger.
/// This function is called from the main thread.
/// \return success
bool idaapi uni_init_debugger(const char * /*hostname*/, int /*portnum*/, const char * /*password*/, qstring * /*errbuf*/) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    msg("uni_init_debugger called\n");
#endif
    return true;
}

/// Terminate debugger.
/// This function is called from the main thread.
/// \return success
bool idaapi uni_term_debugger(void) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    msg("uni_term_debugger called\n");
#endif
//     safe_msg req("uni_term_debugger called\n");
//    execute_sync(req, MFF_FAST);
    if (uc->uc) {
        uc->emu_state = RS_TERM;
        qsem_post(uc->run_sem);
        //***synchronize here to make sure execution thread has stopped
        qthread_join(uc->process_thread);
//        msg("uni_term_debugger thread joined\n");
       uc->close();

       if (uc->registered_menu) {
           detach_action_from_menu("Debugger/Take memory snapshot", "sk3wldbg:mem_map");
//           unregister_action("sk3wldbg:mem_map");
           uc->registered_menu = false;
       }
//       uc->uc = NULL;
    }

    unhook_from_notification_point(::HT_IDB, idb_hook);

//   safe_msg req2("uni_term_debugger complete\n");
//   execute_sync(req2, MFF_FAST);
    return true;
}

bool sk3wldbg::queue_exception_event(uint32_t code, uint64_t mem_addr, const char *errmsg) {
    debug_event_t exc;
    exc.set_eid(::EXCEPTION);
    exc.pid = the_process;
    exc.tid = the_threads.front();
    exc.ea = (ea_t)get_pc();
#ifdef DEBUG
    qstring msgbuf;
    msgbuf.sprnt("Exception occurred at: %p\n", (void*)exc.ea);
    msg("%s", msgbuf.c_str());
#endif
    exc.handled = true;

    excinfo_t &xcpt = exc.exc();
    xcpt.info = errmsg;

    xcpt.code = code;
    xcpt.can_cont = false;
    xcpt.ea = (ea_t)mem_addr;

    enqueue_debug_evt(exc);
    return true;
}

void sk3wldbg::queue_step_event(uint64_t _pc) {
    debug_event_t cont;
    cont.set_eid(::STEP);
    cont.pid = the_process;
    cont.tid = the_threads.front();
    cont.ea = (ea_t)_pc;
    cont.handled = true;
    enqueue_debug_evt(cont);
}

bool sk3wldbg::queue_bpt_event(bool is_hardware) {
    debug_event_t brk;
    brk.set_eid(::BREAKPOINT);
    bptaddr_t &bpt = brk.bpt();
    brk.pid = the_process;
    brk.tid = the_threads.front();
    brk.ea = (ea_t)get_pc();
#ifdef DEBUG
    qstring msgbuf;
    msgbuf.sprnt("Breakpoint hit at: %p\n", (void*)brk.ea);
    msg("%s", msgbuf.c_str());
#endif
    brk.handled = true;
    bpt.hea = is_hardware ? brk.ea : BADADDR;
    bpt.kea = BADADDR;
    enqueue_debug_evt(brk);
    return true;
}

struct print_pc : public exec_request_t {
    uint64_t pc;
    print_pc(uint64_t _pc) : pc(_pc) {};
    int idaapi execute(void);
};

int idaapi print_pc::execute(void) {
#ifdef DEBUG
    qstring msgbuf;
    msgbuf.sprnt("processRunner running from %p\n", (void*)pc);
    msg("%s", msgbuf.c_str());
#endif
    return 0;
}

int idaapi processRunner(void *unicorn) {
    sk3wldbg *uc = (sk3wldbg*)unicorn;
    uint64_t pc = uc->get_pc();
    if (pc == 0) {
        msg("PC was not set previously, going with screen EA\n");
        pc = get_screen_ea();
    } else {
        qstring msgbuf;
        msgbuf.sprnt("PC was set previously to %p\n", (void*)pc);
        msg("%s", msgbuf.c_str());
    }
    uc->start(pc);
    //unicorn start has returned, process has ended, so tell IDA to detach
    debug_event_t detach;
    detach.set_eid(PROCESS_DETACHED);
    detach.pid = uc->the_process;
    detach.tid = uc->the_threads.front();
    detach.ea  = BADADDR;
    detach.handled = true;
    uc->enqueue_debug_evt(detach);
    return 0;
}

/// Return information about the n-th "compatible" running process.
/// If n is 0, the processes list is reinitialized.
/// This function is called from the main thread.
/// \retval 1  ok
/// \retval 0  failed
/// \retval -1 network error
int idaapi uni_get_processes(procinfo_vec_t *procs, qstring * /*errbuf*/) {
#ifdef DEBUG
    msg("uni_get_processes called\n");
#endif
    sk3wldbg *uc = (sk3wldbg*)dbg;
    process_info_t info;
    qstring *procname = get_process_name();
    info.name = *procname;
    delete procname;
    info.pid = uc->the_process;
    procs->push_back(info);
    return 1;
}

#if IDA_SDK_VERSION < 700
//*** Learn proper way to do this in Ida 7.0
struct install_menu : public exec_request_t {
    sk3wldbg *uc;
    install_menu(sk3wldbg *_uc) : uc(_uc) {};
    int idaapi execute(void);
};

int idaapi install_menu::execute(void) {
    attach_action_to_menu("Debugger/Take memory snapshot", "sk3wldbg:mem_map", SETMENU_APP);
    enable_menu_item("Debugger/Map memory...", false);
    uc->registered_menu = true;
    return 0;
}
#endif

/// Start an executable to debug.
/// This function is called from debthread.
/// \param path              path to executable
/// \param args              arguments to pass to executable
/// \param startdir          current directory of new process
/// \param dbg_proc_flags    \ref DBG_PROC_
/// \param input_path        path to database input file.
///                          (not always the same as 'path' - e.g. if you're analyzing
///                          a dll and want to launch an executable that loads it)
/// \param input_file_crc32  CRC value for 'input_path'
/// \retval  1                    ok
/// \retval  0                    failed
/// \retval -2                    file not found (ask for process options)
/// \retval  1 | #CRC32_MISMATCH  ok, but the input file crc does not match
/// \retval -1                    network error
int idaapi uni_start_process(const char * /*path*/,
                             const char *args,
                             const char * /*startdir*/,
                             int /*dbg_proc_flags*/,
                             const char *input_path,
                             uint32 /*input_file_crc32*/, qstring * /*errbuf*/) {

    int choice = ask_buttons("Cursor", "Entry point", NULL, ASKBTN_YES, "Begin execution from:");

    if (choice == ASKBTN_CANCEL) {
        return 0;
    }

#ifdef DEBUG
    msg("uni_start_process called\n");
#endif
    sk3wldbg *uc = (sk3wldbg*)dbg;

#if IDA_SDK_VERSION < 700
    //*** Learn proper way to do this in Ida 7.0
    install_menu req(uc);
    execute_sync(req, MFF_FAST);
#endif

    ea_t init_pc = BADADDR;

    if (choice == ASKBTN_YES) {
        init_pc = get_screen_ea();
        uc->check_mode(init_pc);
    }

    if (!uc->open()) {
        //failed to open unicorn instance
        return 0;
    }

    qsem_free(uc->run_sem);
    uc->run_sem = qsem_create(NULL, 0);
    uc->pause_sem = qsem_create(NULL, 0);
    qmutex_unlock(uc->evt_mutex);
    uc->clear_memory();
    uc->dbg_evt_list.clear();
    uc->the_threads.clear();

    uc->getRandomBytes(&uc->the_process, 2);
    uc->the_process = (uc->the_process % 40000) + 1000;

    thid_t a_thread = 0;
    do {
        uc->getRandomBytes(&a_thread, 2);
        a_thread = (a_thread % 40000) + 1000;
    } while (a_thread == (thid_t)uc->the_process);
    uc->the_threads.push_back(a_thread);

    FILE *bin = fopen(input_path, "rb");
    bool loaded = false;
    if (bin != NULL) {
        msg("found input file %s\n", input_path);
        if (fseek(bin, 0, SEEK_END) != 0) {
            //HUH?
            msg("SEEK_END fail\n");
        } else {
            long sz = ftell(bin);
            void *img = malloc(sz);
            if (img == NULL) {
                //OOM
                msg("image allocate fail\n");
            } else {
                msg("reading file of %u bytes\n", (uint32_t)sz);
                fseek(bin, 0, SEEK_SET);
                if (fread(img, sz, 1, bin) != 1) {
                    //fail
                    msg("fread fail\n");
                } else {
                    loaded = loadImage(uc, img, sz, args, init_pc);
                }
                free(img);
            }
        }
        fclose(bin);
    }
    void *buf16 = NULL; //memory pointer
    if (uc->debug_mode == UC_MODE_16) {
        //just map a megabyte
        uc->init_memmgr(0, 0x100000);
        buf16 = uc->map_mem_zero(0, 0x100000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, SDB_MAP_FIXED);
    } else if (uc->get_sp() == 0) {
        //need a stack too, just sling it somewhere
        //add it to uc->memory
        unsigned int stack_top = 0xffffe000;
        uc->init_memmgr(0x100000, stack_top);
        uc->map_mem_zero(stack_top - 0x100000, stack_top, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, SDB_MAP_FIXED);
        stack_top -= 16;
        uc->set_sp(stack_top);
    }
    if (!loaded) {
        //didn't know format, let's try for what we need from IDA
        //init memory, by copying from IDA
        //May prefer instead to init from file, in which case we need loaders
        //Also need to map in a stack and init stack pointer, this will be
        //architecture dependent since each arch has its own SP register
        //arch specific unicorns also need to set initial register state
        segment_t *seg;
        for (seg = get_first_seg(); seg != NULL; seg = get_next_seg(seg->start_ea)) {
            void *buf;
            ssize_t exact = (ssize_t)(seg->end_ea - seg->start_ea);
            if (uc->debug_mode == UC_MODE_16) {
                buf = seg->start_ea + (char*)buf16;
            } else {
                buf = uc->map_mem_zero(seg->start_ea, seg->end_ea, ida_to_uc_perms_map[seg->perm], SDB_MAP_FIXED);
            }
            get_bytes(buf, exact, seg->start_ea);
        }

        //need other ways to set PC, from start, user specified
        uc->set_pc(init_pc);
    } else { // we loaded it, but may need to load any additional segments that exist in IDA
        segment_t *seg;
        void *buf;
        for (seg = get_first_seg(); seg != NULL; seg = get_next_seg(seg->start_ea)) {
            if (seg->is_loader_segm()) {
                //should have been handled by our loader
                continue;
            }
            ssize_t exact = (ssize_t)(seg->end_ea - seg->start_ea);
            buf = uc->map_mem_zero(seg->start_ea, seg->end_ea, ida_to_uc_perms_map[SEGPERM_EXEC | SEGPERM_WRITE | SEGPERM_READ], SDB_MAP_FIXED);
            msg("trying to populate new segment\n");
            get_bytes(buf, exact, seg->start_ea);
            msg("populated new segment\n");
        }
    }

    // need to respond to some idb events
    hook_to_notification_point(::HT_IDB, idb_hook, uc);

    //init registers
    //TODO: each architecture subclass should have its own register state initialization

    //register unicorn hooks

    //start in break state, RS_RUN will be set in uni_continue_after_event
    uc->emu_state = RS_BREAK;
    uc->do_suspend = false;
    uc->finished = false;
    uc->single_step = false;

    //this is going to have to run in a separate thread otherwise other
    //debthread functions will never get called
    uc->process_thread = qthread_create(processRunner, uc);
    if (uc->process_thread == NULL) {
        //error failed to create thread
        msg(PLUGIN_NAME": Failed to start process.\n");
        return 0;
    }

    debug_event_t start;
    qstring *procname = get_process_name();
    start.set_eid(PROCESS_STARTED);
    modinfo_t &mod = start.modinfo();
    mod.name = *procname;
    delete procname;
    start.pid = uc->the_process;
    start.tid = uc->the_threads.front();
    start.ea = BADADDR;
    start.handled = true;
    mod.base = inf_get_min_ea();
    mod.size = inf_get_max_ea() - inf_get_min_ea();
    mod.rebase_to = BADADDR;
    uc->enqueue_debug_evt(start);

#ifdef DEBUG
    msg("uni_start_process complete\n");
#endif
    return 1;
}

/// Attach to an existing running process.
/// event_id should be equal to -1 if not attaching to a crashed process.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error

int idaapi uni_attach_process(pid_t /*pid*/, int /*event_id*/, int /*dbg_proc_flags*/, qstring * /*errbuf*/) {
    //can't do this with unicorn
#ifdef DEBUG
    msg("uni_attach_process called\n");
#endif
    return 0;
}

/// Detach from the debugged process.
/// May be called while the process is running or suspended.
/// Must detach from the process in any case.
/// The kernel will repeatedly call get_debug_event() and until ::PROCESS_DETACHED.
/// In this mode, all other events will be automatically handled and process will be resumed.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_detach_process(void) {
#ifdef DEBUG
    msg("uni_detach_process called\n");
#endif
    //for unicorn we will just terminate session if user wants to detach
    sk3wldbg *uc = (sk3wldbg*)dbg;
    uc->emu_state = RS_TERM;
    qsem_post(uc->run_sem);
    //***synchronize here to make sure execution thread has stopped
    qthread_join(uc->process_thread);
#ifdef DEBUG
    msg("uni_detach_process thread joined\n");
#endif
/*
    debug_event_t detach;
    detach.set_eid(PROCESS_DETACHED);
    detach.pid = uc->the_process;
    detach.tid = uc->the_threads.front();
    detach.ea  = BADADDR;
    detach.handled = true;
    uc->enqueue_debug_evt(detach);
*/
#ifdef DEBUG
    msg("uni_detach_process complete\n");
#endif
    return 1;
}

/// Rebase database if the debugged program has been rebased by the system.
/// This function is called from the main thread.
void idaapi uni_rebase_if_required_to(ea_t /*new_base*/) {
#ifdef DEBUG
    msg("uni_rebase_if_required_to called: NOT IMPLEMENTED\n");
#endif
}

/// Prepare to pause the process.
/// Normally the next get_debug_event() will pause the process
/// If the process is sleeping then the pause will not occur
/// until the process wakes up. The interface should take care of
/// this situation.
/// If this function is absent, then it won't be possible to pause the program.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_prepare_to_pause_process(qstring * /*errbuf*/) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    msg("uni_prepare_to_pause_process called\n");
#endif
    uc->pause();
    debug_event_t pause;
    pause.set_eid(PROCESS_SUSPENDED);
    pause.info()[0] = 0;
    pause.pid = uc->the_process;
    pause.tid = uc->the_threads.front();
#if IDA_SDK_VERSION < 730
    pause.ea = inf.min_ea;   //??? get pc from unicorn
#else
    pause.ea = inf_get_min_ea();
#endif
    uc->enqueue_debug_evt(pause);
#ifdef DEBUG
    msg("uni_prepare_to_pause_process complete\n");
#endif
    return 1;
}

/// Stop the process.
/// May be called while the process is running or suspended.
/// Must terminate the process in any case.
/// The kernel will repeatedly call get_debug_event() and until ::PROCESS_EXITED.
/// In this mode, all other events will be automatically handled and process will be resumed.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_exit_process(qstring * /*errbuf*/) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    msg("uni_exit_process called\n");
#endif
    uc->emu_state = RS_TERM;
    qsem_post(uc->run_sem);
    //***synchronize here to make sure execution thread has stopped
    qthread_join(uc->process_thread);
#ifdef DEBUG
    msg("uni_exit_process thread joined\n");
#endif
    debug_event_t stop;
    stop.set_exit_code(::PROCESS_EXITED, 0);
    stop.pid = uc->the_process;
    stop.tid = uc->the_threads.front();
#if IDA_SDK_VERSION < 730
    stop.ea = inf.min_ea;
#else
    stop.ea = inf_get_min_ea();
#endif
    uc->enqueue_debug_evt(stop);

    return 1;
}

/// Get a pending debug event and suspend the process.
/// This function will be called regularly by IDA.
/// This function is called from debthread.
/// IMPORTANT: commdbg does not expect immediately after a BPT-related event
/// any other event with the same thread/IP - this can cause erroneous
/// restoring of a breakpoint before resume
/// (the bug was encountered 24.02.2015 in pc_linux_upx.elf)
gdecode_t idaapi uni_get_debug_event(debug_event_t *event, int /*timeout_ms*/) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
    if (uc->debug_queue_len() == 0) {
        return GDE_NO_EVENT;
    } else {
        uc->dequeue_debug_evt(event);
//        msg("uni_get_debug_event called returning: eid = 0x%08x\n", event->eid);
        //should we ever act on event->eid here?
        return uc->debug_queue_len() > 0 ? GDE_MANY_EVENTS : GDE_ONE_EVENT;
    }
}

/// Continue after handling the event.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_continue_after_event(const debug_event_t *event) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
    event_id_t eid = event->eid();
#ifdef DEBUG
    msg("uni_continue_after_event called: eid = 0x%08x\n", eid);
#endif
    if (event == NULL || eid == 2) {// || uc->dbg_evt_list.size() == 0) {
        return 1;
    }
    uc->emu_state = RS_RUN;
    switch (eid) {
        case PROCESS_STARTED:
#ifdef DEBUG
           msg("uni_continue_after_event PROCESS_STARTED\n");
#endif
           qsem_post(uc->run_sem);
           break;
        case PROCESS_EXITED:
#ifdef DEBUG
            msg("uni_continue_after_event PROCESS_EXITED\n");
#endif
            uc->emu_state = RS_TERM;
            qsem_post(uc->run_sem);
            break;
        case THREAD_STARTED:
#ifdef DEBUG
            msg("uni_continue_after_event THREAD_STARTED\n");
#endif
            qsem_post(uc->run_sem);
            break;
        case THREAD_EXITED:
#ifdef DEBUG
            msg("uni_continue_after_event THREAD_EXITED\n");
#endif
            qsem_post(uc->run_sem);
            break;
        case BREAKPOINT:
#ifdef DEBUG
            msg("uni_continue_after_event BREAKPOINT\n");
#endif
            //resume from breakpoint, replace instruction in memory, single step resume again?
            //need to honor resume_mode in this case
            uc->emu_state = uc->resume_mode;
            qsem_post(uc->run_sem);
            break;
        case STEP:
#ifdef DEBUG
            msg("uni_continue_after_event trying to step\n");
#endif
            //state should have been set in set_resume_mode
            //need to honor resume_mode in this case
            uc->emu_state = uc->resume_mode;
            qsem_post(uc->run_sem);
            break;
        case EXCEPTION:
#ifdef DEBUG
            msg("uni_continue_after_event EXCEPTION\n");
#endif
            //give it a try
            qsem_post(uc->run_sem);
            break;
        case LIB_LOADED:
#ifdef DEBUG
            msg("uni_continue_after_event LIB_LOADED\n");
#endif
            qsem_post(uc->run_sem);
            break;
        case LIB_UNLOADED:
#ifdef DEBUG
            msg("uni_continue_after_event LIB_UNLOADED\n");
#endif
            qsem_post(uc->run_sem);
            break;
        case INFORMATION:
#ifdef DEBUG
            msg("uni_continue_after_event INFORMATION\n");
#endif
            break;
        case PROCESS_ATTACHED:
#ifdef DEBUG
            msg("uni_continue_after_event PRICESS_ATTACH\n");
#endif
            break;
        case PROCESS_DETACHED:
#ifdef DEBUG
            msg("uni_continue_after_event PROCESS_DETACHED\n");
#endif
            break;
        case PROCESS_SUSPENDED:
#ifdef DEBUG
            msg("uni_continue_after_event PROCESS_SUSPENDED\n");
#endif
            qsem_post(uc->run_sem);
            break;
        case TRACE_FULL:
#ifdef DEBUG
            msg("uni_continue_after_event TRACE_FULL\n");
#endif
            break;
        case NO_EVENT:
            break;
    }
    return 1;
}

/// Set exception handling.
/// This function is called from debthread or the main thread.
void idaapi uni_set_exception_info(const exception_info_t *info, int qty) {
#ifdef DEBUG
    msg("uni_set_exception_info called\n");
#endif
    for (int i = 0; i < qty; i++) {
        msg("Exception #%d\n", i);
        msg("   Code: 0x%x, flags: 0x%x\n", info[i].code, info[i].flags);
        msg("   Name: %s, Desc: %s\n", info[i].name.c_str(), info[i].desc.c_str());
    }
}

/// This function will be called by the kernel each time
/// it has stopped the debugger process and refreshed the database.
/// The debugger module may add information to the database if it wants.
///
/// The reason for introducing this function is that when an event line
/// LOAD_DLL happens, the database does not reflect the memory state yet
/// and therefore we can't add information about the dll into the database
/// in the get_debug_event() function.
/// Only when the kernel has adjusted the database we can do it.
/// Example: for imported PE DLLs we will add the exported function
/// names to the database.
///
/// This function pointer may be absent, i.e. NULL.
/// This function is called from the main thread.
void idaapi uni_stopped_at_debug_event(thread_name_vec_t * /*thr_names*/, bool /*dlls_added*/) {
#ifdef DEBUG
    msg("uni_stopped_at_debug_event called\n");
#endif
}

/// \name Threads
/// The following functions manipulate threads.
/// These functions are called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_thread_suspend(thid_t /*tid*/) { ///< Suspend a running thread
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    msg("uni_thread_suspend called\n");
#endif
    uc->pause();
    uc->do_suspend = true;
    //is there an event we need to post to IDA?
    return 1;
}

int idaapi uni_thread_continue(thid_t /*tid*/) { ///< Resume a suspended thread
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    msg("uni_thread_continue called\n");
#endif
    //this is going to have to run in a separate thread otherwise other
    //debthread functions will never get called
    if (uc->do_suspend) {
        uc->do_suspend = false;
    }
    uc->resume();
    return 1;
}

int idaapi uni_set_resume_mode(thid_t /*tid*/, resume_mode_t resmod) { ///< Specify resume action
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    msg("uni_set_resume_mode called. resmod = %d\n", resmod);
#endif
    //*** figure out how best to handle all resume modes
    switch (resmod) {
        case RESMOD_OVER:
            uc->resume_mode = RS_STEP_OVER;
            break;
        case RESMOD_OUT:
            uc->resume_mode = RS_STEP_OUT;
            break;
        case RESMOD_INTO:
            uc->resume_mode = RS_STEP_INTO;
            uc->set_stepping();
            break;
        case RESMOD_NONE:
            uc->resume_mode = RS_RUN;   //????
            break;
        default:
            break;
    }
    return 1;
}

/// Read thread registers.
/// This function is called from debthread.
/// \param tid      thread id
/// \param clsmask  bitmask of register classes to read
/// \param regval   pointer to vector of regvals for all registers.
///                 regval is assumed to have debugger_t::nregs elements
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_read_registers(thid_t /*tid*/, int clsmask, regval_t *values, qstring * /*errbuf*/) {
#ifdef DEBUG
    msg("uni_read_registers called\n");
#endif
    sk3wldbg *uc = (sk3wldbg*)dbg;
    uc_err err = UC_ERR_OK;
    //need to figure out how to do this across all unicorn archs
    for (int i = 0; i < uc->nregs; i++) {
        if (uc->registers[i].register_class & clsmask) {
            if (!uc->read_register(i, &values[i])) {
                return 0;
            }
        }
    }
    return 1;
}

/// Write one thread register.
/// This function is called from debthread.
/// \param tid     thread id
/// \param regidx  register index
/// \param regval  new value of the register
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_write_register(thid_t /*tid*/, int regidx, const regval_t *value, qstring * /*errbuf*/) {
#ifdef DEBUG
    msg("uni_write_register called\n");
#endif
    //need to figure out how to do this across all unicorn archs
    sk3wldbg *uc = (sk3wldbg*)dbg;
    uc_err err = uc_reg_write(uc->uc, uc->reg_map[regidx], &value->ival);
    return err == UC_ERR_OK;
}

/// Get information about the base of a segment register.
/// Currently used by the IBM PC module to resolve references like fs:0.
/// This function is called from debthread.
/// \param tid         thread id
/// \param sreg_value  value of the segment register (returned by get_reg_val())
/// \param answer      pointer to the answer. can't be NULL.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_thread_get_sreg_base(ea_t *answer, thid_t /*tid*/, int /*sreg_value*/, qstring * /*errbuf*/) {
#ifdef DEBUG
    msg("uni_thread_get_sreg_base called\n");
#endif
    //right now unicorn has no way to get this information since base is not a register
    //would need to read decide whether seg is local or global, then UC_X86_REG_L/GDTR,
    //the uc_read_mem to read correct descriptor, then parse out the base address
    *answer = 0;
    return 1;
}

/// \name Memory manipulation
/// The following functions manipulate bytes in the memory.

/// Get information on the memory areas.
/// The debugger module fills 'areas'. The returned vector MUST be sorted.
/// This function is called from debthread.
/// \retval  -3  use idb segmentation
/// \retval  -2  no changes
/// \retval  -1  the process does not exist anymore
/// \retval   0  failed
/// \retval   1  new memory layout is returned
int idaapi uni_get_memory_info(meminfo_vec_t &areas, qstring * /*errbuf*/) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    qstring msgbuf;
    msg("uni_get_memory_info called\n");
#endif
    uc_mem_region *regions;
    uint32_t count;
    uc_err err = uc_mem_regions(uc->uc, &regions, &count);
#ifdef DEBUG
    msg("uc_mem_regions returned\n");
#endif
    if (err == UC_ERR_OK) {
        for (uint32_t i = 0; i < count; i++) {
            memory_info_t mem;
            mem.start_ea = (ea_t)regions[i].begin;
            mem.end_ea = (ea_t)regions[i].end - 1;   //-1 because uc_mem_region is inclusive
            mem.perm = uc_to_ida_perms_map[regions[i].perms];
            mem.bitness = 1;  //default to 32
            if (uc->debug_mode & UC_MODE_16) {
                mem.bitness = 0;
            } else if (uc->debug_mode & UC_MODE_64) {
                mem.bitness = 2;
            }
            areas.push_back(mem);
#ifdef DEBUG
            msgbuf.sprnt("   region %d: %p-%p (%d-%d:%d)\n", i,
                     (void*)mem.start_ea, (void*)mem.end_ea, mem.perm, regions[i].perms, mem.bitness);
            msg("%s", msgbuf.c_str());
#endif
        }
        uc_free(regions);
#ifdef DEBUG
        msg("uc_mem_regions returned %d regions\n", count);
#endif
    } else {
        msg("Failed on uc_mem_regions() with error returned %u: %s\n", err, uc_strerror(err));
    }
    return 1;
}

/// Read process memory.
/// Returns number of read bytes.
/// This function is called from debthread.
/// \retval 0  read error
/// \retval -1 process does not exist anymore
ssize_t idaapi uni_read_memory(ea_t ea, void *buffer, size_t size, qstring * /*errbuf*/) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    qstring msgbuf;
    msgbuf.sprnt("uni_read_memory called for %p:%d\n", (void*)ea, size);
    msg("%s", msgbuf.c_str());
#endif
    uc_err err = uc_mem_read(uc->uc, ea, buffer, size);
    if (err != UC_ERR_OK) {
        msg("Failed on uc_mem_read() with error returned %u: %s\n", err, uc_strerror(err));
    }
    return size;
}

/// Write process memory.
/// This function is called from debthread.
/// \return number of written bytes, -1 if fatal error
ssize_t idaapi uni_write_memory(ea_t ea, const void *buffer, size_t size, qstring * /*errbuf*/) {
    sk3wldbg *uc = (sk3wldbg*)dbg;
#ifdef DEBUG
    qstring msgbuf;
    msgbuf.sprnt("uni_write_memory called for %p:%u\n", (void*)ea, (uint32_t)size);
    msg("%s", msgbuf.c_str());
#endif
    uc_err err = uc_mem_write(uc->uc, ea, buffer, size);
    if (err != UC_ERR_OK) {
        msg("Failed on uc_mem_write() with error returned %u: %s\n", err, uc_strerror(err));
    }
    return size;
}

/// Is it possible to set breakpoint?.
/// This function is called from debthread or from the main thread if debthread
/// is not running yet.
/// It is called to verify hardware breakpoints.
/// \return ref BPT_
int idaapi uni_is_ok_bpt(bpttype_t type, ea_t ea, int /*len*/) {
#ifdef DEBUG
    qstring msgbuf;
    msgbuf.sprnt("uni_is_ok_bpt called for %p, type: %d\n", (void*)ea, type);
    msg("%s", msgbuf.c_str());
#endif
    //*** test type and setup appropriate actions in hook functions to break
    //    when appropriate
    switch (type) {
        case BPT_EXEC:    //hardware bpt
        case BPT_SOFT:
            //code bpt
            return BPT_OK;
        case BPT_RDWR:
        case BPT_WRITE:
            //data wpt
            //need to make sure read/write hook is installed
        default:
            return BPT_BAD_TYPE;
    }
    return BPT_OK;
}

/// Add/del breakpoints.
/// bpts array contains nadd bpts to add, followed by ndel bpts to del.
/// This function is called from debthread.
/// \return number of successfully modified bpts, -1 if network error
int idaapi uni_update_bpts(int *nbpts, update_bpt_info_t *bpts, int nadd, int ndel, qstring * /*errbuf*/) {
#ifdef DEBUG
    msg("uni_update_bpts called\n");
#endif
    int processed = 0;
    sk3wldbg *uc = (sk3wldbg*)dbg;
    for (int i = 0; i < nadd; i++) {
        uint8_t orig;
        uc_err err = uc_mem_read(uc->uc, bpts[i].ea, &orig, 1);
        if (err == UC_ERR_OK) {
            bpts[i].orgbytes.push_back(orig);
            processed++;
            uc->add_bpt(bpts[i].ea);
        }
    }
    for (int i = nadd; i < (nadd + ndel); i++) {
        uc->del_bpt(bpts[i].ea);
        processed++;
    }
    *nbpts = processed;
    return DRC_OK;
}

/// Update low-level (server side) breakpoint conditions.
/// This function is called from debthread.
/// \return nlowcnds. -1-network error
int idaapi uni_update_lowcnds(int *nupdated, const lowcnd_t * /*lowcnds*/, int nlowcnds, qstring * /*errbuf*/) {
#ifdef DEBUG
    msg("uni_update_lowcnds called\n");
#endif
    warning("TITLE Under Construction\nICON INFO\nAUTOHIDE NONE\nHIDECANCEL\nConditional breakpoints are currently unimplemented");
    *nupdated = nlowcnds;
    return DRC_OK;
}

/// \name Remote file
/// Open/close/read a remote file.
/// These functions are called from the main thread
/// -1-error
int idaapi uni_open_file(const char *file, uint64 * /*fsize*/, bool /*readonly*/) {
#ifdef DEBUG
    msg("uni_open_file called (%s)\n", file);
#endif
    return -1;
}

void idaapi uni_close_file(int /*fn*/) {
#ifdef DEBUG
    msg("uni_close_file called\n");
#endif
    return;
}

ssize_t idaapi uni_read_file(int /*fn*/, int64 /*off*/, void * /*buf*/, size_t /*size*/) {
#ifdef DEBUG
    msg("uni_read_file called\n");
#endif
    return -1;
}

/// Map process address.
/// This function may be absent.
/// This function is called from debthread.
/// \param off      offset to map
/// \param regs     current register values. if regs == NULL, then perform
///                 global mapping, which is independent on used registers
///                 usually such a mapping is a trivial identity mapping
/// \param regnum   required mapping. maybe specified as a segment register number
///                 or a regular register number if the required mapping can be deduced
///                 from it. for example, esp implies that ss should be used.
/// \return mapped address or #BADADDR
ea_t idaapi uni_map_address(ea_t off, const regval_t * /*regs*/, int /*regnum*/) {
    ea_t res = BADADDR;
/* TODO
   Lots to be done here. Need to lookup associated segment bas, then add offset
   and check against limit. Return valuse is either base + offset or BADADDR
   For this and other functions, need some helpers that read segment descriptors
*/

/*
    qstring msgbuf;
    msgbuf.sprnt("uni_map_address called for %p\n", (void*)off);
    msg("%s", msgbuf.c_str());
*/
/*
    meminfo_vec_t mv;
    uni_get_memory_info(mv);
    for (int i = 0; i < mv.size(); i++) {
        if (mv[i].contains(off)) {
            res = off;
            break;
        }
    }
 */
    return off;
}

/// Set debugger options (parameters that are specific to the debugger module).
/// See the definition of ::set_options_t for arguments.
/// See the convenience function in dbg.hpp if you need to call it.
/// The kernel will call this function after reading the debugger specific
/// config file (arguments are: keyword="", type=#IDPOPT_STR, value="")
/// This function is optional.
/// This function is called from the main thread
//Called with keyword == NULL indicates user has selected "Set specific options" button
// in IDA's Debugger setup dialog
const char *idaapi uni_set_dbg_options(const char *keyword, int /*pri*/,
                                int value_type, const void *value) {
//   msg("uni_set_dbg_options called: %s\n", keyword);
    if (value_type == IDPOPT_STR) {
        msg("   option value: %s\n", (char*)value);
    }
    return IDPOPT_OK;
}

/// Get pointer to debugger specific functions.
/// This function returns a pointer to a structure that holds pointers to
/// debugger module specific functions. For information on the structure
/// layout, please check the corresponding debugger module. Most debugger
/// modules return NULL because they do not have any extensions. Available
/// extensions may be called from plugins.
/// This function is called from the main thread.
const void *idaapi uni_get_debmod_extensions(void) {
#ifdef DEBUG
    msg("uni_get_debmod_extensions called\n");
#endif
    return NULL;
}

/// Calculate the call stack trace.
/// This function is called when the process is suspended and should fill
/// the 'trace' object with the information about the current call stack.
/// If this function is missing or returns false, IDA will use the standard
/// mechanism (based on the frame pointer chain) to calculate the stack trace
/// This function is called from the main thread.
/// \return success
bool idaapi uni_update_call_stack(thid_t /*tid*/, call_stack_t * /*trace*/) {
#ifdef DEBUG
   msg("uni_update_call_stack called\n");
#endif
   warning("TITLE Under Construction\nICON INFO\nAUTOHIDE NONE\nHIDECANCEL\nStack trace is currently unimplemented");
   return false;
}

/// Call application function.
/// This function calls a function from the debugged application.
/// This function is called from debthread
/// \param func_ea      address to call
/// \param tid          thread to use
/// \param fti          type information for the called function
/// \param nargs        number of actual arguments
/// \param regargs      information about register arguments
/// \param stkargs      memory blob to pass as stack arguments (usually contains pointed data)
///                     it must be relocated by the callback but not changed otherwise
/// \param retregs      function return registers.
/// \param[out] errbuf  the error message. if empty on failure, see 'event'.
///                     should not be filled if an appcall exception
///                     happened but #APPCALL_DEBEV is set
/// \param[out] event   the last debug event that occurred during appcall execution
///                     filled only if the appcall execution fails and #APPCALL_DEBEV is set
/// \param options      appcall options, usually taken from \inf{appcall_options}.
///                     possible values: combination of \ref APPCALL_  or 0
/// \return ea of stkargs blob, #BADADDR if failed and errbuf is filled
ea_t idaapi uni_appcall(
     ea_t /*func_ea*/,
     thid_t /*tid*/,
     const struct func_type_data_t * /*fti*/,
     int /*nargs*/,
     const struct regobjs_t * /*regargs*/,
     struct relobj_t * /*stkargs*/,
     struct regobjs_t * /*retregs*/,
     qstring * /*errbuf*/,
     debug_event_t * /*event*/,
     int /*options*/) {

#ifdef DEBUG
   msg("uni_appcall called\n");
#endif
   warning("TITLE Under Construction\nICON INFO\nAUTOHIDE NONE\nHIDECANCEL\nappcall is currently unimplemented");
   return BADADDR;

/*
   sk3wldbg *uc = (sk3wldbg*)dbg;
   if (!uc->save_registers()) {
      *errbuf = "Failed to save current register values";
      return BADADDR;
   }
   uint64_t addr_size = (inf.lflags & LFLG_64BIT) ? 8 :4;
   uint64_t curr_sp = uc->get_sp() & ~0xf; //16 byte align for starters
   curr_sp -= stkargs->size();  //claim the space we need for stack args
   if (uc->call_changes_sp()) {
      //if return address gets saved on the stack account for it
      curr_sp -= addr_size;
   }

   curr_sp &= ~0xf;   //and realign

   if (stkargs->relocate((ea_t)curr_sp, false) == 0) {
      *errbuf = "Failed to relocate stack args";
      return BADADDR;
   }

   //need an address that won't get hit during normal execution of the appcall
   uint64_t appcall_brk = addr_size == 8 ? 0x4141414141414141LL : 0x41414141;
   uc->add_bpt(appcall_brk);

   uc->save_ret_addr(curr_sp);
   //write the stack arguments into the stack
   uc_mem_write(uc->uc, curr_sp + (uc->call_changes_sp() ? addr_size : 0), stkargs->begin(), (size_t)stkargs->size());

   //copy regargs into parameter registers

   //copy parameter registers
   for (uint32_t i = 0; i < regargs->size(); i++) {
      const regobj_t &ri = regargs->at(i);
      int regidx = ri.regidx;
      if (ri.relocate && (ri.size() <= addr_size)) {
         uint64_t relocated = 0;
         memcpy(&relocated, ri.value.begin(), ri.size());
         relocated += curr_sp;
         uc_reg_write(uc->uc, uc->reg_map[regidx], &relocated);
      } else {
         uc_reg_write(uc->uc, uc->reg_map[regidx], ri.value.begin());
      }
   }
   uc->set_pc(func_ea);

   //continue execution until we hit the appcall_brk

   if ((options & APPCALL_MANUAL) != 0) {
      return (ea_t)curr_sp;
   }

   //some registers hold return values
   // Retrieve the return value
   if (retregs != NULL) {
      for (uint32_t i = 0; i < retregs->size(); i++) {
         regobj_t &r = retregs->at(i);
         regval_t rv;
         if (uc->read_register(r.regidx, &rv)) {
            memcpy(r.value.begin(), &rv.ival, r.value.size());
            r.relocate = false;
         }
      }
   }

   //now restore pre-appcall context
   uc->restore_registers();
   uc->del_bpt(appcall_brk);

   return (ea_t)curr_sp;
*/
}

/// Cleanup after appcall().
/// The debugger module must keep the stack blob in the memory until this function
/// is called. It will be called by the kernel for each successful appcall().
/// There is an exception: if #APPCALL_MANUAL, IDA may not call cleanup_appcall.
/// If the user selects to terminate a manual appcall, then cleanup_appcall will be called.
/// Otherwise, the debugger module should terminate the appcall when the called
/// function returns.
/// This function is called from debthread.
/// \retval  2  ok, there are pending events
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi uni_cleanup_appcall(thid_t /*tid*/) {
#ifdef DEBUG
   msg("uni_cleanup_appcall called\n");
#endif
   return 1;

/*
   sk3wldbg *uc = (sk3wldbg*)dbg;
   uc->restore_registers();

   //remove breakpoint at end of function
*/
}

/// Evaluate a low level breakpoint condition at 'ea'.
/// Other evaluation errors are displayed in a dialog box.
/// This call is rarely used by IDA when the process has already been suspended
/// for some reason and it has to decide whether the process should be resumed
/// or definitely suspended because of a breakpoint with a low level condition.
/// This function is called from debthread.
/// \retval  1  condition is satisfied
/// \retval  0  not satisfied
/// \retval -1  network error
int idaapi uni_eval_lowcnd(thid_t /*tid*/, ea_t ea, qstring * /*errbuf*/) {
#ifdef DEBUG
   qstring msgbuf;
   msgbuf.sprnt("uni_eval_lowcnd called: %p\n", (void*)ea);
   msg("%s", msgbuf.c_str());
#endif
//   warning("TITLE Under Construction\nICON INFO\nAUTOHIDE NONE\nHIDECANCEL\nConditional breakpoints are currently unimplemented");
   return 1;
}

/// This function is called from main thread
ssize_t idaapi uni_write_file(int /*fn*/, int64 /*off*/, const void * /*buf*/, size_t /*size*/) {
#ifdef DEBUG
   msg("uni_write_file called\n");
#endif
   return -1;
}

/// Perform a debugger-specific function.
/// This function is called from debthread
int idaapi uni_send_ioctl(int /*fn*/, const void * /*buf*/, size_t /*size*/, void ** /*poutbuf*/, ssize_t * /*poutsize*/) {
#ifdef DEBUG
   msg("uni_send_ioctl called\n");
#endif
   return -1;
}

/// Enable/Disable tracing.
/// "trace_flags" can be a set of STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE.
/// See thread_t::trace_mode in debugger.h.
/// This function is called from the main thread.
bool idaapi uni_dbg_enable_trace(thid_t /*tid*/, bool /*enable*/, int /*trace_flags*/) {
#ifdef DEBUG
   msg("uni_dbg_enable_trace called\n");
#endif
   warning("TITLE Under Construction\nICON INFO\nAUTOHIDE NONE\nHIDECANCEL\naTracing is currently unimplemented");
   return false;
}

/// Is tracing enabled? ONLY used for tracers.
/// "trace_bit" can be one of the following: STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE
bool idaapi uni_is_tracing_enabled(thid_t /*tid*/, int /*tracebit*/) {
#ifdef DEBUG
   msg("uni_is_tracing_enabled called\n");
#endif
   return false;
}

/// Execute a command on the remote computer.
/// \return exit code
int idaapi uni_rexec(const char *cmdline) {
#ifdef DEBUG
   msg("uni_rexec called (%s)\n", cmdline);
#endif
   return 0;
}

/// Get (store to out_pattrs) process/debugger-specific runtime attributes.
/// This function is called from main thread.
void idaapi uni_get_debapp_attrs(debapp_attrs_t *out_pattrs) {
#ifdef DEBUG
   msg("uni_get_debapp_attrs called\n");
#endif
#if IDA_SDK_VERSION < 730
   bool is64 = (inf.lflags & LFLG_64BIT) != 0;
   filetype_t filetype = (filetype_t)inf.filetype;
#else
   bool is64 = inf_is_64bit();
   filetype_t filetype = inf_get_filetype();
#endif
   out_pattrs->addrsize = is64 ? 8 :4;
   if (filetype == f_PE) {
      if (is64) {
         out_pattrs->platform = "win64";
      } else {
         out_pattrs->platform = "win32";
      }
   } else if (filetype == f_ELF) {
      if (is64) {
         out_pattrs->platform = "linux64";
      } else {
         out_pattrs->platform = "linux";
      }
   } else if (filetype == f_MACHO) {
      if (is64) {
         out_pattrs->platform = "macosx64";
      } else {
         out_pattrs->platform = "macosx";
      }
   } else {
      out_pattrs->platform = "unk";
   }
   return;
}

bool idaapi uni_get_srcinfo_path(qstring *path, ea_t base) {
   return false;
}

drc_t uni_bin_search(ea_t * /*ea*/, ea_t /*start_ea*/, ea_t /*end_ea*/,
                     const compiled_binpat_vec_t * /*ptns*/, int /*srch_flags*/,
                     qstring * /*errbuf*/) {
   return DRC_NONE;
}

sk3wldbg::sk3wldbg(const char *procname, uc_arch arch, uc_mode mode, const char *cpu_model) {
   version = IDD_INTERFACE_VERSION;
   uc = NULL;
   name = "sk3wldbg";
   debug_arch = arch;
   debug_mode = mode;
   if (cpu_model != NULL) {
      this->cpu_model = cpu_model;
   }
   evt_mutex = qmutex_create();
   run_sem = qsem_create(NULL, 0);
   pause_sem = qsem_create(NULL, 0);
   emu_state = RS_INIT;
   resume_mode = RS_RUN;
   process_thread = NULL;
   saved = NULL;
   h_code_hook = 0;
   h_mem_fault_hook = 0;
   h_ihook = 0;
   
   which_hook = UC_HOOK_NONE;
   
   thumb = 0;

#ifdef __NT__
   hProv = NULL;
#else
   hProv = -1;
#endif

   do_suspend = false;
   finished = false;
   single_step = false;
   registered_menu = false;
   bool is_be = inf_is_be();
   if (is_be) {
      debug_mode = (uc_mode)((int)UC_MODE_BIG_ENDIAN | (int)debug_mode);
      msg("sk3wldbg: Setting Big-Endian mode\n");
   }

   id = 0x100;       //debugger id. Can we use one of the existing constants?
   processor = procname;
   flags =   DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_SAFE | DBG_FLAG_DEBTHREAD
           | DBG_FLAG_DEBUG_DLL | DBG_FLAG_ANYSIZE_HWBPT
           | DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPARAMETERS | DBG_FLAG_NOPASSWORD;
            /* maybe use DBG_FLAG_FAKE_MEMORY also */
   flags2 = DBG_HAS_GET_PROCESSES | DBG_HAS_DETACH_PROCESS | DBG_HAS_REQUEST_PAUSE |
            DBG_HAS_SET_EXCEPTION_INFO | DBG_HAS_THREAD_SUSPEND | DBG_HAS_THREAD_CONTINUE |
            DBG_HAS_SET_RESUME_MODE | DBG_HAS_CHECK_BPT;

   filetype = inf_get_filetype();

   memory_page_size = 0x1000;
   memmgr = NULL;

   //SET THE FOLLOWING IN YOUR PROCESSOR SPECIFIC SUBCLASS
   regclasses = NULL;
   default_regclasses = 0;    ///< Mask of default printed register classes
   registers = NULL;               ///< Array of registers. Use registers() to access it
   nregs = 0;              ///< Number of registers
   bpt_bytes = NULL;                ///< Array of bytes for a breakpoint instruction
   bpt_size = 0;                    ///< Size of this array

   resume_modes = DBG_RESMOD_STEP_INTO | DBG_RESMOD_STEP_OVER | DBG_RESMOD_STEP_OUT;
                  /* maybe also RESMOD_HANDLE */

   set_dbg_options = uni_set_dbg_options;

   callback = idd_hook;
}

sk3wldbg::~sk3wldbg(void) {
   qmutex_free(evt_mutex);
   qsem_free(run_sem);
   qsem_free(pause_sem);
   if (hProv) {
#ifdef __NT__
      CryptReleaseContext(hProv, 0);
#else
      ::close(hProv);
#endif
   }
   if (memmgr) {
      //is this going to take care of all the mappings
      //replace the memmap vector with this???
      delete memmgr;
      memmgr = NULL;
   }
   for (vector<void*>::iterator i = memmap.begin(); i != memmap.end(); i++) {
      qfree(*i);
   }
}

void sk3wldbg::enqueue_debug_evt(debug_event_t &evt) {
#ifdef DEBUG
   qstring msgbuf;
   msgbuf.sprnt("Queueing event eid = %d, ea = %p\n", evt.eid(), (void*)evt.ea);
   msg("%s", msgbuf.c_str());
#endif
   qmutex_lock(evt_mutex);
   dbg_evt_list.push_back(evt);
   qmutex_unlock(evt_mutex);
}

bool sk3wldbg::dequeue_debug_evt(debug_event_t *out) {
   if (debug_queue_len() == 0) {
      return false;
   }
   qmutex_lock(evt_mutex);
   *out = dbg_evt_list.front();
   dbg_evt_list.pop_front();
   qmutex_unlock(evt_mutex);
   return true;
}

void sk3wldbg::close(void) {
   if (h_code_hook) {
      uc_hook_del(uc, h_code_hook);
      h_code_hook = 0;
   }
   if (h_mem_fault_hook) {
      uc_hook_del(uc, h_mem_fault_hook);
      h_mem_fault_hook = 0;
   }
   if (h_ihook) {
      uc_hook_del(uc, h_ihook);
      h_ihook = 0;
   }

   detach_action_from_menu("Debugger/Take memory snapshot", "sk3wldbg:mem_map");

//   safe_msg req("sk3wldbg: closing unicorn instance\n");
//   execute_sync(req, MFF_FAST);
//   msg("sk3wldbg: closing unicorn instance\n");
   uc_close(uc);
//   uc = NULL;
}

void sk3wldbg::runtime_exception(uc_err err, uint64_t pc) {
     qstring errmsg;
#ifdef DEBUG
     errmsg.sprnt("runtime_exception(0x%x, %p)", (uint32_t)err, (void*)pc);
     msg("%s\n", errmsg);
#endif
    switch (err) {
        case UC_ERR_READ_UNMAPPED:
            errmsg.sprnt("The instruction at %p attempted to read from unmapped memory", (void*)pc);
            break;
        case UC_ERR_WRITE_UNMAPPED:
            errmsg.sprnt("The instruction at %p attempted to write to unmapped memory", (void*)pc);
            break;
        case UC_ERR_FETCH_UNMAPPED:
            errmsg.sprnt("The instruction at %p attempted to execute from unmapped memory", (void*)pc);
            break;
        case UC_ERR_WRITE_PROT:
            errmsg.sprnt("The instruction at %p attempted to write to write protected memory", (void*)pc);
            break;
        case UC_ERR_READ_PROT:
            errmsg.sprnt("The instruction at %p attempted to read from read protected unmapped memory", (void*)pc);
            break;
        case UC_ERR_FETCH_PROT:
            errmsg.sprnt("The instruction at %p attempted to fetch from NX memory", (void*)pc);
            break;
    }
    queue_exception_event(11, pc, errmsg.c_str());
}

void sk3wldbg::start(uint64_t pc) {
    init_session();
    check_mode((ea_t)pc);
    qsem_wait(run_sem, -1);
    //not a fan of mentioning thumb here, need to push this back down to ARM specific code
    //to force unicorn to begin in thumb mode, low bit of address needs to be set
    uc_err err = uc_emu_start(uc, pc | thumb, (uint64_t)-1, 0, 0);
    if (err != UC_ERR_OK) {
        runtime_exception(err, get_pc());
    }
}

void sk3wldbg::pause(void) {
    emu_state = RS_PAUSE;
    // now wait until unicorn thread sees the pause and signals us
    qsem_wait(pause_sem, -1);
}

void sk3wldbg::resume(void) {
    emu_state = RS_RUN;
    qsem_post(run_sem);
}

bool sk3wldbg::open(void) {
#ifdef DEBUG
    msg("uc_open mode is 0x%0x\n", debug_mode);
#endif
    uc_err err = uc_open(debug_arch, debug_mode, &uc);
    if (err) {
        msg("Failed on uc_open() with error returned: %u\n", err);
        return false;
    }
    memmgr = new mem_mgr(uc);
    //msg("sk3wldbg::open uc == %p, memmgr = %p\n", this, memmgr);
    install_initial_hooks();
    return true;
}

void sk3wldbg::init_memmgr(uint64_t map_min, uint64_t map_max) {
    if (memmgr == NULL) {
        memmgr = new mem_mgr(uc, map_min, map_max);
    } else {
        memmgr->set_mmap_region(map_min, map_max);
    }
}

void sk3wldbg::map_mem_copy(uint64_t startAddr, uint64_t endAddr, unsigned int perms, void *src) {
   uint64_t exact = endAddr - startAddr;
   char *block = (char*)map_mem_zero(startAddr, endAddr, perms, SDB_MAP_FIXED);
   if (block) {
      memcpy(block, src, (size_t)exact);
   }
}

/*
void *sk3wldbg::map_mem_zero(uint64_t startAddr, uint64_t endAddr, unsigned int perms) {
   qstring msgbuf;
   msgbuf.sprnt("map_mem_zero(%p, %p, 0x%x)\n", (void*)startAddr, (void*)endAddr, perms);
   msg("%s", msgbuf.c_str());
   endAddr = (endAddr + 0xfff) & ~0xfff;
   uint64_t pageAddr = startAddr & ~0xfff;
   uint64_t blockSize = endAddr - pageAddr;
   void *block = qcalloc((size_t)blockSize, 1);
   if (block) {
      uc_err err = uc_mem_map_ptr(uc, pageAddr, (size_t)blockSize, perms, block);
      if (err != UC_ERR_OK) {
         msg("Failed on uc_mem_map() with error returned %u: %s\n", err, uc_strerror(err));
         qfree(block);
      } else {
         memmap.push_back(block);
         //return a pointer to the byte corresponding to startAddr
         //this may not be the first byte of block if startAddr was not page aligned
         return (startAddr - pageAddr) + (char*)block;
      }
   }
   return NULL;
}
*/

void *sk3wldbg::map_mem_zero(uint64_t startAddr, uint64_t endAddr, unsigned int perms, uint32_t flags) {
   qstring msgbuf;
   msgbuf.sprnt("map_mem_zero(%p, %p, 0x%x)\n", (void*)startAddr, (void*)endAddr, perms);
   msg("%s", msgbuf.c_str());
   endAddr = (endAddr + 0xfff) & ~0xfff;
   uint64_t pageAddr = startAddr & ~0xfff;
   uint64_t blockSize = endAddr - pageAddr;
   if (blockSize & 0xffffffff00000000ll) {
      //too large
      msg("Size too large in map_mem_zero\n");
      return NULL;
   }
   // for now we cheat and make all sections rwx in unicorn to easily handle self modifying code
   // we would need to handle mprotect and VirtualProtect-like functions to catch permission changes
   perms = UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC;
   map_block *b = memmgr->mmap(pageAddr, (uint32_t)blockSize, perms, flags);
   if (b) {
      //return a pointer to the byte corresponding to startAddr
      //this may not be the first byte of block if startAddr was not page aligned
      msgbuf.sprnt("Allocated at %p in map_mem_zero\n", (void*)startAddr);
      msg("%s", msgbuf.c_str());
      return (startAddr - pageAddr) + (char*)b->host;
   }
   msgbuf.sprnt("Failed to allocate at %p in map_mem_zero\n", (void*)startAddr);
   msg("%s", msgbuf.c_str());
   return NULL;
}

void sk3wldbg::getRandomBytes(void *buf, unsigned int len) {
#ifdef __NT__
   if (hProv == 0) {
      CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
   }
   CryptGenRandom(hProv, len, (BYTE*)buf);
#else
   if (hProv == -1) {
      hProv = ::open("/dev/urandom", O_RDONLY);
   }
   read(hProv, buf, len);
#endif
}

void sk3wldbg::add_bpt(uint64_t bpt_addr) {
#ifdef DEBUG
   qstring msgbuf;
   msgbuf.sprnt("add_bpt: %p\n", (void*)bpt_addr);
   msg("%s", msgbuf.c_str());
#endif
   breakpoints.insert(bpt_addr);
}

void sk3wldbg::del_bpt(uint64_t bpt_addr) {
#ifdef DEBUG
   qstring msgbuf;
   msgbuf.sprnt("del_bpt: %p\n", (void*)bpt_addr);
   msg("%s", msgbuf.c_str());
#endif
   breakpoints.erase(bpt_addr);
}

uint64_t sk3wldbg::get_pc(void) {
   uint64_t pc = 0;
   for (int i = 0; i < nregs; i++) {
      if (registers[i].flags & REGISTER_IP) {
         uc_err err = uc_reg_read(uc, reg_map[i], &pc);
         if (err == UC_ERR_OK) {
            return pc;
         }
         break;
      }
   }
   return (uint64_t)-1LL;
}

bool sk3wldbg::set_pc(uint64_t pc) {
#ifdef DEBUG
   qstring buf;
   buf.sprnt("set_pc called to set to %p\n", (void*)pc);
   msg("%s", buf.c_str());
#endif
   for (int i = 0; i < nregs; i++) {
      if (registers[i].flags & REGISTER_IP) {
         uc_err err = uc_reg_write(uc, reg_map[i], &pc);
         if (err == UC_ERR_OK) {
            return true;
         }
         break;
      }
   }
   return false;
}

uint64_t sk3wldbg::get_sp(void) {
   uint64_t sp = 0;
   for (int i = 0; i < nregs; i++) {
      if (registers[i].flags & REGISTER_SP) {
         uc_err err = uc_reg_read(uc, reg_map[i], &sp);
         if (err == UC_ERR_OK) {
            return sp;
         }
         break;
      }
   }
   return (uint64_t)-1LL;
}

bool sk3wldbg::set_sp(uint64_t sp) {
   for (int i = 0; i < nregs; i++) {
      if (registers[i].flags & REGISTER_SP) {
         uc_err err = uc_reg_write(uc, reg_map[i], &sp);
         if (err == UC_ERR_OK) {
            return true;
         }
         break;
      }
   }
   return false;
}

void sk3wldbg::intr_hook(uint32_t intno) {
   qstring errmsg;
#ifdef DEBUG
   errmsg.sprnt("intr_hook(0x%x)\n", intno);
   msg("%s", errmsg.c_str());
#endif
}

void generic_intr_hook(uc_engine *uc, uint32_t intno, sk3wldbg *dbg) {
    dbg->which_hook = UC_HOOK_INTR;
    dbg->intr_hook(intno);
    dbg->which_hook = UC_HOOK_NONE;
}

bool sk3wldbg::mem_fault_hook(uc_mem_type type, uint64_t address,
                              int /*size*/, int64_t value) {
   uint64_t pc = get_pc();
   qstring errmsg;
#ifdef DEBUG
   errmsg.sprnt("mem_fault_hook(0x%x, %p)\n", (uint32_t)type, (void*)address);
   msg("%s", errmsg);
#endif
   switch (type) {
      case UC_MEM_READ_UNMAPPED:
        errmsg.sprnt("The instruction at %p attempted to read from unmapped memory", (void*)pc);
         break;
      case UC_MEM_WRITE_UNMAPPED:
        errmsg.sprnt("The instruction at %p attempted to write to unmapped memory", (void*)pc);
         break;
      case UC_MEM_FETCH_UNMAPPED:
        errmsg.sprnt("The instruction at %p attempted to execute from unmapped memory", (void*)pc);
         break;
      case UC_MEM_WRITE_PROT:
        errmsg.sprnt("The instruction at %p attempted to write to write protected memory", (void*)pc);
         break;
      case UC_MEM_READ_PROT:
        errmsg.sprnt("The instruction at %p attempted to read from read protected unmapped memory", (void*)pc);
         break;
      case UC_MEM_FETCH_PROT:
        errmsg.sprnt("The instruction at %p attempted to fetch from NX memory", (void*)pc);
         break;
   }
   queue_exception_event(11, address, errmsg.c_str());
   return false;
}

bool generic_mem_fault_hook(uc_engine *uc, uc_mem_type type, uint64_t address,
                                int size, int64_t value, sk3wldbg *dbg) {
    bool res;
    dbg->which_hook = UC_HOOK_MEM_INVALID;
    res = dbg->mem_fault_hook(type, address, size, value);
    dbg->which_hook = UC_HOOK_NONE;
    return res;
}

//This function is called from within the unicorn thread
//We do all checking for debugger related events at each instruction here
void sk3wldbg::code_hook(uint64_t address, uint32_t size) {
   bool stopping = false;
#ifdef DEBUG
   qstring buf;
   buf.sprnt("code hit at: %p, expecting to exec %p\n", (void*)address, (void*)get_dword((ea_t)address));
   uint64_t tpc = get_pc();
   do_safe_msg(buf.c_str());
   uint32_t opc;
   uc_mem_read(uc, address, &opc, sizeof(opc));
   buf.sprnt("really executing code bytes: 0x%x\n", opc);
   do_safe_msg(buf.c_str());
/*
   uint32_t *cp = (uint32_t*)memmgr->to_host_ptr(address);
   if (cp == NULL) {
      buf.sprnt("dereffing mem ptr yields a NULL ptr\n");
   } else {
      buf.sprnt("dereffing mem ptr yields 0x%x\n", *cp);
   }
   do_safe_msg(buf.c_str());
*/
#endif
   bool is_brk = false;
   if (breakpoints.find((ea_t)address) != breakpoints.end()) {
      //this is a breakpoint
      set_state(RS_BREAK);
      //tell IDA we hit a breakpoint
      queue_bpt_event(false);
      is_brk = true;
#ifdef DEBUG
      do_safe_msg("This is a breakpoint\n");
#endif
   }
   if (tbreaks.find((ea_t)address) != tbreaks.end() || is_stepping()) {
      //this is a temproary breakpoint
      tbreaks.erase((ea_t)address);
      if (!is_brk) {
         //don't want to queue both a breakpoint and a step event at same address
         set_state(RS_BREAK);
         queue_step_event(address);
      }
      clear_stepping();
#ifdef DEBUG
      do_safe_msg("This is a step break\n");
#endif
   }
#ifdef DEBUG
   buf.sprnt("emu_state: %d\n", get_state());
   do_safe_msg(buf.c_str());
#endif
   switch (get_state()) {
      case RS_PAUSE:
         //we are paused until user causes qsem_post to get called
         //let the gui thread know we are paused, then wait like all other states
         qsem_post(pause_sem);
      case RS_BREAK:
         //need to wait for resume from user
      case RS_INIT:
         //first time in, wait for the signal to go
#ifdef DEBUG
         do_safe_msg("code_hook is waiting\n");
#endif
         qsem_wait(run_sem, -1);
#ifdef DEBUG
         do_safe_msg("code_hook done waiting\n");
#endif
         //at this point user wants to run or term
         break;
      case RS_RUN:
         //no need to stop if we are running
         break;
      case RS_STEP_INTO:
         //indicate we want to break at next instruction
         set_stepping();
         break;
      case RS_STEP_OVER:
         //add a breakpoint at the return address
         tbreaks.insert((ea_t)address + size);
         //and keep running
         break;
      case RS_STEP_OUT:
         //*** not implemented, start balancing calls (+1) against rets (-1) until count == -1
         set_stepping();
//         dbg->tbreaks.insert((ea_t)address + size);
         break;
      case RS_TERM:
         //break out of emulation loop
         uc_emu_stop(uc);
         stopping = true;
         break;
   }

#ifdef DEBUG
   ea_t cpc = (ea_t)get_pc();
   buf.sprnt("pc out of break is: %p\n", (void*)cpc);
   do_safe_msg(buf.c_str());
#endif

   uint8_t *inst = new uint8_t[size]; //change over to to_host_ptr when mem_mgr gets integrated
   uc_mem_read(uc, address, inst, size);
   if (!stopping && is_system_call(inst, size)) {
      handle_system_call(inst, size);
   }
   delete [] inst;

#ifdef DEBUG
   cpc = (ea_t)get_pc();
   buf.sprnt("pc leaving is: %p\n", (void*)cpc);
   do_safe_msg(buf.c_str());
#endif

}

//This function is called from within the unicorn thread
//We do all checking for debugger related events at each instruction here
void generic_code_hook(uc_engine *uc, uint64_t address, uint32_t size, sk3wldbg *dbg) {
    dbg->which_hook = UC_HOOK_CODE;
    dbg->code_hook(address, size);
    dbg->which_hook = UC_HOOK_NONE;
}

run_state sk3wldbg::get_state(void) {
   return emu_state;
}

void sk3wldbg::set_state(run_state new_state) {
   emu_state = new_state;
}

void sk3wldbg::install_initial_hooks(void) {
   uc_err err = uc_hook_add(uc, &h_code_hook, UC_HOOK_CODE, (void*)generic_code_hook, this, 1, 0);
   if (err) {
      h_code_hook = 0;
      msg("Failed on uc_hook_add(generic_code_hook) with error returned: %u\n", err);
   }
   err = uc_hook_add(uc, &h_mem_fault_hook, UC_HOOK_MEM_INVALID, (void*)generic_mem_fault_hook, this, 1, 0);
   if (err) {
      h_mem_fault_hook = 0;
      msg("Failed on uc_hook_add(generic_mem_fault_hook) with error returned: %u\n", err);
   }
   err = uc_hook_add(uc, &h_ihook, UC_HOOK_INTR, (void*)generic_intr_hook, this, 1, 0);
   if (err) {
      h_ihook = 0;
      msg("Failed on uc_hook_add(generic_intr_hook) with error returned: %u\n", err);
   }
}

bool sk3wldbg::read_register(int regidx, regval_t *value) {
   int32_t rtype = RVT_INT;
   op_dtype_t dt = registers[regidx].dtype;
   if (dt == dt_float || dt == dt_double) {
      rtype = RVT_FLOAT;
   }
   value->rvtype = rtype;
   return uc_reg_read(uc, reg_map[regidx], &value->ival) == UC_ERR_OK;
}

bool sk3wldbg::save_registers(void) {
   if (saved != NULL) {
      //this should not happen, but what if it does?
      qfree(saved);
      saved = NULL;
   }
   saved = (regval_t*)qalloc(sizeof(regval_t) * nregs);
   qstring errbuf;
   if (uni_read_registers(0, -1, saved, &errbuf) == 0) {
      qfree(saved);
      saved = NULL;
      return false;
   }
   return true;
}

bool sk3wldbg::restore_registers(void) {
   if (saved == NULL ) {
      return false;
   }
   for (int regidx = 0; regidx < nregs; regidx++) {
      uc_err err = uc_reg_write(uc, reg_map[regidx], &saved->ival);
   }
   qfree(saved);
   saved = NULL;
   return true;
}

//return non-zero to have ida refresh all windows
int idaapi mem_map_action_handler::activate(action_activation_ctx_t *ctx) {
   uint64_t base = 0;
   uint64_t size = 0x1000;
   uint16_t perms = 3;
   int ok;
   sk3wldbg *uc = (sk3wldbg*)dbg;
//   msg("mem_map_action_handler activated\n");
   ok = ask_form("Map Memory Region\n\n\n<Start address:L:18:20::>\n<Region size  :L:18:20::><Read:C>\n<Write:C>\n<Exec:C>>\n", &base, &size, &perms);
   if (ok) {
      if (base & 0xfff) {
         warning("AUTOHIDE NONE\nHIDECANCEL\nRegion base address must be page aligned");
      } else if (size & 0xfff) {
         warning("AUTOHIDE NONE\nHIDECANCEL\nRegion size must be page aligned");
      } else {
         //we need to make sure that unicorn is paused when we do this
//         uc_err err = uc_mem_map(uc->uc, base, (size_t)size, perms);
      }
   }
   return 0;
}

action_state_t idaapi mem_map_action_handler::update(action_update_ctx_t *ctx) {
//   msg("mem_map_action_handler::update called\n");
   return AST_ENABLE_ALWAYS;
}

static ssize_t idaapi idd_hook(void * /* ud */, int notification_code, va_list va) {
   sk3wldbg *uc = (sk3wldbg*)dbg;

   int retcode = DRC_NONE;
   qstring *errbuf;

   switch (notification_code) {
      case debugger_t::ev_init_debugger: {
         const char *hostname = va_arg(va, const char *);
         int portnum = va_arg(va, int);
         const char *password = va_arg(va, const char *);
         errbuf = va_arg(va, qstring *);
         return uni_init_debugger(hostname, portnum, password, errbuf);
      }

      case debugger_t::ev_term_debugger:
         return uni_term_debugger();

      case debugger_t::ev_get_processes: {
         procinfo_vec_t *procs = va_arg(va, procinfo_vec_t *);
         errbuf = va_arg(va, qstring *);
         return uni_get_processes(procs, errbuf);
      }

      case debugger_t::ev_start_process: {
         const char *path = va_arg(va, const char *);
         const char *args = va_arg(va, const char *);
         const char *startdir = va_arg(va, const char *);
         uint32 dbg_proc_flags = va_arg(va, uint32);
         const char *input_path = va_arg(va, const char *);
         uint32 input_file_crc32 = va_arg(va, uint32);
         errbuf = va_arg(va, qstring *);
         return uni_start_process(path, args, startdir, dbg_proc_flags,
                                input_path, input_file_crc32, errbuf);
      }

      case debugger_t::ev_attach_process: {
         pid_t pid = va_argi(va, pid_t);
         int event_id = va_arg(va, int);
         uint32 dbg_proc_flags = va_arg(va, uint32);
         errbuf = va_arg(va, qstring *);
         return uni_attach_process(pid, event_id, dbg_proc_flags, errbuf);
      }

      case debugger_t::ev_detach_process:
         return uni_detach_process();

      case debugger_t::ev_get_debapp_attrs: {
         debapp_attrs_t *out_pattrs = va_arg(va, debapp_attrs_t *);
         uni_get_debapp_attrs(out_pattrs);
         return DRC_OK;
      }

      case debugger_t::ev_rebase_if_required_to: {
         ea_t new_base = va_arg(va, ea_t);
         uni_rebase_if_required_to(new_base);
         return DRC_OK;
      }

      case debugger_t::ev_request_pause:
         errbuf = va_arg(va, qstring *);
         return uni_prepare_to_pause_process(errbuf);

      case debugger_t::ev_exit_process:
         errbuf = va_arg(va, qstring *);
         return uni_exit_process(errbuf);

      case debugger_t::ev_get_debug_event: {
         gdecode_t *code = va_arg(va, gdecode_t *);
         debug_event_t *event = va_arg(va, debug_event_t *);
         int timeout_ms = va_arg(va, int);
         *code = uni_get_debug_event(event, timeout_ms);
         return DRC_OK;
         break;
      }

      case debugger_t::ev_resume: {
         debug_event_t *event = va_arg(va, debug_event_t *);
         return uni_continue_after_event(event);
      }

      case debugger_t::ev_set_exception_info: {
         exception_info_t *info = va_arg(va, exception_info_t *);
         int qty = va_arg(va, int);
         uni_set_exception_info(info, qty);
         return DRC_OK;
      }

      case debugger_t::ev_suspended: {
         bool dlls_added = va_argi(va, bool);
         thread_name_vec_t *thr_names = va_arg(va, thread_name_vec_t *);
         uni_stopped_at_debug_event(thr_names, dlls_added);
         return DRC_OK;
      }

      case debugger_t::ev_thread_suspend: {
         thid_t tid = va_argi(va, thid_t);
         return uni_thread_suspend(tid);
      }

      case debugger_t::ev_thread_continue: {
         thid_t tid = va_argi(va, thid_t);
         return uni_thread_continue(tid);
      }

      case debugger_t::ev_set_resume_mode: {
         thid_t tid = va_argi(va, thid_t);
         resume_mode_t resmod = va_argi(va, resume_mode_t);
         return uni_set_resume_mode(tid, resmod);
      }

      case debugger_t::ev_read_registers: {
         thid_t tid = va_argi(va, thid_t);
         int clsmask = va_arg(va, int);
         regval_t *values = va_arg(va, regval_t *);
         errbuf = va_arg(va, qstring *);
         return uni_read_registers(tid, clsmask, values, errbuf);
      }

      case debugger_t::ev_write_register: {
         thid_t tid = va_argi(va, thid_t);
         int regidx = va_arg(va, int);
         const regval_t *value = va_arg(va, const regval_t *);
         errbuf = va_arg(va, qstring *);
         return uni_write_register(tid, regidx, value, errbuf);
      }

      case debugger_t::ev_thread_get_sreg_base: {
         ea_t *answer = va_arg(va, ea_t *);
         thid_t tid = va_argi(va, thid_t);
         int sreg_value = va_arg(va, int);
         errbuf = va_arg(va, qstring *);
         return uni_thread_get_sreg_base(answer, tid, sreg_value, errbuf);
      }

      case debugger_t::ev_get_memory_info: {
         meminfo_vec_t *ranges = va_arg(va, meminfo_vec_t *);
         errbuf = va_arg(va, qstring *);
         return uni_get_memory_info(*ranges, errbuf);
      }

      case debugger_t::ev_read_memory: {
         size_t *nbytes = va_arg(va, size_t *);
         ea_t ea = va_arg(va, ea_t);
         void *buffer = va_arg(va, void *);
         size_t size = va_arg(va, size_t);
         errbuf = va_arg(va, qstring *);
         ssize_t code = uni_read_memory(ea, buffer, size, errbuf);
         *nbytes = code >= 0 ? code : 0;
         return code >= 0 ? DRC_OK : DRC_NOPROC;
      }

      case debugger_t::ev_write_memory: {
         size_t *nbytes = va_arg(va, size_t *);
         ea_t ea = va_arg(va, ea_t);
         const void *buffer = va_arg(va, void *);
         size_t size = va_arg(va, size_t);
         errbuf = va_arg(va, qstring *);
         ssize_t code = uni_write_memory(ea, buffer, size, errbuf);
         *nbytes = code >= 0 ? code : 0;
         return code >= 0 ? DRC_OK : DRC_NOPROC;
      }

      case debugger_t::ev_check_bpt: {
         int *bptvc = va_arg(va, int *);
         bpttype_t type = va_argi(va, bpttype_t);
         ea_t ea = va_arg(va, ea_t);
         int len = va_arg(va, int);
         *bptvc = uni_is_ok_bpt(type, ea, len);
         return DRC_OK;
      }

      case debugger_t::ev_update_bpts: {
         int *nbpts = va_arg(va, int *);
         update_bpt_info_t *bpts = va_arg(va, update_bpt_info_t *);
         int nadd = va_arg(va, int);
         int ndel = va_arg(va, int);
         errbuf = va_arg(va, qstring *);
         return uni_update_bpts(nbpts, bpts, nadd, ndel, errbuf);
      }

      case debugger_t::ev_update_lowcnds: {
         int *nupdated = va_arg(va, int *);
         const lowcnd_t *lowcnds = va_arg(va, const lowcnd_t *);
         int nlowcnds = va_arg(va, int);
         errbuf = va_arg(va, qstring *);
         return uni_update_lowcnds(nupdated, lowcnds, nlowcnds, errbuf);
      }

      case debugger_t::ev_open_file: {
         const char *file = va_arg(va, const char *);
         uint64 *fsize = va_arg(va, uint64 *);
         bool readonly = va_argi(va, bool);
         return uni_open_file(file, fsize, readonly);
      }

      case debugger_t::ev_close_file: {
         int fn = va_arg(va, int);
         uni_close_file(fn);
         retcode = DRC_OK;
      }

      case debugger_t::ev_read_file: {
         int fn = va_arg(va, int);
         qoff64_t off = va_arg(va, qoff64_t);
         void *buf = va_arg(va, void *);
         size_t size = va_arg(va, size_t);
         return uni_read_file(fn, off, buf, size);
      }

      case debugger_t::ev_write_file: {
         int fn = va_arg(va, int);
         qoff64_t off = va_arg(va, qoff64_t);
         const void *buf = va_arg(va, const void *);
         size_t size = va_arg(va, size_t);
         return uni_write_file(fn, off, buf, size);
      }

      case debugger_t::ev_map_address: {
         ea_t *mapped = va_arg(va, ea_t *);
         ea_t ea = va_arg(va, ea_t);
         const regval_t *regs = va_arg(va, const regval_t *);
         int regnum = va_arg(va, int);
         *mapped = uni_map_address(ea, regs, regnum);
         return DRC_OK;
      }

#ifdef GET_DEBMOD_EXTS
      case debugger_t::ev_get_debmod_extensions: {
         const void **ext = va_arg(va, const void **);
         *ext = GET_DEBMOD_EXTS();
         return DRC_OK;
      }
#endif

#ifdef HAVE_UPDATE_CALL_STACK
      case debugger_t::ev_update_call_stack: {
         thid_t tid = va_argi(va, thid_t);
         call_stack_t *trace = va_arg(va, call_stack_t *);
         return uni_update_call_stack(tid, trace);
      }
#endif

#ifdef HAVE_APPCALL
      case debugger_t::ev_appcall: {
         ea_t *blob_ea = va_arg(va, ea_t *);
         ea_t func_ea = va_arg(va, ea_t);
         thid_t tid = va_arg(va, thid_t);
         const func_type_data_t *fti = va_arg(va, const func_type_data_t *);
         int nargs = va_arg(va, int);
         const regobjs_t *regargs = va_arg(va, const regobjs_t *);
         relobj_t *stkargs = va_arg(va, relobj_t *);
         regobjs_t *retregs = va_arg(va, regobjs_t *);
         errbuf = va_arg(va, qstring *);
         debug_event_t *event = va_arg(va, debug_event_t *);
         int opts = va_arg(va, int);
         *blob_ea = uni_appcall(func_ea, tid, fti, nargs, regargs, stkargs, retregs, errbuf, event, opts);
         return DRC_OK;
      }

      case debugger_t::ev_cleanup_appcall: {
         thid_t tid = va_argi(va, thid_t);
         return uni_cleanup_appcall(tid);
      }
#endif

      case debugger_t::ev_eval_lowcnd: {
         thid_t tid = va_argi(va, thid_t);
         ea_t ea = va_arg(va, ea_t);
         errbuf = va_arg(va, qstring *);
         return uni_eval_lowcnd(tid, ea, errbuf);
      }

      case debugger_t::ev_send_ioctl: {
         int fn = va_arg(va, int);
         const void *buf = va_arg(va, const void *);
         size_t size = va_arg(va, size_t);
         void **poutbuf = va_arg(va, void **);
         ssize_t *poutsize = va_arg(va, ssize_t *);
         return uni_send_ioctl(fn, buf, size, poutbuf, poutsize);
      }

      case debugger_t::ev_dbg_enable_trace: {
         thid_t tid = va_arg(va, thid_t);
         bool enable = va_argi(va, bool);
         int trace_flags = va_arg(va, int);
         return uni_dbg_enable_trace(tid, enable, trace_flags) ? DRC_OK : DRC_NONE;
      }

      case debugger_t::ev_is_tracing_enabled: {
         thid_t tid = va_arg(va, thid_t);
         int tracebit = va_arg(va, int);
         return uni_is_tracing_enabled(tid, tracebit) ? DRC_OK : DRC_NONE;
         break;
      }

      case debugger_t::ev_rexec: {
         const char *cmdline = va_arg(va, const char *);
         return uni_rexec(cmdline);
      }

      case debugger_t::ev_get_srcinfo_path: {
         qstring *path = va_arg(va, qstring *);
         ea_t base = va_arg(va, ea_t);
         bool ok = uni_get_srcinfo_path(path, base);
         return ok ? DRC_OK : DRC_NONE;
      }

      case debugger_t::ev_bin_search: {
         ea_t *ea = va_arg(va, ea_t *);
         ea_t start_ea = va_arg(va, ea_t);
         ea_t end_ea = va_arg(va, ea_t);
         const compiled_binpat_vec_t *ptns = va_arg(va, const compiled_binpat_vec_t *);
         int srch_flags = va_arg(va, int);
         errbuf = va_arg(va, qstring *);
         if (ptns != NULL) {
            return uni_bin_search(ea, start_ea, end_ea, ptns, srch_flags, errbuf);
         }
      }
   }

   return retcode;

}

