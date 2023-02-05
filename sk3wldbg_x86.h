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

#include <map>
#include "sk3wldbg.h"

using std::map;

struct sk3wldbg_x86_16 : public sk3wldbg {
    map<uint8_t,uint32_t> dos_irq_table;
    
    sk3wldbg_x86_16(void);
    virtual void init_session(void);
    bool save_ret_addr(uint64_t retaddr);
    bool call_changes_sp(void) {return true;};
    virtual bool set_pc(uint64_t pc);
    virtual uint64_t get_pc(void);
    virtual void intr_hook(uint32_t intno);
    
    void handle_dos_int21(void);
};

struct sk3wldbg_x86_32 : public sk3wldbg {
    sk3wldbg_x86_32(void);
    bool save_ret_addr(uint64_t retaddr);
    bool call_changes_sp(void) {return true;};
    virtual bool is_system_call(uint8_t *inst, uint32_t size);
    virtual void handle_system_call(uint8_t *inst, uint32_t size);
};

struct sk3wldbg_x86_64 : public sk3wldbg {
    sk3wldbg_x86_64(void);
    bool save_ret_addr(uint64_t retaddr);
    bool call_changes_sp(void) {return true;};
};
