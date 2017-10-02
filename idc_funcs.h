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

#ifndef __IDC_FUNCS_H
#define __IDC_FUNCS_H

#include "sk3wldbg.h"

/*
  add IDC functions for interacting with the debugger
  sk3wl_mmap();
  sk3wl_munmap();
*/

void register_funcs(sk3wldbg *uc);
void unregister_funcs();

#endif
