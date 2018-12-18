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

#ifndef __MEM_MGR_H
#define __MEM_MGR_H

#include <stdint.h>

#include <unicorn/unicorn.h>

#define SDB_MAP_FIXED 1

struct map_block {
   void *host;
   uint64_t guest;
   uint32_t length;
   map_block *left;
   map_block *right;
};

class mem_mgr {
   uc_engine *uc;
   map_block *root;
   uint64_t map_min;
   uint64_t map_max;
   uint64_t max_block;

   void insert(map_block *tree, map_block *node);
   map_block *find(map_block *tree, uint64_t addr);
   map_block *next(map_block *tree, uint64_t addr);
   map_block *next_block(uint64_t addr);
   map_block *prev(map_block *tree, uint64_t addr);
   map_block *prev_block(uint64_t addr);
   void remove(map_block *tree, map_block *node);

public:
   mem_mgr(uc_engine *uc);
   mem_mgr(uc_engine *uc, uint64_t map_min, uint64_t map_max);
   ~mem_mgr();

   void set_mmap_region(uint64_t map_min, uint64_t map_max);
   
   map_block *add_block(void *host, uint64_t guest, uint32_t length);
   map_block *find_block(uint64_t addr);
   void *to_host_ptr(uint64_t addr);
   map_block *mmap(uint64_t addr, uint32_t length, uint32_t perms, uint32_t flags = 0);
   void mprotect(uint64_t addr, uint32_t length, uint32_t perms);
   void munmap(uint64_t addr, uint32_t length);
};

#endif
