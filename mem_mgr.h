#ifndef __MEM_MGR_H
#define __MEM_MGR_H

#include <stdint.h>

#include <unicorn/unicorn.h>

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
   mem_mgr(uc_engine *uc) : uc(uc) {};
   mem_mgr(uc_engine *uc, uint64_t map_min, uint64_t map_max);
   ~mem_mgr();

   void set_mmap_region(uint64_t map_min, uint64_t map_max);
   
   map_block *add_block(void *host, uint64_t guest, uint32_t length);
   map_block *find_block(uint64_t addr);
   void *to_host_ptr(uint64_t addr);
   map_block *mmap(uint64_t addr, uint32_t length, uint32_t perms);
   void mprotect(uint64_t addr, uint32_t length, uint32_t perms);
   void munmap(uint64_t addr, uint32_t length);
};

#endif
