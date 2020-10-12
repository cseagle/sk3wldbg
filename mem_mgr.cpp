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

#ifndef __NT__
#include <unistd.h>
#endif

#include <stdlib.h>
#include <ida.hpp>
#include <kernwin.hpp>

#include "mem_mgr.h"

//#define DEBUG 1

mem_mgr::mem_mgr(uc_engine *uc, uint64_t map_min, uint64_t map_max) {
   root = NULL;
   this->uc = uc;
   set_mmap_region(map_min, map_max);
}

mem_mgr::mem_mgr(uc_engine *uc) {
   root = NULL;
   this->uc = uc;
   map_min = 0;
   map_max = 0;
   max_block = 0;
}

mem_mgr::~mem_mgr() {
   //need to free/unmap all the pages
}

void mem_mgr::set_mmap_region(uint64_t map_min, uint64_t map_max) {
   if (map_min > map_max) {
      this->map_min = map_max;
      this->map_max = map_min;
   }
   else {
      this->map_min = map_min;
      this->map_max = map_max;
   }
   max_block = this->map_max - this->map_min;
}

void mem_mgr::insert(map_block *tree, map_block *node) {
   if (root == NULL) {
      root = node;
   }
   else if (node->guest <= tree->guest) {
      if (tree->left == NULL) {
         tree->left = node;
      }
      else {
         insert(tree->left, node);
      }
   }
   else {
      if (tree->right == NULL) {
         tree->right = node;
      }
      else {
         insert(tree->right, node);
      }
   }
}

map_block *mem_mgr::add_block(void *host, uint64_t guest, uint32_t length) {
   map_block *m = (map_block*)calloc(sizeof(map_block), 1);
   if (m == NULL) {
      return NULL;
   }
   m->host = host;
   m->guest = guest;
   m->length = length;
   insert(root, m);
   return m;
}

map_block *mem_mgr::find(map_block *tree, uint64_t addr) {
   if (tree == NULL) {
      return NULL;
   }
   if (addr < tree->guest) {
      return find(tree->left, addr);
   }
   else if (addr >= (tree->guest + tree->length)) {
      return find(tree->right, addr);
   }
   return tree;
}

map_block *mem_mgr::find_block(uint64_t addr) {
   return find(root, addr);
}

map_block *mem_mgr::next(map_block *tree, uint64_t addr) {
   if (tree == NULL) {
      return NULL;
   }
   if (addr < tree->guest) {
      //this might be the "next" block, but look for something lower
      map_block *b = next(tree->left, addr);
      return b ? b : tree;
   }
   //next must follow this block
   return next(tree->right, addr);
}

map_block *mem_mgr::next_block(uint64_t addr) {
   return next(root, addr);
}

map_block *mem_mgr::prev(map_block *tree, uint64_t addr) {
   if (tree == NULL) {
      return NULL;
   }
   if (addr >= (tree->guest + tree->length)) {
      //this might be the "prev" block, but look for something higher
      map_block *b = prev(tree->right, addr);
      return b ? b : tree;
   }
   //prev must precede this block
   return prev(tree->left, addr);
}

map_block *mem_mgr::prev_block(uint64_t addr) {
   return prev(root, addr);
}

void *mem_mgr::to_host_ptr(uint64_t addr) {
   map_block *b = find_block(addr);
   if (b) {
      return (addr - b->guest) + (char*)b->host;
   }
   return NULL;
}

//node must be non-null and in the tree (returned by find)
void mem_mgr::remove(map_block *tree, map_block *node) {
   if (tree == NULL || node == NULL) {
      //safety check for invalid args
      return;
   }
   if (node == root) {
      if (root->right) {
         if (root->left) {
            insert(root->right, root->left);
         }
         root = root->right;
      }
      else {
         root = root->left;
      }
   }
   else if (node->guest > tree->guest) {
      if (tree->right == node) {
         tree->right = node->left;
         if (node->right != NULL) {
            insert(tree, node->right);
         }
      }
      else {
         remove(tree->right, node);
      }
   }
   else {
      if (tree->left == node) {
         tree->left = node->left;
         if (node->right != NULL) {
            insert(tree, node->right);
         }
      }
      else {
         remove(tree->left, node);
      }
   }
   node->left = node->right = NULL;
}

/*
//Unicorn permissions are the same as Linux permissions
#define PROT_READ       0x1  // page can be read
#define PROT_WRITE      0x2  // page can be written
#define PROT_EXEC       0x4  // page can be executed
*/
map_block *mem_mgr::mmap(uint64_t addr, uint32_t length, uint32_t perms, uint32_t flags) {
   uint64_t guest = 0;
   bool found = false;
   uint64_t orig = addr;
   map_block *b = NULL;
   if (length & 0xfff) {
      //length must be multiple of page size
#ifdef DEBUG
      msg("mmap: non-aligned size\n");
#endif
      return NULL;
   }
   if (addr & 0xfff) {
      //addr must be page aligned
#ifdef DEBUG
      msg("mmap: non-aligned address\n");
#endif
      return NULL;
   }
   if (length > max_block) {
      //out of memory
#ifdef DEBUG
      msg("mmap: out of memory\n");
#endif
      return NULL;
   }
   //highest address at which this allocation can be made
   uint64_t max_alloc = map_max - length;
   if (addr > max_alloc) {
      if (flags & SDB_MAP_FIXED) {
         //can't do what user wants
#ifdef DEBUG
         msg("mmap: address unavailable for fixed allocation\n");
#endif
         return NULL;
      }
      //just use top down allocation
      addr = 0;
   }
   if (addr || (flags & SDB_MAP_FIXED) != 0) {
//   if (addr) {
      //user wants a specific address
      if (addr < map_min) {
         addr = map_min;
         orig = map_min;
      }
      map_block *n = next_block(addr);
      while (!found && addr >= map_min && addr <= max_alloc) {
         b = find_block(addr);
         if (b) {
            //desired address is already in use
            if (flags & SDB_MAP_FIXED) {
               return NULL;  //can't grant user request
            }
            //compute the next lower address that might fit the entire request block
            addr = b->guest - length;
#ifdef DEBUG
            msg("mmap1: addr set to %p\n", (void*)addr);
#endif
         }
         else if (n == NULL) {
            guest = addr;
#ifdef DEBUG
            msg("mmap2: guest set to %p\n", (void*)guest);
#endif
            found = true;
         }
         else {
            b = prev_block(addr);
            if (b) {
               uint64_t end = b->guest + b->length;
               uint64_t gap = n->guest - addr;
               if (gap >= length) {
                  guest = addr;
#ifdef DEBUG
                  msg("mmap3: guest set to %p\n", (void*)guest);
#endif
                  found = true;
               }
               else {
                  n = b;
               }
            }
            else {
               uint64_t gap = n->guest - addr;
               if (gap >= length) {
                  guest = addr;
#ifdef DEBUG
                  msg("mmap4: guest set to %p\n", (void*)guest);
#endif
                  found = true;
               }
               else {
                  //hit bottom;
                  break;
               }
            }
         }
      }
      addr = orig;
#ifdef DEBUG
      msg("mmap5: addr set to %p\n", (void*)addr);
#endif
      while (!found && addr <= max_alloc) {
         b = find_block(addr);
         n = next_block(addr);
         if (b) {
            addr = b->guest + b->length;
#ifdef DEBUG
            msg("mmap6: addr set to %p\n", (void*)addr);
#endif
         }
         else if (n == NULL) {
            guest = addr;
#ifdef DEBUG
            msg("mmap7: guest set to %p\n", (void*)guest);
#endif
            found = true;
         }
         else {
            uint64_t gap = n->guest - addr;
            if (gap >= length) {
               guest = addr;
#ifdef DEBUG
               msg("mmap8: guest set to %p\n", (void*)guest);
#endif
               found = true;
            }
            else {
               addr = n->guest + n->length;
#ifdef DEBUG
               msg("mmap9: addr set to %p\n", (void*)addr);
#endif
            }
         }
      }
   }
   else {
      uint64_t top = map_max;
      while (1) {
         b = prev_block(top);
         if (b == NULL) {
            if (top >= (length + map_min)) {
               guest = top - length;
#ifdef DEBUG
               msg("mmap10: guest set to %p\n", (void*)guest);
#endif
               found = true;
            }
            break;
         }
         else {
            if ((top - (b->guest + b->length)) > length) {
               //fits in the gap
               guest = top - length;
#ifdef DEBUG
               msg("mmap11: guest set to %p\n", (void*)guest);
#endif
               found = true;
               break;
            }
            top = b->guest;
         }
      }
   }
   if (!found) {
      return NULL;
   }
   void *host = calloc(length, 1);
   if (host == NULL) {
      return NULL;
   }
#ifdef DEBUG
   msg("add_block(ptr, %p, 0x%x)\n", (void*)guest, (uint32_t)length);
#endif
   b = add_block(host, guest, length);
   uc_err err = uc_mem_map_ptr(uc, b->guest, b->length, perms, b->host);
#ifdef DEBUG
   msg("uc_mem_map_ptr(%p, 0x%x, %d)\n", (void*)b->guest, (uint32_t)b->length, perms);
#endif
   if (err != UC_ERR_OK) {
      msg("Failed on uc_mem_map_ptr() with error returned %u: %s\n", err, uc_strerror(err));
   }
   else {
   }

   return b;
}

void mem_mgr::mprotect(uint64_t addr, uint32_t length, uint32_t perms) {
}

void mem_mgr::munmap(uint64_t addr, uint32_t length) {
   uint64_t end = addr + length;
   map_block *b = find_block(addr);
   if (b) {
      uc_mem_unmap(uc, b->guest, b->length);
   }
   do {
      if (b) {
         uint64_t bend = b->guest + b->length;
         remove(root, b);
         if (b->guest < addr) {
            add_block(b->host, b->guest, (uint32_t)(addr - b->guest));
         }
         if (end < bend) {
            add_block((end - b->guest) + (char*)b->host, end, (uint32_t)(bend - end));
            free(b);
            break;
         }
         if (end == bend) {
            free(b);
            break;
         }
         free(b);
      }
   } while ((b = next_block(addr)) != NULL && end > b->guest);
}
