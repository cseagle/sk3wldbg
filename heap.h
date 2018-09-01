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

#ifndef __TEMPLATE_HEAP_H
#define __TEMPLATE_HEAP_H

#include <stdint.h>

#define PREV_IN_USE 1

template <class T>
class heap {
protected:
   struct _chunk {
      T prev_size;
      T size;
      T fd;     //heap_chunk32*
      T bk;     //heap_chunk32*
   };

   struct _list {
      T fd;     //heap_chunk32*
      T bk;     //heap_chunk32*
   };

   void *user_mem;
   T heap_base;
   T heap_end;
   T tail;
   
   void *to_user(T addr);

   inline T CHUNK_ADDR(T a) {return a - 2 * sizeof(T);};
   inline _chunk* CHUNK_PTR(T c) {return (_chunk*)to_user(c);};
   inline T CHUNK_SIZE(_chunk *c) {return c->size & ~1;};

   T marker;
   _list free_list;
   void unlink(T chunk);
   void link(T chunk);
   T best_fit(T size);

public:
   heap(void *heap_mem, T _heap_base, uint32_t _heap_size);
   ~heap();

   T malloc(T size);
   T calloc(T nmemb, T size);
   T realloc(T ptr, T sz);
   void free(T ptr);
};

template <class T>
void *heap<T>::to_user(T addr) {
   return (addr - heap_base) + (char*)user_mem;
}

template <class T>
heap<T>::heap(void *heap_mem, T _heap_base, uint32_t _heap_size) {
   user_mem = heap_mem;
   heap_base = _heap_base;
   heap_end = heap_base + _heap_size;
   tail = heap_base;

   marker = ~(2 * sizeof(T) - 1) & (T)(uint64_t)&free_list;
   free_list.fd = marker;
   free_list.bk = marker;
   //setup initial chunk
   _chunk *chunk = (_chunk *)user_mem;
   chunk->prev_size = 0;
   chunk->size = _heap_size | PREV_IN_USE;
}

template <class T>
heap<T>::~heap() {
}

template <class T>
void heap<T>::unlink(T chunk) {
   _chunk *mchunk = CHUNK_PTR(chunk);
   if (mchunk->fd == marker) {
      free_list.bk = mchunk->bk;
   }
   else {
      _chunk *next = CHUNK_PTR(mchunk->fd);
      next->bk = mchunk->bk;
   }
   if (mchunk->bk == marker) {
      free_list.fd = mchunk->fd;
   }
   else {
      _chunk *prev = CHUNK_PTR(mchunk->bk);
      prev->fd = mchunk->fd;
   }
}

template <class T>
void heap<T>::link(T chunk) {
   _chunk *mchunk = CHUNK_PTR(chunk);
   mchunk->fd = free_list.fd;
   mchunk->bk = marker;
   free_list.fd = chunk;
   if (mchunk->fd != marker) {
      _chunk *nchunk = CHUNK_PTR(mchunk->fd);
      nchunk->bk = chunk;
   }
   else {
      free_list.bk = chunk;
   }
}

template <class T>
T heap<T>::best_fit(T size) {
   T best = 0;
   _chunk *best_chunk = NULL;
   for (T c = free_list.fd; c != marker;) {
      _chunk *chunk = CHUNK_PTR(c);
      if (chunk->size == size) {
         best = c;
         best_chunk = chunk;
         break;
      }
      if (chunk->size > size) {
         if (best == 0) {
            best = c;
            best_chunk = chunk;
         }
         else if ((chunk->size - size) < (best_chunk->size - size)) {
            best = c;
            best_chunk = chunk;
         }
      }
   }
   if (best) {
      unlink(best);
      _chunk *nchunk = CHUNK_PTR(best + CHUNK_SIZE(best_chunk));
      if (best_chunk->size >= (size + sizeof(_chunk))) {
         T split = best + size;
         _chunk *new_chunk = CHUNK_PTR(split);
         new_chunk->size = best_chunk->size - size; //this will have PREV_IN_USE set already
         best_chunk->size = size | PREV_IN_USE;
         nchunk->prev_size = CHUNK_SIZE(new_chunk);
         link(split);
      }
      else {
         //not enough room for a separate chunk, just give back the entire chunk
         //in which case there is no need to adjust the next chunk much
         nchunk->size |= PREV_IN_USE;
      }
   }
   else {
      //take it off the tail chunk
      _chunk *chunk = CHUNK_PTR(tail);
      if (size <= (chunk->size + 2 * sizeof(T))) {
         _chunk *tchunk = CHUNK_PTR(tail + size);
         best = tail;
         tchunk->size = (chunk->size - size) | PREV_IN_USE; //chunk before tail is always in use
         chunk->size = size | PREV_IN_USE;  //chunk before tail is always in use
         tail = tail + size;
      }
      else {
         //ideally we could extend heap at this point
      }
   }
   return best;
}

template <class T>
T heap<T>::malloc(T size) {
   size += 3 * sizeof(T) - 1;
   size &= ~(2 * sizeof(T) - 1);
   if (size < (4 * sizeof(T))) {
      size = 4 * sizeof(T);
   }
   T chunk = best_fit(size);
   if (chunk) {
      chunk += 2 * sizeof(T);
   }
   return chunk;
}

template <class T>
T heap<T>::calloc(T nmemb, T size) {
   T sz = nmemb * size;
   T block = malloc(sz);
   if (block) {
      void *p = to_user(block);
      memset(p, 0, sz);
   }
   return block;
}

template <class T>
T heap<T>::realloc(T ptr, T sz) {
   if (ptr == 0) {
      return malloc(sz);
   }
   if (sz == 0) {
      free(ptr);
      return 0;
   }
   T need = (sz + (3 * sizeof(T) - 1)) & ~(2 * sizeof(T) - 1);
   if (need < (4 * sizeof(T))) {
      need = 4 * sizeof(T);
   }
   T chunk = CHUNK_ADDR(ptr);
   _chunk *mchunk = CHUNK_PTR(chunk);
   T next_chunk = chunk + CHUNK_SIZE(mchunk);
   _chunk *nchunk = CHUNK_PTR(next_chunk);

   if (next_chunk == tail) {
      //adjacent to tail, it either fits or it doesn't
      T max = CHUNK_SIZE(mchunk) + CHUNK_SIZE(nchunk) - 2 * sizeof(T);
      if (sz < max) {
         //it fits, this will accomodate growing or shrinking realloc
         T new_chunk = chunk + need;
         _chunk *newchunk = CHUNK_PTR(new_chunk);
         newchunk->size = CHUNK_SIZE(mchunk) + CHUNK_SIZE(nchunk) - need;
         newchunk->size |= PREV_IN_USE;
         tail = new_chunk;
         mchunk->size = need | (mchunk->size & PREV_IN_USE);
         return ptr;
      }
   }
   else { 
      T next_next = next_chunk + CHUNK_SIZE(nchunk);
      _chunk *nnchunk = CHUNK_PTR(next_next);
      bool next_in_use = (nnchunk->size & 1) == 0;
      if (need <= mchunk->size) {
         //smaller or same
         if (need <= (mchunk->size - sizeof(_chunk))) {
            //enough room to split
            T new_chunk = chunk + need;
            _chunk *newchunk = CHUNK_PTR(new_chunk);
            if (!next_in_use) {
               T nsize = CHUNK_SIZE(mchunk) - need + CHUNK_SIZE(nchunk);
               newchunk->size = nsize | PREV_IN_USE;
               unlink(next_chunk);
               nnchunk->prev_size = nsize;
            }
            else {
               newchunk->size = (CHUNK_SIZE(mchunk) - need) | PREV_IN_USE;
               nchunk->size &= ~1;
            }
            link(new_chunk);
            mchunk->size = need | (mchunk->size & PREV_IN_USE);
         }
         else {
            //don't change a thing
         }
         return ptr;
      }
      if (!next_in_use) {
         //maybe we can grow into the next chunk
         if (need <= (CHUNK_SIZE(mchunk) + CHUNK_SIZE(nchunk))) {
            T tsize = CHUNK_SIZE(nchunk);
            unlink(next_chunk); //we are going to use at least some of this
            if (need <= ((CHUNK_SIZE(mchunk) + tsize) - sizeof(_chunk))) {
               //enough room to split
               T new_chunk = chunk + need;
               _chunk *newchunk = CHUNK_PTR(new_chunk);

               T nsize = CHUNK_SIZE(mchunk) + tsize - need;
               newchunk->size = nsize | PREV_IN_USE;
               nnchunk->prev_size = nsize;
               link(new_chunk);
            }
            else {
               //used all of next chunk
               nnchunk->size |= PREV_IN_USE;
            }            
            mchunk->size = need | (mchunk->size & PREV_IN_USE);
            return ptr;
         }
      }
   }
   //need to do a malloc and copy at this point
   T new_block = malloc(sz);
   if (new_block) {
      T ncopy = CHUNK_SIZE(mchunk) - 2 * sizeof(T) + sizeof(T);  //take next->prev_size field too
      void *dest = to_user(new_block);
      memcpy(dest, &mchunk->fd, ncopy);
      free(ptr);
   }
   return new_block;
}

template <class T>
void heap<T>::free(T ptr) {
   T chunk = CHUNK_ADDR(ptr);
   _chunk *mchunk = CHUNK_PTR(chunk);
   T next_chunk = chunk + CHUNK_SIZE(mchunk);
   _chunk *nchunk = CHUNK_PTR(next_chunk);

   if (next_chunk == tail) {
      mchunk->size += CHUNK_SIZE(nchunk);  //add this into tail
      tail = chunk;
   }
   else {
      T next_next = next_chunk + CHUNK_SIZE(nchunk);
      _chunk *nnchunk = CHUNK_PTR(next_next);
      if ((nnchunk->size & PREV_IN_USE) == 0) {
         //next chunk is not in use, so consolidate forward
         mchunk->size += CHUNK_SIZE(nchunk);  //grow size to include next
         unlink(next_chunk);                   //unlink next chunk
         nnchunk->prev_size = CHUNK_SIZE(mchunk); //update prev_size in new next
      }
      else {
         nchunk->prev_size = CHUNK_SIZE(mchunk);  //this chunk not in use so set prev_size
         nchunk->size &= ~1;  //this chunk is not in use anymore
      }
      link(chunk);
   }

   if ((mchunk->size & PREV_IN_USE) == 0) {
      //prev is not in use, need to consolidate backwards
      T prev_chunk = chunk - mchunk->prev_size;
      unlink(prev_chunk);
      _chunk *pchunk = CHUNK_PTR(prev_chunk);
      pchunk->size += mchunk->size;
      if (chunk == tail) {
         tail = prev_chunk;
      }
      else {
         //chunk was linked during forward consolidation check
         unlink(chunk);
         T next_chunk = chunk + mchunk->size;
         //next chunk already knows that this chunk is not in use from forward consolidation
         _chunk *nchunk = CHUNK_PTR(next_chunk);
         nchunk->prev_size = CHUNK_SIZE(pchunk);
         link(prev_chunk);
      }
   }
}

#endif
