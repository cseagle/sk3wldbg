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

#ifndef __IMAGE_LOADER_H
#define __IMAGE_LOADER_H

#include "sk3wldbg.h"

bool loadImage(sk3wldbg *uc, void *img, size_t sz, const char *args);
bool loadPE64(sk3wldbg *uc, void *img, size_t sz, const char *args);
bool loadPE32(sk3wldbg *uc, void *img, size_t sz, const char *args);
bool loadElf64(sk3wldbg *uc, void *img, size_t sz, const char *args);
bool loadElf32(sk3wldbg *uc, void *img, size_t sz, const char *args);

#endif
