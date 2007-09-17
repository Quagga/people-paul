/*
 * Memory management routine
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>
/* malloc.h is generally obsolete, however GNU Libc mallinfo wants it. */
#if !defined(HAVE_STDLIB_H) || (defined(GNU_LINUX) && defined(HAVE_MALLINFO))
#include <malloc.h>
#endif /* !HAVE_STDLIB_H || HAVE_MALLINFO */

#include "log.h"
#include "memory.h"

/* some debug and probably performance debilitating compile options.. */
#define MTYPE_EXTRA_STATS 1
/* Tide optimisation (if it actually is an optimisation */
#define MTYPE_TRACK_TIDES 0
/* free() debugging: poison on free if possible and verify poison on realloc,
 * check for double-free's.
 * This will use a lot of extra RAM.
 */
#define MTYPE_POISON 1
/* Redzone tracking (where possible - size must stay same for object) */
#define MTYPE_REDZONE 1

static void log_memstats(int log_priority);
static const int redzone_marker = 0xf0f0f0f0;

static const char *
lookup_memtype(int key)
{
  /* use global mlists */
  struct mlist *list;
  
  for (list = &mlists[0]; list != NULL; list++) 
    {
      struct memory_list *m;
      
      for (m = list[0].list; m->index >= 0; m++)
        if (m->index == key)
          return m->format;
    }
  return "";
}

/* Fatal memory allocation error occured. */
static void __attribute__ ((noreturn))
zerror (const char *fname, int type, size_t size)
{
  zlog_err ("%s : can't allocate memory for `%s' size %d: %s\n", 
	    fname, lookup_memtype (type), (int) size, safe_strerror(errno));
  log_memstats(LOG_WARNING);
  /* N.B. It might be preferable to call zlog_backtrace_sigsafe here, since
     that function should definitely be safe in an OOM condition.  But
     unfortunately zlog_backtrace_sigsafe does not support syslog logging at
     this time... */
  zlog_backtrace(LOG_WARNING);
  abort();
}

/* most objects for a type we can try cache */
/* If poisoning, cache lots of them so we get to verify lots of poison fill */
#if defined(MTYPE_POISON) && (MTYPE_POISON > 0)
#define MTYPE_CACHE_NUM_SLOTS 50
#else
/* Normally we only want a very few cache slots, as these are statically 
 * allocated
 */
#define MTYPE_CACHE_NUM_SLOTS 3
#endif /* MTYPE_POISON */

/* Allocations / frees can be thought of as coming in 'tides', with a 'flow'
 * of allocations followed by an 'ebb' of frees. We're really only interested
 * in caching tides whose length is not much greater than the number of
 * cache slots (ie, allocation patterns we can get a reasonably good hit
 * rate on). Caching (ie not freeing) the first $FEW frees of a very long
 * "tidal pattern" isn't going to do much, and at worst would just stuff
 * things up for the underlying libc allocator (eg, fragmentation).
 *
 * Hence we track:
 * flow: the current length and direction of flow or ebb
 *
 * And we only cache allocations while the ebb or flow is <= an
 * arbitrary bound on the tide. Ie, we only cache objects whose
 * allocation pattern has recently tended to be a roughly symmetrical
 * series of allocs/frees, allowed to skew only within this bound.
 */
#define MTYPE_CACHE_TIDE (MTYPE_CACHE_NUM_SLOTS * 16)

/* absolute value of the signed flow value */
#define MTYPE_CACHE_FLOW_ABS(T) \
  ((mstat[(T)].flow >= 0) ? (mstat[(T)].flow) \
   : (-mstat[(T)].flow))

/* Is cache valid? */
#define CACHE_IS_INVALID(T) (mstat[(T)].cache_used == -1)

static struct 
{
  unsigned long alloc;
  size_t cached_size;  /* size of objects cached */
#if (MTYPE_TRACK_TIDES > 0)
  int flow;    /* the current direction and length of the tide */
#endif
  void *cache_slot[MTYPE_CACHE_NUM_SLOTS];
  int cache_used;	/* -1 means never ever cache again, see zrealloc() */
  enum mtype_cacheable cacheable;
#if (MTYPE_EXTRA_STATS > 0)
  unsigned long st_cache_hit;
  unsigned long st_cache_invalidated;
  unsigned long st_cache_revalidated;
  unsigned long st_cache_add;
  unsigned long st_malloc;
  unsigned long st_calloc;
  unsigned long st_realloc;
  unsigned long st_strdup;
  unsigned long st_free;
#endif /* MTYPE_EXTRA_STATS */
} mstat [MTYPE_MAX];

/* Increment allocation counter. */
static inline void
alloc_inc (int type)
{
  mstat[type].alloc++;
  
#if (MTYPE_TRACK_TIDES > 0)
  if (mstat[type].flow < 0)
    mstat[type].flow = 1;
  else
    mstat[type].flow++;
#endif /* MTYPE_TRACK_TIDES */
}

/* Decrement allocation counter. */
static inline void
alloc_dec (int type)
{
  mstat[type].alloc--;
  
#if (MTYPE_TRACK_TIDES > 0)
  if (mstat[type].flow > 0)
    mstat[type].flow = -1;
  else
    mstat[type].flow--;
#endif /* MTYPE_TRACK_TIDES */
}

/* free the cache, eg because it was invalidated, or the tide is too
 * long
 */
static void
zmemory_cache_free (int type)
{
  while (mstat[type].cache_used > 0)
    {
      mstat[type].cache_used--;
      free (mstat[type].cache_slot[mstat[type].cache_used]);
    }
}

/* invalidate the cache. Free all entries. Reset cached_size */
static void
zmemory_cache_invalidate (int type)
{
  mstat[type].cached_size = 0;
  
#if (MTYPE_EXTRA_STATS > 0)
  mstat[type].st_cache_invalidated++;
#endif /* MTYPE_EXTRA_STATS */

  zmemory_cache_free (type);
  
  mstat[type].cache_used = -1;
}

/* helper to fill pointed to buffer
 * only for use by zpoison and zpoison_verify
 */
static void
zpoison_fill (unsigned int *p, size_t size, unsigned int fill)
{
  unsigned int i;
  
  for (i = 0; i < (size / sizeof (fill)); i++)
    memcpy ((p + i), &fill, sizeof (fill));
  
  if (size % sizeof (fill))
    memcpy ((p + i), &fill, size % sizeof (fill));
}

static const unsigned int poison = 0x00000badU;
static const unsigned int antidote = 0xdeadbeefU;

/* poison memory */
static void
zpoison (int type, void *ptr)
{
  /* only if cache is valid can we have a size */
  if (CACHE_IS_INVALID (type))
    return;
  
  /* if cache is valid, and we're poisoning freed object, we surely must
   * have a size cached..
   */
  assert (mstat[type].cached_size > 0);
  
  zpoison_fill (ptr, mstat[type].cached_size, poison);
  
  return;
}

static inline void *
zpoison_verify (int type, unsigned int *ptr)
{
  unsigned int i;
  
  assert (!CACHE_IS_INVALID (type) && mstat[type].cached_size > 0);
  
  for (i = 0; i < (mstat[type].cached_size / sizeof (poison)); i++)
    assert (*(ptr + i) == poison);
  
  zpoison_fill (ptr, mstat[type].cached_size, antidote);
  
  return ptr;
}

/* Lookup cache entry for (type,size) This is a simple, low overhead
 * cache to mitigate costs of repeated malloc(x)/free by higher level
 * code which existing malloc implementations dont seem to deal well
 * with.
 *
 * As we have a memory type parameter, information not available to a libc,
 * and we already maintain stats per mtype, we can implement a low-overhead
 * cache to short-circuit repetitive malloc(x)/free from having to go into
 * system malloc()/free().
 *
 * We cant handle the size changing, if we detect different size requests
 * of memory for a type, the cache for that type is cleared and invalidated
 * and will remain invalid until allocations for the type return to 0.
 *
 * Note that the most important function here is to:
 * - detect size changing
 * - keep cache invalid while different size allocations are outstanding
 *
 * For we use the size parameter to do things other than just cache types
 * (overflow redzones)
 */
static void *
zmemory_cache_lookup (int type, size_t size)
{
   /* Caching invalid for this type, if all objects have been returned,
    * we can enable caching again
    */
  if (CACHE_IS_INVALID (type))
    {
      /* If all outstanding allocations are returned, cache be can made
       * valid again, otherwise left it is left as invalid.
       *
       * the still-invalid case is put first as all x86 CPUs seem to
       * consider the first outcome of a branch as the most likely for
       * branch prediction purposes..
       */
      if (mstat[type].alloc > 0)
        return NULL;
      else
        {
#if (MTYPE_EXTRA_STATS > 0)
          mstat[type].st_cache_revalidated++;
#endif /* MTYPE_EXTRA_STATS */
          
          mstat[type].cache_used = 0;
        }
    }
  
  /* cache must be valid at this point.
   * Three possibilities: 
   * - it's the first alloc (possibly after revalidation):
   *   size will be zero, record the size.
   * - the size is the same:
   *   see if we can satisfy from cache
   * - the size is different:
   *   invalidate the cache
   */
  
  /* record size for now */
  if (mstat[type].cached_size == 0)
    {
      mstat[type].cached_size = size;
      return NULL;
    }
  
  /* cache_used && cached_size must both be >= here */
  if (size == mstat[type].cached_size)
    {
      /* Not a cacheable type, or nothing cached,
       * but we've done our job of tracking size 
       */
      if (mstat[type].cacheable != MTYPE_CACHE
          || mstat[type].cache_used == 0)
        return NULL;
      
#if (MTYPE_EXTRA_STATS > 0)
      mstat[type].st_cache_hit++;
#endif /* MTYPE_EXTRA_STATS */
      
      mstat[type].cache_used--;

#define MTYPE_CACHED_SLOT(T) (mstat[(T)].cache_slot[mstat[(T)].cache_used])
      if (MTYPE_POISON)
        return zpoison_verify (type, MTYPE_CACHED_SLOT (type));
      else
        return MTYPE_CACHED_SLOT (type);
    }
  else
    {
      /* size doesnt match, invalidate cache which will
       * mark cache as unusable for now 
       */
      zmemory_cache_invalidate (type);
    }
  return NULL;
}

/* return 0 or 1 to signify whether memory was cached.
 * 0 - not added to cache
 * 1 - added to cache 
 *
 * caller is left to free (or not) as appropriate.
 */
static inline int
zmemory_cache_add (int type, void *p)
{
  int i;
  /* caching invalid for this type */
  if (mstat[type].cacheable != MTYPE_CACHE
      || CACHE_IS_INVALID (type))
    return 0;

  /* Double free check */
  if (MTYPE_POISON)
    for (i = 0; i < mstat[type].cache_used; i++)
      assert (mstat[type].cache_slot[i] != p);
  
#if (MTYPE_TRACK_TIDES > 0)
  /* Tide check: last tide and the current flow of the tide should be
   * less than MTYPE_CACHE_TIDE. An object with very long 'tides' isn't
   * worth caching.
   */
  if (MTYPE_CACHE_FLOW_ABS(type) > MTYPE_CACHE_TIDE)
    {
      zmemory_cache_free (type);
      return 0;
    }
#endif /* MTYPE_TRACK_TIDES */
  
  if (mstat[type].cache_used < MTYPE_CACHE_NUM_SLOTS)
    {
#if (MTYPE_EXTRA_STATS > 0)
      mstat[type].st_cache_add++;
#endif /* MTYPE_EXTRA_STATS */

      mstat[type].cache_slot[mstat[type].cache_used] = p;
      mstat[type].cache_used++;
      return 1;
    }
  
  return 0;
}

/* Round up given size to where redzone would start, naturally aligned */
#define REDZONE_ROUNDUP(S) \
  (1 + (((S) - 1) | (sizeof (redzone_marker) - 1)))
#define MTYPE_SIZE_WITH_REDZONE(S) \
  (REDZONE_ROUNDUP(S) + sizeof (redzone_marker))

static void
zredzone_add (char *p, size_t size)
{
  *((int *)(p + REDZONE_ROUNDUP(size))) = redzone_marker;
}

static void
zredzone_verify (int type, char *p)
{
  size_t size = mstat[type].cached_size;
  
  if (CACHE_IS_INVALID (type))
    return;
  
  if (size > 0)
    assert (*((int *)(p + REDZONE_ROUNDUP(size))) == redzone_marker);
  else
    assert (mstat[type].alloc == 0);
}

/* Memory allocation. */
void *
zmalloc (int type, size_t size)
{
  void *memory;
  
  /* try the cache */
  if ( (memory = zmemory_cache_lookup (type, size)) == NULL)
    {
      if (MTYPE_REDZONE)
        memory = malloc (REDZONE_ROUNDUP(size) + sizeof (redzone_marker));
      else
        memory = malloc (size);
    }

  if (memory == NULL)
    zerror ("malloc", type, size);
  
  if (MTYPE_REDZONE)
    zredzone_add (memory, size);
  
  alloc_inc (type);
  
#if (MTYPE_EXTRA_STATS > 0)
  mstat[type].st_malloc++;
#endif /* MTYPE_EXTRA_STATS */
  
  return memory;
}

/* Memory allocation with num * size with cleared. */
void *
zcalloc (int type, size_t size)
{
  void *memory;

  if ( (memory = zmemory_cache_lookup (type, size)) != NULL)
    memset (memory, 0, size);
  else
    {
      if (MTYPE_REDZONE)
        memory = calloc (1, REDZONE_ROUNDUP(size) + sizeof (redzone_marker));
      else
        memory = calloc (1, size);
    }

  if (memory == NULL)
    zerror ("calloc", type, size);

  if (MTYPE_REDZONE)
    zredzone_add (memory, size);
  
#if (MTYPE_EXTRA_STATS > 0)
  mstat[type].st_calloc++;
#endif /* MTYPE_EXTRA_STATS */
  
  alloc_inc (type);

  return memory;
}

/* Memory reallocation. */
void *
zrealloc (int type, void *ptr, size_t size)
{
  void *memory;
  
  if (ptr == NULL)
    return zmalloc (type, size);
  
  if (MTYPE_REDZONE)
    zredzone_verify (type, ptr);
  
  /* invalidate cache if not already invalid */
  if (mstat[type].cache_used >= 0)
    zmemory_cache_invalidate (type);
  
  memory = realloc (ptr, size);
  if (memory == NULL)
    zerror ("realloc", type, size);

#if (MTYPE_EXTRA_STATS > 0)
  mstat[type].st_realloc++;
#endif /* MTYPE_EXTRA_STATS */

  return memory;
}

/* Memory free. */
void
zfree (int type, void *ptr)
{
  if (MTYPE_POISON)
    zpoison (type, ptr);
  
  if (MTYPE_REDZONE)
    zredzone_verify (type, ptr);
  
  /* try add to cache, free if it wasnt cached */
  if (zmemory_cache_add (type, ptr) == 0)
    free(ptr);

#if (MTYPE_EXTRA_STATS > 0)
  mstat[type].st_free++;
#endif /* MTYPE_EXTRA_STATS */
  
  alloc_dec (type);
}

/* String duplication. */
char *
zstrdup (int type, const char *str)
{
  void *dup;
  
  dup = strdup (str);
  if (dup == NULL)
    zerror ("strdup", type, strlen (str));
  
  /* invalidate cache if not already invalid, we have no idea of size */
  if (mstat[type].cache_used >= 0)
    zmemory_cache_invalidate (type);
  
#if (MTYPE_EXTRA_STATS > 0)
  mstat[type].st_strdup++;
#endif /* MTYPE_EXTRA_STATS */
  
  alloc_inc (type);

  return dup;
}

#ifdef MEMORY_LOG
static void
mtype_log (char *func, void *memory, const char *file, int line, int type)
{
  zlog_debug ("%s: %s %p %s %d", func, lookup (mstr, type), memory, file, line);
}

void *
mtype_zmalloc (const char *file, int line, int type, size_t size)
{
  void *memory;

  memory = zmalloc (type, size);
  mtype_log ("zmalloc", memory, file, line, type);

  return memory;
}

void *
mtype_zcalloc (const char *file, int line, int type, size_t size)
{
  void *memory;

  memory = zcalloc (type, size);
  mtype_log ("xcalloc", memory, file, line, type);

  return memory;
}

void *
mtype_zrealloc (const char *file, int line, int type, void *ptr, size_t size)
{
  void *memory;

  memory = zrealloc (type, ptr, size);

  mtype_log ("xrealloc", memory, file, line, type);

  return memory;
}

/* Important function. */
void 
mtype_zfree (const char *file, int line, int type, void *ptr)
{
  mtype_log ("xfree", ptr, file, line, type);
  zfree (type, ptr);
}

char *
mtype_zstrdup (const char *file, int line, int type, const char *str)
{
  char *memory;

  memory = zstrdup (type, str);
  
  mtype_log ("xstrdup", memory, file, line, type);

  return memory;
}
#endif /* MTPYE_LOG */

/* Looking up memory status from vty interface. */
#include "vector.h"
#include "vty.h"
#include "command.h"

static void
log_memstats(int pri)
{
  struct mlist *ml;

  for (ml = mlists; ml->list; ml++)
    {
      struct memory_list *m;

      zlog (NULL, pri, "Memory utilization in module %s:", ml->name);
      for (m = ml->list; m->index >= 0; m++)
	if (m->index && mstat[m->index].alloc)
	  zlog (NULL, pri, "  %-30s: %10ld", m->format, mstat[m->index].alloc);
    }
}

static void
show_separator(struct vty *vty)
{
  vty_out (vty, "-----------------------------\r\n");
}

static void
show_memory_vty_header (struct vty *vty)
{
  vty_out (vty, "%12s\t%s%s", "Cached:",
           "Objects cached, -1 for invalidated cache",
           VTY_NEWLINE);
  vty_out (vty, "%12s\t%s%s", "Size Cached:",
           "Size of objects in bytes", VTY_NEWLINE);
#if (MTYPE_TRACK_TIDES > 0)
  vty_out (vty, "%12s\t%s%s", "flow:",
           "Length of current flow/ebb (negative for ebb/free's)",
           VTY_NEWLINE);
#endif
#if (MTYPE_EXTRA_STATS > 0)
  vty_out (vty, "%12s\t%s%s", "cache hit:",
           "Requests satisfied from cache",
           VTY_NEWLINE);
  vty_out (vty, "%12s\t%s%s", "cache add:",
           "Object added to cache rather than freed",
           VTY_NEWLINE);
  vty_out (vty, "%12s\t%s%s", "inval:",
           "Cache invalidated due to request size mismatch",
           VTY_NEWLINE);
  vty_out (vty, "%12s\t%s%s", "reval:",
           "Invalid cache revalidated and made useable again",
           VTY_NEWLINE);
  vty_out (vty, "%12s\t%s%s", "diff:",
           "Discrepancy between (allocations - free) and 'allocated'",
           VTY_NEWLINE);
#endif /* MTYPE_EXTRA_STATS */

  vty_out (vty, "Cache slots: %3d, Poisoning: %senabled, "
                 "Redzone: %senabled%s",
           MTYPE_CACHE_NUM_SLOTS,
           (MTYPE_POISON > 0) ? "" : "not ",
           (MTYPE_REDZONE > 0) ? "" : "not ",
           VTY_NEWLINE);
  
  vty_out (vty, "%s%-28s | %10s | %10s | %11s | %7s%s",
           VTY_NEWLINE,
           "Memory Type", "Allocated", "Cached", "Size Cached", 
           "Caching", VTY_NEWLINE);
}

static int
show_memory_vty (struct vty *vty, struct memory_list *list)
{
  struct memory_list *m;
  int needsep = 0;

  show_memory_vty_header (vty);
  
  for (m = list; m->index >= 0; m++)
    if (m->index == 0)
      {
	if (needsep)
	  {
	    show_separator (vty);
	    needsep = 0;
	  }
      }
    else if (mstat[m->index].alloc
#if (MTYPE_EXTRA_STATS > 0)
             || mstat[m->index].st_strdup
             || mstat[m->index].st_calloc
             || mstat[m->index].st_malloc
             || mstat[m->index].st_free
#endif
             )
      {
        vty_out (vty, "%-28s | %10lu | %10d | %11lu | %7s%s", 
                 m->format, 
                 mstat[m->index].alloc,
                 mstat[m->index].cache_used, 
                 mstat[m->index].cached_size,
                 (mstat[m->index].cacheable == MTYPE_CACHE
                  && !CACHE_IS_INVALID(m->index)) ? "yes" : "no",
                 VTY_NEWLINE);
#if (MTYPE_EXTRA_STATS > 0)
          {
            long int diff = mstat[m->index].alloc
                            - (mstat[m->index].st_strdup
                               + mstat[m->index].st_calloc
                               + mstat[m->index].st_malloc
                               - mstat[m->index].st_free);
            
            vty_out (vty, "%28s | %10lu | %10lu | %11lu |%s",
                    "malloc | calloc | realloc",
                    mstat[m->index].st_malloc,
                    mstat[m->index].st_calloc,
                    mstat[m->index].st_realloc,
                    VTY_NEWLINE);
            vty_out (vty, "%-28s | %10lu | %10lu | %11ld |%s",
                    "   strdup |  free  |  diff",
                    mstat[m->index].st_strdup,
                    mstat[m->index].st_free,
                    diff,
                    VTY_NEWLINE);
            vty_out (vty, "%-28s | %10lu | %10lu |%s",
                    "cache hit |   add  |",
                    mstat[m->index].st_cache_hit,
                    mstat[m->index].st_cache_add,
                    VTY_NEWLINE);
            vty_out (vty, "%-28s | %10lu | %10lu |%s",
                    "    inval | reval  |",
                    mstat[m->index].st_cache_invalidated,
                    mstat[m->index].st_cache_revalidated,
                    VTY_NEWLINE);
          }
#endif /* MTYPE_EXTRA_STATS */

#if (MTYPE_TRACK_TIDES > 0)  
        vty_out (vty, "%-28s | %10d |%s",
                "     flow |",
                mstat[m->index].flow,
                VTY_NEWLINE);
#endif /* MTYPE_TRACK_TIDES */
        
        /* If we don't have the extra stats output, every objects fits on one
         * line and we don't need the extra newline to help distinguish
         */
        if (MTYPE_TRACK_TIDES > 0 || MTYPE_EXTRA_STATS > 0)
          vty_out (vty, "%s", VTY_NEWLINE);
        
        needsep = 1;
      }

  return needsep;
}

#ifdef HAVE_MALLINFO
static int
show_memory_mallinfo (struct vty *vty)
{
  struct mallinfo minfo = mallinfo();
  char buf[MTYPE_MEMSTR_LEN];
  
  vty_out (vty, "System allocator statistics:%s", VTY_NEWLINE);
  vty_out (vty, "  Total heap allocated:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.arena),
           VTY_NEWLINE);
  vty_out (vty, "  Holding block headers: %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.hblkhd),
           VTY_NEWLINE);
  vty_out (vty, "  Used small blocks:     %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.usmblks),
           VTY_NEWLINE);
  vty_out (vty, "  Used ordinary blocks:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.uordblks),
           VTY_NEWLINE);
  vty_out (vty, "  Free small blocks:     %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.fsmblks),
           VTY_NEWLINE);
  vty_out (vty, "  Free ordinary blocks:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.fordblks),
           VTY_NEWLINE);
  vty_out (vty, "  Ordinary blocks:       %ld%s",
           (unsigned long)minfo.ordblks,
           VTY_NEWLINE);
  vty_out (vty, "  Small blocks:          %ld%s",
           (unsigned long)minfo.smblks,
           VTY_NEWLINE);
  vty_out (vty, "  Holding blocks:        %ld%s",
           (unsigned long)minfo.hblks,
           VTY_NEWLINE);
  vty_out (vty, "(see system documentation for 'mallinfo' for meaning)%s",
           VTY_NEWLINE);
  return 1;
}
#endif /* HAVE_MALLINFO */

DEFUN (show_memory_all,
       show_memory_all_cmd,
       "show memory all",
       "Show running system information\n"
       "Memory statistics\n"
       "All memory statistics\n")
{
  struct mlist *ml;
  int needsep = 0;
  
#ifdef HAVE_MALLINFO
  needsep = show_memory_mallinfo (vty);
#endif /* HAVE_MALLINFO */
  
  for (ml = mlists; ml->list; ml++)
    {
      if (needsep)
	show_separator (vty);
      needsep = show_memory_vty (vty, ml->list);
    }

  return CMD_SUCCESS;
}

ALIAS (show_memory_all,
       show_memory_cmd,
       "show memory",
       "Show running system information\n"
       "Memory statistics\n")

DEFUN (show_memory_lib,
       show_memory_lib_cmd,
       "show memory lib",
       SHOW_STR
       "Memory statistics\n"
       "Library memory\n")
{
  show_memory_vty (vty, memory_list_lib);
  return CMD_SUCCESS;
}

DEFUN (show_memory_zebra,
       show_memory_zebra_cmd,
       "show memory zebra",
       SHOW_STR
       "Memory statistics\n"
       "Zebra memory\n")
{
  show_memory_vty (vty, memory_list_zebra);
  return CMD_SUCCESS;
}

DEFUN (show_memory_rip,
       show_memory_rip_cmd,
       "show memory rip",
       SHOW_STR
       "Memory statistics\n"
       "RIP memory\n")
{
  show_memory_vty (vty, memory_list_rip);
  return CMD_SUCCESS;
}

DEFUN (show_memory_ripng,
       show_memory_ripng_cmd,
       "show memory ripng",
       SHOW_STR
       "Memory statistics\n"
       "RIPng memory\n")
{
  show_memory_vty (vty, memory_list_ripng);
  return CMD_SUCCESS;
}

DEFUN (show_memory_bgp,
       show_memory_bgp_cmd,
       "show memory bgp",
       SHOW_STR
       "Memory statistics\n"
       "BGP memory\n")
{
  show_memory_vty (vty, memory_list_bgp);
  return CMD_SUCCESS;
}

DEFUN (show_memory_ospf,
       show_memory_ospf_cmd,
       "show memory ospf",
       SHOW_STR
       "Memory statistics\n"
       "OSPF memory\n")
{
  show_memory_vty (vty, memory_list_ospf);
  return CMD_SUCCESS;
}

DEFUN (show_memory_ospf6,
       show_memory_ospf6_cmd,
       "show memory ospf6",
       SHOW_STR
       "Memory statistics\n"
       "OSPF6 memory\n")
{
  show_memory_vty (vty, memory_list_ospf6);
  return CMD_SUCCESS;
}

DEFUN (show_memory_isis,
       show_memory_isis_cmd,
       "show memory isis",
       SHOW_STR
       "Memory statistics\n"
       "ISIS memory\n")
{
  show_memory_vty (vty, memory_list_isis);
  return CMD_SUCCESS;
}

void
memory_init (void)
{
  struct mlist *ml;
  struct memory_list *m;
  
  for (ml = mlists; ml->list; ml++)
    {
      for (m = ml->list; m->index >= 0; m++)
        if (m->index > 0)
          mstat[m->index].cacheable = m->cacheable;
    }
  
  /* the 0th cache is special, for extremely lazy users, must be invalid */
  mstat[0].cache_used = -1;
  
  install_element (VIEW_NODE, &show_memory_cmd);
  install_element (VIEW_NODE, &show_memory_all_cmd);
  install_element (VIEW_NODE, &show_memory_lib_cmd);
  install_element (VIEW_NODE, &show_memory_rip_cmd);
  install_element (VIEW_NODE, &show_memory_ripng_cmd);
  install_element (VIEW_NODE, &show_memory_bgp_cmd);
  install_element (VIEW_NODE, &show_memory_ospf_cmd);
  install_element (VIEW_NODE, &show_memory_ospf6_cmd);
  install_element (VIEW_NODE, &show_memory_isis_cmd);

  install_element (ENABLE_NODE, &show_memory_cmd);
  install_element (ENABLE_NODE, &show_memory_all_cmd);
  install_element (ENABLE_NODE, &show_memory_lib_cmd);
  install_element (ENABLE_NODE, &show_memory_zebra_cmd);
  install_element (ENABLE_NODE, &show_memory_rip_cmd);
  install_element (ENABLE_NODE, &show_memory_ripng_cmd);
  install_element (ENABLE_NODE, &show_memory_bgp_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf6_cmd);
  install_element (ENABLE_NODE, &show_memory_isis_cmd);
}

/* Stats querying from users */
/* Return a pointer to a human friendly string describing
 * the byte count passed in. E.g:
 * "0 bytes", "2048 bytes", "110kB", "500MiB", "11GiB", etc.
 * Up to 4 significant figures will be given.
 * The pointer returned may be NULL (indicating an error)
 * or point to the given buffer, or point to static storage.
 */
const char *
mtype_memstr (char *buf, size_t len, unsigned long bytes)
{
  unsigned int t, g, m, k;
  
  /* easy cases */
  if (!bytes)
    return "0 bytes";
  if (bytes == 1)
    return "1 byte";
    
  if (sizeof (unsigned long) >= 8)
    /* Hacked to make it not warn on ILP32 machines
     * Shift will always be 40 at runtime. See below too */
    t = bytes >> (sizeof (unsigned long) >= 8 ? 40 : 0);
  else
    t = 0;
  g = bytes >> 30;
  m = bytes >> 20;
  k = bytes >> 10;
  
  if (t > 10)
    {
      /* The shift will always be 39 at runtime.
       * Just hacked to make it not warn on 'smaller' machines. 
       * Static compiler analysis should mean no extra code
       */
      if (bytes & (1UL << ((sizeof (unsigned long) >= 8) ? 39 : 0)))
        t++;
      snprintf (buf, len, "%4d TiB", t);
    }
  else if (g > 10)
    {
      if (bytes & (1 << 29))
        g++;
      snprintf (buf, len, "%d GiB", g);
    }
  else if (m > 10)
    {
      if (bytes & (1 << 19))
        m++;
      snprintf (buf, len, "%d MiB", m);
    }
  else if (k > 10)
    {
      if (bytes & (1 << 9))
        k++;
      snprintf (buf, len, "%d KiB", k);
    }
  else
    snprintf (buf, len, "%ld bytes", bytes);
  
  return buf;
}

unsigned long
mtype_stats_alloc (int type)
{
  return mstat[type].alloc;
}
