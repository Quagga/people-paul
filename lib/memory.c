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

#include "log.h"
#include "memory.h"

/* some debug and probably performance debilitating compile options.. */
#define MTYPE_EXTRA_STATS 1

static void log_memstats(int log_priority);

static struct message mstr [] =
{
  { MTYPE_THREAD, "thread" },
  { MTYPE_THREAD_MASTER, "thread_master" },
  { MTYPE_VECTOR, "vector" },
  { MTYPE_VECTOR_INDEX, "vector_index" },
  { MTYPE_IF, "interface" },
  { 0, NULL },
};

/* Fatal memory allocation error occured. */
static void __attribute__ ((noreturn))
zerror (const char *fname, int type, size_t size)
{
  zlog_err ("%s : can't allocate memory for `%s' size %d: %s\n", 
	    fname, lookup (mstr, type), (int) size, safe_strerror(errno));
  log_memstats(LOG_WARNING);
  /* N.B. It might be preferable to call zlog_backtrace_sigsafe here, since
     that function should definitely be safe in an OOM condition.  But
     unfortunately zlog_backtrace_sigsafe does not support syslog logging at
     this time... */
  zlog_backtrace(LOG_WARNING);
  abort();
}


static struct 
{
  unsigned long alloc;
#if (MTYPE_EXTRA_STATS > 0)
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
}

/* Decrement allocation counter. */
static inline void
alloc_dec (int type)
{
  mstat[type].alloc--;
}

/* Memory allocation. */
void *
zmalloc (int type, size_t size)
{
  void *memory;

  memory = malloc (size);

  if (memory == NULL)
    zerror ("malloc", type, size);
  
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

  memory = calloc (1, size);

  if (memory == NULL)
    zerror ("calloc", type, size);

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
#if (MTYPE_EXTRA_STATS > 0)
  mstat[type].st_free++;
#endif /* MTYPE_EXTRA_STATS */
  
  alloc_dec (type);
  free (ptr);
}

/* String duplication. */
char *
zstrdup (int type, const char *str)
{
  void *dup;
  
  dup = strdup (str);
  if (dup == NULL)
    zerror ("strdup", type, strlen (str));
  
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
  if (MTYPE_EXTRA_STATS > 0)
    vty_out (vty, "%12s\t%s%s", "diff:",
             "Discrepancy between (allocations - free) and 'allocated'",
             VTY_NEWLINE);
  vty_out (vty, "%s%-28s | %10s%s",
           VTY_NEWLINE,
           "Memory Type", "Allocated",
           VTY_NEWLINE);
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
        vty_out (vty, "%-28s | %10lu%s", 
                 m->format, 
                 mstat[m->index].alloc,
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
          }
#endif /* MTYPE_EXTRA_STATS */

        /* If we don't have the extra stats output, every objects fits on one
         * line and we don't need the extra newline to help distinguish
         */
        if (MTYPE_EXTRA_STATS > 0)
          vty_out (vty, "%s", VTY_NEWLINE);
        
        needsep = 1;
      }

  return needsep;
}

DEFUN (show_memory_all,
       show_memory_all_cmd,
       "show memory all",
       "Show running system information\n"
       "Memory statistics\n"
       "All memory statistics\n")
{
  struct mlist *ml;
  int needsep = 0;

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
