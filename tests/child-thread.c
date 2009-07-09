/*
 * $Id: child-thread.c,v 1.3 2005/04/25 16:42:24 paul Exp $
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

/* This programme shows the effects of 'heavy' long-running functions
 * on the cooperative threading model.
 *
 * Run it with a config file containing 'password whatever', telnet to it
 * (it defaults to port 4000) and enter the 'clear foo string' command.
 * then type whatever and observe that the vty interface is unresponsive
 * for quite a period of time, due to the clear_something command
 * taking a very long time to complete.
 */
#include <zebra.h>

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "hash.h"
#include "jhash.h"

extern struct thread_master *master;

struct hash *var_hash;

struct var {
  const char *name;
  char *data;
};

/* Make hash value by raw aspath data. */
static unsigned int
var_key_make (void *p)
{
  struct var *var = p;
  unsigned int key = 0;

  key = jhash (var->name, strlen (var->name), 2334325);

  return key;
}

static int
var_cmp (const void *arg1, const void *arg2)
{
  const struct var *var1 = arg1;
  const struct var *var2 = arg2;
  
  return !strcmp (var1->name, var2->name);
}

static void *
var_alloc (void *arg)
{
  struct var *var = arg;
  struct var *new;
  
  new = XMALLOC (MTYPE_TMP, sizeof (struct var));
  
  new->name = XSTRDUP (MTYPE_TMP, var->name);
  new->data = var->data;
  
  return new;
}

static void
var_init (void)
{
  char buf[100];
  struct var v;
  char *str = "foo";
  char c;
  int i;
  
  v.name = buf;
  
  memset (&buf, '\0', sizeof (buf));
  
  for (i = 0; i < sizeof(buf) - 1; i++)
    {
      for (c = 'a'; c <= 'z'; c++)
        {
          struct var *found;
          v.data = NULL;
          
          buf[i] = c;
          
          found = hash_get (var_hash, &v, &var_alloc);
          
          if (found->data)
            XFREE (MTYPE_TMP, found->data);
          
          found->data = str;
        }
    }

}

DEFUN (set,
       set_cmd,
       "set WORD .LINE",
       "set variable\n"
       "variable name\n"
       "arbitrary string\n")
{
  char *str;
  struct var v;
  struct var *found;
  
  if (argc < 2)
    {
      vty_out (vty, "%% string argument required%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  v.name = argv[0];
  v.data = NULL;
  
  str = argv_concat (argv, argc, 1);
  
  found = hash_get (var_hash, &v, &var_alloc);
  
  if (found->data)
    XFREE (MTYPE_TMP, found->data);
  
  found->data = str;
  
  return CMD_SUCCESS;
}

static void
var_vty (struct var *v, struct vty *vty)
{
  vty_out (vty, "%s: %s%s", v->name, v->data, VTY_NEWLINE);
}

static void
var_iter (struct hash_backet *backet, struct vty *vty)
{
  //printf ("in child %s\n",((struct var *) backet->data)->name);

  var_vty ((struct var *) backet->data, vty);
}

DEFUN_CHILD (view,
       view_cmd,
       "view WORD",
       "view variable\n"
       "variable name\n"
       "arbitrary string\n")
{
  struct var var;
  struct var *result;
  
  zlog_debug ("in view, %d\n", getpid());
  
  if (!argc)
    {
      
      hash_iterate (var_hash, 
                    (void (*) (struct hash_backet *, void *)) var_iter,
                    vty);
      return CMD_SUCCESS;
    }
  
  var.name = argv[0];
  
  if ((result = hash_lookup (var_hash, &var)) == NULL)
    {
      vty_out (vty, "%% could not find variable %s%s", var.name, VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  var_vty (result, vty);
  
  return CMD_SUCCESS;
}

ALIAS_CHILD (view,
             view_all_cmd,
             "view",
             "view all variables\n")

ALIAS (view,
       view2_all_cmd,
       "view2",
       "view all variables (in parent process)\n")

struct child_args {
  struct vty *vty;
  char *arg;
};


static int
child_func (struct thread *t)
{
  struct child_args *ca = THREAD_ARG(t);
  
  printf ("in child: %s\n", ca->arg);
  exit (0);  
}

static int
child_finish_func (struct thread *t)
{
  struct child_args *ca = THREAD_ARG(t);
  struct vty *vty = ca->vty;
  
  printf ("parent: child finished %d %s\n", t->u.child, ca->arg);
  vty_out (vty, "parent: child finished %d %s%s",
           t->u.child, ca->arg, VTY_NEWLINE);
  
  XFREE (MTYPE_TMP, ca->arg);
  XFREE (MTYPE_TMP, ca);
  
  return CMD_SUCCESS;
}

DEFUN (child_thread,
       child_thread_cmd,
       "child-thread WORD",
       "run a child process, with fork deferred to thread\n"
       "word to pass to the child\n")
{
  struct child_args *ca;
  if (argc != 1)
    {
      vty_out (vty, "%% word argument required%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ca = XMALLOC (MTYPE_TMP, sizeof (struct child_args));
  ca->vty = vty;
  ca->arg = XSTRDUP (MTYPE_TMP, argv[0]);
  
  thread_add_child (master, child_func, ca, child_finish_func);
  
  return CMD_SUCCESS;
}

DEFUN (child_inline,
       child_inline_cmd,
       "child-inline WORD",
       "run a child process, fork done in line\n"
       "word to pass to the child\n")
{
  struct child_args *ca;
  if (argc != 1)
    {
      vty_out (vty, "%% word argument required%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  ca = XMALLOC (MTYPE_TMP, sizeof (struct child_args));
  ca->vty = vty;
  ca->arg = XSTRDUP (MTYPE_TMP, argv[0]);
  
  thread_do_child (master, child_func, ca, child_finish_func);
  
  return CMD_SUCCESS;
}

DEFUN_CHILD (child,
             child_cmd,
             "child WORD",
             "run a command as a child process, using vty DEFUN_CHILD\n"
             "word to pass to the child\n")
{
  if (argc != 1)
    {
      vty_out (vty, "%% word argument required%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  vty_out (vty, "in child: %s%s", argv[0], VTY_NEWLINE);
  printf ("in child: %s\n", argv[0]);

  return CMD_SUCCESS;
}

void
test_init (void)
{
  var_hash = hash_create_size (128, var_key_make, var_cmp);
  var_init ();
  printf ("here\n");
  install_element (VIEW_NODE, &set_cmd);
  install_element (VIEW_NODE, &view_cmd);
  install_element (VIEW_NODE, &view_all_cmd);
  install_element (VIEW_NODE, &view2_all_cmd);
  install_element (VIEW_NODE, &child_thread_cmd);
  install_element (VIEW_NODE, &child_inline_cmd);
  install_element (VIEW_NODE, &child_cmd);
}
