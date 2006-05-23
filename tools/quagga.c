/*
 * $Id: quagga.c,v 1.1 2005/04/25 16:42:24 paul Exp $
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

#include <fnmatch.h>
#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"

static struct {
  unsigned int sources; /* default is all */
#define QTOOL_SOURCE_ROUTES (1 << 0)
#define QTOOL_SOURCE_IFACE  (1 << 1)
  char *ifarg; /* interface pattern */
  afi_t afi; /* default is both AFIs */
  int monitor; /* don't exit, keep printing changes */
} config = { .sources = -1U };

struct thread_master *master;
static struct zclient *zclient;

/* longopts - should be unique across all subcommands. Even where they
 * are not valid for that command
 * Though, we only have one sub-command at the moment ;)
 */
static struct option longopts[] = 
{
  { "source",		required_argument,	NULL,	's' },
  { "interface",	required_argument, 	NULL,	'i' },
  { "route",		required_argument, 	NULL,	'r' },
  { "version",		no_argument,		NULL,	'V' },
  { "ipv4",		no_argument,		NULL,	'4' },
  { "ipv6",		no_argument,		NULL,	'6' },
  { "help",		no_argument,		NULL,	'?' },
  { 0 }
};

/* Sub-commands */
enum subcommand_types
{
  QTOOL_SCMD_UNKNOWN = 0,
  QTOOL_SCMD_LIST,
  QTOOL_SCMD_MONITOR,
  QTOOL_SCMD_MAX,
};

static const char *subcommands[] =
{
  [QTOOL_SCMD_LIST] = "list",
  [QTOOL_SCMD_MONITOR] = "monitor",
};

/* option arguments allowed prior to sub-command */
static const char *init_opts = "+V?";

/* option arguments allowed for subcommands */
static const char *subcmd_opts[] =
{
  [QTOOL_SCMD_LIST] = "+s:i:r:V46?",
  [QTOOL_SCMD_MONITOR] = "+s:i:r:V46?",
  NULL,
};

static enum subcommand_types
str2subcommand (const char *str)
{
  int i;
  
  for (i = 0; i < QTOOL_SCMD_MAX; i++)
    if (strcmp (subcommands[i], str) == 0)
      return i;
  return QTOOL_SCMD_UNKNOWN;
}

/* Initial parsing, before command is known */
static int
get_subcommand (int argc, char **argv)
{
  /* take care of:
   * $0 <--help|--version>
   * $0 SUBCOMMAND
   */
  
}

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s SUBCOMMAND [OPTION...]\n\n"
"Quagga command line tool.\n\n\
Report bugs to %s\n", 
      progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}

static void
subusage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s SUBCOMMAND [OPTION...]\n\n"
"Quagga command line tool.\n\n\
\n\
  -r TYPE\n\
  --route=TYPE\n\
                Retrieve routes of the given type.\n\
                May be given multiple times as distinct arguments,\n\
                and/or the TYPE may be given as comma seperated list.\n\
                Types may be prefixed with `!' to NOT display those routes.\n\
                Types are:\n\
                  kernel, connected, ospf, ospf6, rip,\n\
                  ripng, bgp, isis, static, all\n\
                E.g: -r bgp -r rip - list bgp and rip routes\n\
                     -r bgp,rip    - list bgp and rip routes\n\
                     -r all,!bgp   - list all but bgp routes\n\
  -i\n\
  --interface[=<pattern>]\n\
                Retrieve interface state.\n\
                Optional interface to restrict output to can be\n\
                given via the long form. Only one interface\n\
                may be specified, however it may be specified as a glob\n\
                pattern. Further, it may be prefixed with ! to indicate\n\
                negative match.\n\
                E.g: --interface='bge*'  - list all bge interfaces\n\
                     --interface='!bge*' - list all but bge interfaces\n\
\n\
  -(4|6)\n\
  --ipv(4|6)	Display only IPv4 or IPv6 prefixes\n\
  -m\n\
  --monitor	Monitor\n\
  -?\n\
  --help	Display this help and exit\n\
  -V\n\
  --version	Print version and exit\n\
\n\
One or both of the commands, --interface and/or --route, must be given\n\
Report bugs to %s\n", 
      progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}

static const char * const route_subopts[] =
{
  [ZEBRA_ROUTE_SYSTEM]	= "system",
  [ZEBRA_ROUTE_KERNEL]	= "kernel",
  [ZEBRA_ROUTE_CONNECT]	= "connected",
  [ZEBRA_ROUTE_STATIC]	= "static",
  [ZEBRA_ROUTE_RIP]	= "rip",
  [ZEBRA_ROUTE_RIPNG]	= "ripng",
  [ZEBRA_ROUTE_OSPF]	= "ospf",
  [ZEBRA_ROUTE_OSPF6]	= "osfp6",
  [ZEBRA_ROUTE_ISIS]	= "isis",
  [ZEBRA_ROUTE_BGP]	= "bgp",
  [ZEBRA_ROUTE_HSLS]	= "hsls",
  [ZEBRA_ROUTE_MAX]	= "all",
  NULL
};

/* 0 to display this ifname, 1 to ignore */
static unsigned int
qcli_test_ifname (const char *ifname)
{
  const char *i;
  int neg = 0;
  unsigned int ret;
  
  if (!config.ifarg)
    return 0;
  
  if (!ifname)
    return 0;
  
  if (config.ifarg[0] == '!')
    {
      neg = 1;
      i = (config.ifarg + 1);
    }
  else
    i = config.ifarg;
  
  if (i[0] == '\0')
    return 0;
  
  ret = fnmatch (i, ifname, 0);
    
  if (neg)
    ret = (ret ? 0 : 1);
  
  return ret;
}

/* Zclient call back functions
 * called by lib/zclient.c on arrival of a Zserv message
 */
static int
qcli_interface_add (int command, struct zclient *zclient,
                    zebra_size_t length)
{
  struct interface *ifp;
  
  ifp = zebra_interface_add_read (zclient->ibuf);
  if (ifp)
    {
      int i;
      
      if (qcli_test_ifname (ifp->name))
        return 0;
      
      printf ("interface: %s", ifp->name);
      printf (" is %s\n",
              if_is_up (ifp) ? "up" : "down");
      if (ifp->flags)
        printf ("  %10s: %s\n", "flags", if_flag_dump (ifp->flags));
      if (ifp->hw_addr_len)
        {
          printf ("  %10s: ", "HW address");
          for (i = 0; i < ifp->hw_addr_len; i++)
            printf ("%s%02x", i == 0 ? "" : ":", ifp->hw_addr[i]);
          printf ("\n");
        }
      if (ifp->ifindex)
        {
          printf ("  %10s: %u metric: %u mtu: %u mtu6: %u", "index",
                  ifp->ifindex, ifp->metric, ifp->mtu, ifp->mtu6);
          if (ifp->bandwidth)
            printf (" bandwidth: %u", ifp->bandwidth);
          printf ("\n");
        }
    }
  
  return 0;
}

static int
qcli_interface_del (int command, struct zclient *zclient,
                    zebra_size_t length)
{
  printf ("%s\n", __func__);
  return 0;
}

static int
qcli_interface_state_up (int command, struct zclient *zclient,
                         zebra_size_t length)
{
  printf ("%s\n", __func__);
  return 0;
}

static int
qcli_interface_state_down (int command, struct zclient *zclient,
                           zebra_size_t length)
{
  printf ("%s\n", __func__);
  return 0;
}


static int
qcli_interface_address_add (int command, struct zclient *zclient,
                            zebra_size_t length)
{
  struct connected *c;
  char addr[64];
  
  c = zebra_interface_address_read (command, zclient->ibuf);
  
  if (!c)
    return 0;
  
  if (config.afi && (c->address->family != afi2family (config.afi)))
    return 0;
  
  if (qcli_test_ifname (c->ifp->name))
    return 0;
  
  if (c->address)
    prefix2str (c->address, addr, sizeof(addr));
  else
    return 0;
  
  printf ("address: %-5s %s",
          prefix_family_str (c->address), addr);
  
  if (c->destination)
    {
      const char *dstr;
      
      inet_ntop (c->destination->family, &c->destination->u.prefix,
                 addr, sizeof(addr));
      if (if_is_pointopoint (c->ifp))
        dstr = "peer";
      else if (if_is_broadcast (c->ifp))
        dstr = "broadcast";
      else
        dstr = "destination";
      printf (" %s %s", dstr, addr);
    }
  printf (" %s\n", c->ifp->name);
  return 0;
}


static int
qcli_interface_address_del (int command, struct zclient *zclient,
                            zebra_size_t length)
{
  printf ("%s\n", __func__);
  return 0;
}

#ifdef ZEBRA_COMMAND_COMPLETE
static int
qcli_completion (int command, struct zclient *zclient, zebra_size_t length)
{
  int cmd = zebra_completion_read (zclient);
  int i;
  
  //printf ("%s: %s completed\n", __func__, zserv_command_string(cmd));
  switch (cmd)
    {
      case ZEBRA_INTERFACE_ADDRESS_ADD:
        UNSET_FLAG (config.objects, QTOOL_OBJECT_IFACE);
        break;
      case ZEBRA_REDISTRIBUTE_ADD:
        for (i = ZEBRA_ROUTE_SYSTEM; i < ZEBRA_ROUTE_MAX; i++)
          if (i != zclient->redist_default
              && zclient->redist[i]
              && zclient->redist[i] < ZCLIENT_REDIST_COMPLETE)
            return 0;
        UNSET_FLAG (config.objects, QTOOL_OBJECT_ROUTES);
        break;
    }
  if (!(config.objects || config.monitor))
    exit (0);
  return 0;
}
#endif /* ZEBRA_COMMAND_COMPLETE */

static int
qcli_zebra_route (int command, struct zclient *zclient, zebra_size_t length)
{
  int nhnum = 0, i;
  u_char type, flags, attrs;
  struct prefix p;
  struct stream *s = zclient->ibuf;
  char addrbuf[64];
   
  type = stream_getc (s);
  flags = stream_getc (s);
  attrs = stream_getc (s);
  p.prefixlen = stream_getc (s);
  
  //printf ("type: %u, flags %u, attrs %u, plen: %u\n", 
  //        type, flags, attrs, p.prefixlen);
  
  switch (command)
    {
      case ZEBRA_IPV4_ROUTE_ADD:
      case ZEBRA_IPV4_ROUTE_DELETE:
        p.family = AF_INET;
        break;
      case ZEBRA_IPV6_ROUTE_ADD:
      case ZEBRA_IPV6_ROUTE_DELETE:
        p.family = AF_INET6;
        break;
      default:
        return 0;
    }
  
  printf ("route: ");
  
  /* if restribute_add completed, then we're monitoring, these are updates */
  if (!CHECK_FLAG (config.sources, QTOOL_SOURCE_ROUTES))
    switch (command)
      {
        case ZEBRA_IPV4_ROUTE_ADD:
        case ZEBRA_IPV6_ROUTE_ADD:
          printf ("%6s: ", "add");
          break;
        case ZEBRA_IPV4_ROUTE_DELETE:
        case ZEBRA_IPV6_ROUTE_DELETE:
          printf ("%6s: ", "remove");
          break;
      }
    
    stream_get (&p.u.prefix, s, (p.prefixlen + 7) / 8);
    
    prefix2str (&p, addrbuf, sizeof(addrbuf));
    printf ("%c> %s", zebra_route_char (type), addrbuf);
    
    if (CHECK_FLAG (attrs, ZAPI_MESSAGE_NEXTHOP))
      nhnum = stream_getc (s);
    
    for (i = 0; i < nhnum; i++)
      {
        switch (command)
          {
            case ZEBRA_IPV4_ROUTE_ADD:
            case ZEBRA_IPV4_ROUTE_DELETE:
              stream_get (&p.u.prefix, s, 4);
              break;
            case ZEBRA_IPV6_ROUTE_ADD:
            case ZEBRA_IPV6_ROUTE_DELETE:
              stream_get (&p.u.prefix, s, 16);
              break;            
          }
        inet_ntop (p.family, &p.u.prefix, addrbuf, sizeof(addrbuf));
        printf (" via %s", addrbuf);
        
        if (CHECK_FLAG (attrs, ZAPI_MESSAGE_IFINDEX))
          {
            stream_getc (s);
            printf (" ifindex %u", stream_getl (s));
          }
      }
    
    if (CHECK_FLAG (attrs, ZAPI_MESSAGE_DISTANCE))
      {
        unsigned int distance;
        
        if ((distance = stream_getc (s)))
          printf (", distance %u", distance);
      }
    if (CHECK_FLAG (attrs, ZAPI_MESSAGE_METRIC))
      printf (", metric %u\n", stream_getl (s));
    return 0;
}

static void
qcli_zebra_init (void)
{
  if (config.sources & QTOOL_SOURCE_IFACE)
    {
      zclient->interface_add = qcli_interface_add;
      zclient->interface_delete = qcli_interface_del;
      zclient->interface_up = qcli_interface_state_up;
      zclient->interface_down = qcli_interface_state_down;
      zclient->interface_address_add = qcli_interface_address_add;
      zclient->interface_address_delete = qcli_interface_address_del;
    }
  if (config.sources & QTOOL_SOURCE_ROUTES)
    {
      switch (config.afi)
        {
          default:
            zclient->ipv6_route_add = qcli_zebra_route;   
            zclient->ipv6_route_delete = qcli_zebra_route;
          case AFI_IP:
            zclient->ipv4_route_add = qcli_zebra_route;   
            zclient->ipv4_route_delete = qcli_zebra_route;
            break;
          case AFI_IP6:
            zclient->ipv6_route_add = qcli_zebra_route;
            zclient->ipv6_route_delete = qcli_zebra_route;
        }
    }
#ifdef ZEBRA_COMMAND_COMPLETION
  zclient->completion = qcli_completion;
#endif /* ZEBRA_COMMAND_COMPLETION */
}

static int
exit_timer (struct thread *t)
{
  exit (0);
  return 0;
}

/* main routine. */
int
main (int argc, char **argv)
{
  char *p;
  char *progname;
  struct thread thread;
  
  /* Set umask before anything for security */
  umask (0027);

  /* get program name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* master init. */
  master = thread_master_create ();

  /* setup zclient */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_SYSTEM);
  
  while (1) 
    {
      int opt;
      char *subopts, *value;
      
      opt = getopt_long (argc, argv, subcmd_opts[QTOOL_SCMD_LIST], longopts, 0);

      printf ("optind: %d, opt %x optopt: %x, argc: %u, argv[optind]: %s\n",
              optind, opt, optopt, argc, argv[optind]);

      if (opt == -1)
        break;

      switch (opt) 
	{
	case 0:
	  break;
        case 'r':
          config.sources |= QTOOL_SOURCE_ROUTES;
          if (optarg)
            {
              int rtype;
              
              subopts = optarg;
              while (*subopts != '\0')
                {
                  int set;
                  
                  if (*subopts == '!')
                    {
                      set = 0;
                      subopts++;
                      if (*subopts == '\0')
                        break;
                    }
                  else
                    set = 1;
                  
                  if ((rtype = getsubopt (&subopts, route_subopts, &value))
                      == ZEBRA_ROUTE_MAX)
                    {
                      /* overloaded as all routes */
                      for (rtype = ZEBRA_ROUTE_SYSTEM;
                           rtype < ZEBRA_ROUTE_MAX; 
                           rtype++)
                        zclient->redist[rtype] = set;
                    }
                  else if (rtype >= ZEBRA_ROUTE_KERNEL || 
                           rtype < ZEBRA_ROUTE_MAX)
                    zclient->redist[rtype] = set;
                  else
                    {
                        fprintf (stderr, "Unknown suboption: `%s'\n", value);
                        usage (progname, 1);
                    }
                }
            }
          break;
	case 'i':
	  config.sources |= QTOOL_SOURCE_IFACE;
	  if (optarg)
            config.ifarg = optarg;
	  break;
        case 'm':
          config.monitor = 1;
          break;
	case '4':
	  if (config.afi)
	    usage (progname, 1);
          config.afi = AFI_IP;
	  break;
        case '6':
          if (config.afi)
            usage (progname, 1);
          config.afi = AFI_IP6;
          break;
	case 'V':
	  print_version (progname);
	  exit (0);
	  break;
	case '?':
	  /* optopt disambiguates '-?' help from '?' getopt/unknown */
	  if (optopt == 0 || optopt == '?')
	    usage (progname, 0);
          else
            usage (progname, 1);
          exit (1);
          break;
	default:
	  usage (progname, 1);
	  break;
	}
    }
  
  /* Library inits. */
  cmd_init (0);
  memory_init ();
  if_init ();
  
  qcli_zebra_init ();
#ifndef ZEBRA_COMMAND_COMPLETION
  if (!config.monitor)
    thread_add_timer (master, exit_timer, NULL, 6);
#endif /* !ZEBRA_COMMAND_COMPLETION */

  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
  return 0;
}

