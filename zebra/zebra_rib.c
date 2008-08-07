/* Routing Information Base.
 * Copyright (C) 1997, 98, 99, 2001 Kunihiro Ishiguro
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

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "str.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "nexthop.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"

/* Default rtm_table for all clients */
extern struct zebra_t zebrad;

/* Hold time for RIB process, should be very minimal.
 * it is useful to able to set it otherwise for testing, hence exported
 * as global here for test-rig code.
 */
int rib_process_hold_time = 10;

/* Each route type's string and default distance value. */
static const struct
{  
  int key;
  int distance;
} route_info[] =
{
  {ZEBRA_ROUTE_SYSTEM,    0},
  {ZEBRA_ROUTE_KERNEL,    ZEBRA_KERNEL_DISTANCE_DEFAULT  },
  {ZEBRA_ROUTE_CONNECT,   ZEBRA_CONNECT_DISTANCE_DEFAULT },
  {ZEBRA_ROUTE_STATIC,    ZEBRA_STATIC_DISTANCE_DEFAULT  },
  {ZEBRA_ROUTE_RIP,       ZEBRA_RIP_DISTANCE_DEFAULT     },
  {ZEBRA_ROUTE_RIPNG,     ZEBRA_RIPNG_DISTANCE_DEFAULT   },
  {ZEBRA_ROUTE_OSPF,      ZEBRA_OSPF_DISTANCE_DEFAULT    },
  {ZEBRA_ROUTE_OSPF6,     ZEBRA_OSPF6_DISTANCE_DEFAULT   },
  {ZEBRA_ROUTE_ISIS,      ZEBRA_ISIS_DISTANCE_DEFAULT    },
  /* IBGP is 200 though.. */
  {ZEBRA_ROUTE_BGP,       ZEBRA_EBGP_DISTANCE_DEFAULT    },
};

/* Vector for routing table.  */
static vector vrf_vector;

/* Allocate new VRF.  */
static struct vrf *
vrf_alloc (const char *name)
{
  struct vrf *vrf;

  vrf = XCALLOC (MTYPE_VRF, sizeof (struct vrf));

  /* Put name.  */
  if (name)
    vrf->name = XSTRDUP (MTYPE_VRF_NAME, name);

  /* Allocate routing table and static table.  */
  vrf->table[AFI_IP][SAFI_UNICAST] = route_table_init ();
  vrf->table[AFI_IP6][SAFI_UNICAST] = route_table_init ();
  vrf->stable[AFI_IP][SAFI_UNICAST] = route_table_init ();
  vrf->stable[AFI_IP6][SAFI_UNICAST] = route_table_init ();

  return vrf;
}

/* Free VRF.  */
static void
vrf_free (struct vrf *vrf)
{
  if (vrf->name)
    XFREE (MTYPE_VRF_NAME, vrf->name);
  XFREE (MTYPE_VRF, vrf);
}

/* Lookup VRF by identifier.  */
struct vrf *
vrf_lookup (u_int32_t id)
{
  return vector_lookup (vrf_vector, id);
}

/* Lookup VRF by name.  */
static struct vrf *
vrf_lookup_by_name (char *name)
{
  unsigned int i;
  struct vrf *vrf;

  for (i = 0; i < vector_active (vrf_vector); i++)
    if ((vrf = vector_slot (vrf_vector, i)) != NULL)
      if (vrf->name && name && strcmp (vrf->name, name) == 0)
	return vrf;
  return NULL;
}

/* Initialize VRF.  */
static void
vrf_init (void)
{
  struct vrf *default_table;

  /* Allocate VRF vector.  */
  vrf_vector = vector_init (1);

  /* Allocate default main table.  */
  default_table = vrf_alloc ("Default-IP-Routing-Table");

  /* Default table index must be 0.  */
  vector_set_index (vrf_vector, 0, default_table);
}

/* Lookup route table.  */
struct route_table *
vrf_table (afi_t afi, safi_t safi, u_int32_t id)
{
  struct vrf *vrf;

  vrf = vrf_lookup (id);
  if (! vrf)
    return NULL;

  return vrf->table[afi][safi];
}

/* Lookup static route table.  */
struct route_table *
vrf_static_table (afi_t afi, safi_t safi, u_int32_t id)
{
  struct vrf *vrf;

  vrf = vrf_lookup (id);
  if (! vrf)
    return NULL;

  return vrf->stable[afi][safi];
}

void
rib_nexthop_add (struct rib *rib, struct prefix *gate, 
             struct prefix *src, unsigned int ifindex)
{
  struct nexthop *nh = nexthop_new ();
  
  if (gate && src)
    assert (gate->family == src->family);
  
  if (gate)
    {
      prefix_copy ((nh->gate = prefix_new()), gate);
      nh->gate->prefixlen = PREFIX_MAX_PLEN (nh->gate);
    }
  if (src)
    {
      prefix_copy ((nh->src = prefix_new()), src);
      nh->src->prefixlen = PREFIX_MAX_PLEN (nh->src);
    }
  
  nh->ifindex = ifindex;
  NEXTHOP_ADD (&rib->nexthop, nh, rib->nexthop_num);
}

void
rib_nexthop_blackhole_add (struct rib *rib)
{
  struct nexthop *nexthop;

  nexthop = nexthop_new ();
  nexthop->flags = NEXTHOP_FLAG_BLACKHOLE;
  SET_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE);

  NEXTHOP_ADD (&rib->nexthop, nexthop, rib->nexthop_num);

  return;
}

struct rib *
rib_match (struct prefix *addr)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop;

  /* Lookup table.  */
  table = vrf_table (family2afi (addr->family), SAFI_UNICAST, 0);
  if (! table)
    return 0;
  
  rn = route_node_match (table, addr);
  
  while (rn)
    {
      route_unlock_node (rn);
      
      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	{
	  if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	    continue;
	  if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	    break;
	}

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match 
	  || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    /* Directly point connected route. */
	    return match;
	  else
	    {
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
		  return match;
              /* XXX: Why don't we walk up for this case? */
	      return NULL;
	    }
	}
    }
  return NULL;
}

struct rib *
rib_lookup (struct prefix *p)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *nexthop;

  /* Lookup table.  */
  table = vrf_table (family2afi (p->family), SAFI_UNICAST, 0);
  if (! table)
    return 0;

  rn = route_node_lookup (table, p);

  /* No route for this prefix. */
  if (! rn)
    return NULL;

  /* Unlock node. */
  route_unlock_node (rn);

  for (match = rn->info; match; match = match->next)
    {
      if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	continue;
      if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	break;
    }

  if (! match || match->type == ZEBRA_ROUTE_BGP)
    return NULL;

  if (match->type == ZEBRA_ROUTE_CONNECT)
    return match;
  
  for (nexthop = match->nexthop; nexthop; nexthop = nexthop->next)
    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
      return match;

  return NULL;
}

/*
 * This clone function, unlike its original rib_lookup_ipv4(), checks
 * if specified IPv4 route record (prefix/mask -> gate) exists in
 * the whole RIB and has ZEBRA_FLAG_SELECTED set.
 *
 * Return values:
 * -1: error
 * 0: exact match found
 * 1: a match was found with a different gate
 * 2: connected route found
 * 3: no matches found
 */
int
rib_lookup_route (struct prefix *p, struct prefix *qgate)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *nexthop;

  /* Lookup table.  */
  table = vrf_table (family2afi (p->family), SAFI_UNICAST, 0);
  if (! table)
    return ZEBRA_RIB_LOOKUP_ERROR;

  /* Scan the RIB table for exactly matching RIB entry. */
  rn = route_node_lookup (table, p);

  /* No route for this prefix. */
  if (! rn)
    return ZEBRA_RIB_NOTFOUND;

  /* Unlock node. */
  route_unlock_node (rn);

  /* Find out if a "selected" RR for the discovered RIB entry exists ever. */
  for (match = rn->info; match; match = match->next)
    {
      if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	continue;
      if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	break;
    }

  /* None such found :( */
  if (!match)
    return ZEBRA_RIB_NOTFOUND;

  if (match->type == ZEBRA_ROUTE_CONNECT)
    return ZEBRA_RIB_FOUND_CONNECTED;
  
  /* Ok, we have a cood candidate, let's check it's nexthop list... */
  for (nexthop = match->nexthop; nexthop; nexthop = nexthop->next)
    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
    {
      /* We are happy with either direct or recursive hexthop */
      if ((nexthop->gate && prefix_same (nexthop->gate, qgate))
          || (nexthop->rgate && prefix_same (nexthop->rgate, qgate)))
        return ZEBRA_RIB_FOUND_EXACT;
      else
      {
        if (IS_ZEBRA_DEBUG_RIB)
        {
          char gate_buf[INET6_ADDRSTRLEN], 
               rgate_buf[INET6_ADDRSTRLEN],
               qgate_buf[INET6_ADDRSTRLEN];
          
          prefix2str (nexthop->gate, gate_buf, sizeof(gate_buf));
          prefix2str (nexthop->rgate, rgate_buf, sizeof(rgate_buf));
          prefix2str (qgate, qgate_buf, sizeof (qgate_buf));
          zlog_debug ("%s: qgate == %s, gate == %s, rgate == %s",
                      __func__, qgate_buf, gate_buf, rgate_buf);
        }
        return ZEBRA_RIB_FOUND_NOGATE;
      }
    }

  return ZEBRA_RIB_NOTFOUND;
}

/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
static int
nexthop_gate_active (struct rib *rib, struct nexthop *nexthop, int set,
                struct route_node *top)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *match;
  struct nexthop *newhop;

  if (set)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

  /* Make lookup prefix. */
  assert (nexthop->gate != NULL);

  /* Lookup table.  */
  table = vrf_table (family2afi (nexthop->gate->family), SAFI_UNICAST, 0);
  if (! table)
    return 0;

  rn = route_node_match (table, nexthop->gate);
  while (rn)
    {
      route_unlock_node (rn);
      
      /* If lookup self prefix return immidiately. */
      if (rn == top)
	return 0;

      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	{
	  if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
	    continue;
	  if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
	    break;
	}

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match 
	  || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    {
	      /* Directly point connected route. */
	      
	      /* Why would this needed???
	      newhop = match->nexthop;
	      if (newhop && nexthop->type == NEXTHOP_TYPE_IPV4)
		nexthop->ifindex = newhop->ifindex;
	      */
	      return 1;
	    }
	  else if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_INTERNAL))
	    {
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
			
			if (newhop->gate)
			  {
			    if (!nexthop->rgate)
			      nexthop->rgate = prefix_new ();
			    prefix_copy (nexthop->rgate, newhop->gate);
                          }
                        
			if (newhop->ifindex != IFINDEX_INTERNAL)
			  nexthop->rifindex = newhop->ifindex;
		      }
		    return 1;
		  }
	      return 0;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
  return 0;
}


#define RIB_SYSTEM_ROUTE(R) \
        ((R)->type == ZEBRA_ROUTE_KERNEL || (R)->type == ZEBRA_ROUTE_CONNECT)

/* This function verifies reachability of one given nexthop, which can be
 * numbered or unnumbered, IPv4 or IPv6. The result is unconditionally stored
 * in nexthop->flags field. If the 4th parameter, 'set', is non-zero,
 * nexthop->ifindex will be updated appropriately as well.
 * An existing route map can turn (otherwise active) nexthop into inactive, but
 * not vice versa.
 *
 * The return value is the final value of 'ACTIVE' flag.
 */

static int
nexthop_active_check (struct route_node *rn, struct rib *rib,
		      struct nexthop *nexthop, int set)
{
  struct interface *ifp;
  route_map_result_t ret = RMAP_MATCH;
  extern char *proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX+1];
  struct route_map *rmap = NULL;

  /* We try find a reason the nexthop /cant/ be active.. */
  SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
  
  if (nexthop->ifindex != IFINDEX_INTERNAL)
    {
      ifp = if_lookup_by_index (nexthop->ifindex);
      if (!ifp || !if_is_operative(ifp))
        UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);        
    }

  if (nexthop->gate)
    {
      assert (rn->p.family == nexthop->gate->family);

#ifdef HAVE_IPV6      
      if (nexthop->gate->family == AF_INET6
          && !IN6_IS_ADDR_LINKLOCAL(&PREFIX_IN6_ADDR(nexthop->gate)))
        UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
#endif

      if (!nexthop_gate_active (rib, nexthop, set, rn))
        UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
    }
  
  if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
    return 0;
  
  if (RIB_SYSTEM_ROUTE(rib))
    return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);

  assert (rib->type >= 0 && rib->type < ZEBRA_ROUTE_MAX);
  
  if (proto_rm[rn->p.family][rib->type])
    rmap = route_map_lookup_by_name (proto_rm[rn->p.family][rib->type]);
  if (!rmap && proto_rm[rn->p.family][ZEBRA_ROUTE_MAX])
    rmap = route_map_lookup_by_name (proto_rm[rn->p.family][ZEBRA_ROUTE_MAX]);
  if (rmap) {
      ret = route_map_apply(rmap, &rn->p, RMAP_ZEBRA, nexthop);
  }

  if (ret == RMAP_DENYMATCH)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
  return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/* Iterate over all nexthops of the given RIB entry and refresh their
 * ACTIVE flag. rib->nexthop_active_num is updated accordingly. If any
 * nexthop is found to toggle the ACTIVE flag, the whole rib structure
 * is flagged with ZEBRA_FLAG_CHANGED. The 4th 'set' argument is
 * transparently passed to nexthop_active_check().
 *
 * Return value is the new number of active nexthops.
 */

static int
nexthop_active_update (struct route_node *rn, struct rib *rib, int set)
{
  struct nexthop *nexthop;
  unsigned int prev_active, prev_index, new_active;

  rib->nexthop_active_num = 0;
  UNSET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
  {
    prev_active = CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
    prev_index = nexthop->ifindex;
    if ((new_active = nexthop_active_check (rn, rib, nexthop, set)))
      rib->nexthop_active_num++;
    if (prev_active != new_active ||
	prev_index != nexthop->ifindex)
      SET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);
  }
  return rib->nexthop_active_num;
}



static void
rib_install_kernel (struct route_node *rn, struct rib *rib)
{
  int ret = 0;
  struct nexthop *nexthop;

  switch (rn->p.family)
    {
    case AF_INET:
      ret = kernel_add_ipv4 (&rn->p, rib);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      ret = kernel_add_ipv6 (&rn->p, rib);
      break;
#endif /* HAVE_IPV6 */
    }

  /* This condition is never met, if we are using rt_socket.c */
  if (ret < 0)
    {
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
    }
}

/* Uninstall the route from kernel. */
static int
rib_uninstall_kernel (struct route_node *rn, struct rib *rib)
{
  int ret = 0;
  struct nexthop *nexthop;

  switch (rn->p.family)
    {
    case AF_INET:
      ret = kernel_delete_ipv4 (&rn->p, rib);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      ret = kernel_delete_ipv6 (&rn->p, rib);
      break;
#endif /* HAVE_IPV6 */
    }

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  return ret;
}

/* Uninstall the route from kernel. */
static void
rib_uninstall (struct route_node *rn, struct rib *rib)
{
  if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
    {
      redistribute_delete (&rn->p, rib);
      if (! RIB_SYSTEM_ROUTE (rib))
	rib_uninstall_kernel (rn, rib);
      UNSET_FLAG (rib->flags, ZEBRA_FLAG_SELECTED);
    }
}

static void rib_unlink (struct route_node *, struct rib *);

/* Core function for processing routing information base. */
static void
rib_process (struct route_node *rn)
{
  struct rib *rib;
  struct rib *next;
  struct rib *fib = NULL;
  struct rib *select = NULL;
  struct rib *del = NULL;
  int installed = 0;
  struct nexthop *nexthop = NULL;
  char buf[INET6_ADDRSTRLEN];
  
  assert (rn);
  
  if (IS_ZEBRA_DEBUG_RIB || IS_ZEBRA_DEBUG_RIB_Q)
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);

  for (rib = rn->info; rib; rib = next)
    {
      /* The next pointer is saved, because current pointer
       * may be passed to rib_unlink() in the middle of iteration.
       */
      next = rib->next;
      
      /* Currently installed rib. */
      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
        {
          assert (fib == NULL);
          fib = rib;
        }
      
      /* Unlock removed routes, so they'll be freed, bar the FIB entry,
       * which we need to do do further work with below.
       */
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        {
          if (rib != fib)
            {
              if (IS_ZEBRA_DEBUG_RIB)
                zlog_debug ("%s: %s/%d: rn %p, removing rib %p", __func__,
                  buf, rn->p.prefixlen, rn, rib);
                rib_unlink (rn, rib);
            }
          else
            del = rib;
          
          continue;
        }
      
      /* Skip unreachable nexthop. */
      if (! nexthop_active_update (rn, rib, 0))
        continue;

      /* Infinit distance. */
      if (rib->distance == DISTANCE_INFINITY)
        continue;

      /* Newly selected rib, the common case. */
      if (!select)
        {
          select = rib;
          continue;
        }
      
      /* filter route selection in following order:
       * - connected beats other types
       * - lower distance beats higher
       * - lower metric beats higher for equal distance
       * - last, hence oldest, route wins tie break.
       */
      
      /* Connected routes. Pick the last connected
       * route of the set of lowest metric connected routes.
       */
      if (rib->type == ZEBRA_ROUTE_CONNECT)
        {
          if (select->type != ZEBRA_ROUTE_CONNECT
              || rib->metric <= select->metric)
            select = rib;
          continue;
        }
      else if (select->type == ZEBRA_ROUTE_CONNECT)
        continue;
      
      /* higher distance loses */
      if (rib->distance > select->distance)
        continue;
      
      /* lower wins */
      if (rib->distance < select->distance)
        {
          select = rib;
          continue;
        }
      
      /* metric tie-breaks equal distance */
      if (rib->metric <= select->metric)
        select = rib;
    } /* for (rib = rn->info; rib; rib = next) */

  /* After the cycle is finished, the following pointers will be set:
   * select --- the winner RIB entry, if any was found, otherwise NULL
   * fib    --- the SELECTED RIB entry, if any, otherwise NULL
   * del    --- equal to fib, if fib is queued for deletion, NULL otherwise
   * rib    --- NULL
   */

  /* Same RIB entry is selected. Update FIB and finish. */
  if (select && select == fib)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: Updating existing route, select %p, fib %p",
                     __func__, buf, rn->p.prefixlen, select, fib);
      if (CHECK_FLAG (select->flags, ZEBRA_FLAG_CHANGED))
        {
          redistribute_delete (&rn->p, select);
          if (! RIB_SYSTEM_ROUTE (select))
            rib_uninstall_kernel (rn, select);

          /* Set real nexthop. */
          nexthop_active_update (rn, select, 1);
  
          if (! RIB_SYSTEM_ROUTE (select))
            rib_install_kernel (rn, select);
          redistribute_add (&rn->p, select);
        }
      else if (! RIB_SYSTEM_ROUTE (select))
        {
          /* Housekeeping code to deal with 
             race conditions in kernel with linux
             netlink reporting interface up before IPv4 or IPv6 protocol
             is ready to add routes.
             This makes sure the routes are IN the kernel.
           */

          for (nexthop = select->nexthop; nexthop; nexthop = nexthop->next)
            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            {
              installed = 1;
              break;
            }
          if (! installed) 
            rib_install_kernel (rn, select);
        }
      goto end;
    }

  /* At this point we either haven't found the best RIB entry or it is
   * different from what we currently intend to flag with SELECTED. In both
   * cases, if a RIB block is present in FIB, it should be withdrawn.
   */
  if (fib)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: Removing existing route, fib %p", __func__,
          buf, rn->p.prefixlen, fib);
      redistribute_delete (&rn->p, fib);
      if (! RIB_SYSTEM_ROUTE (fib))
	rib_uninstall_kernel (rn, fib);
      UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);

      /* Set real nexthop. */
      nexthop_active_update (rn, fib, 1);
    }

  /* Regardless of some RIB entry being SELECTED or not before, now we can
   * tell, that if a new winner exists, FIB is still not updated with this
   * data, but ready to be.
   */
  if (select)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: Adding route, select %p", __func__, buf,
          rn->p.prefixlen, select);
      /* Set real nexthop. */
      nexthop_active_update (rn, select, 1);

      if (! RIB_SYSTEM_ROUTE (select))
        rib_install_kernel (rn, select);
      SET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
      redistribute_add (&rn->p, select);
    }

  /* FIB route was removed, should be deleted */
  if (del)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: Deleting fib %p, rn %p", __func__, buf,
          rn->p.prefixlen, del, rn);
      rib_unlink (rn, del);
    }

end:
  if (IS_ZEBRA_DEBUG_RIB_Q)
    zlog_debug ("%s: %s/%d: rn %p dequeued", __func__, buf, rn->p.prefixlen, rn);
}

/* Take a list of route_node structs and return 1, if there was a record
 * picked from it and processed by rib_process(). Don't process more, 
 * than one RN record; operate only in the specified sub-queue.
 */
static unsigned int
process_subq (struct list * subq, u_char qindex)
{
  struct listnode *lnode  = listhead (subq);
  struct route_node *rnode;

  if (!lnode)
    return 0;

  rnode = listgetdata (lnode);
  rib_process (rnode);

  if (rnode->info) /* The first RIB record is holding the flags bitmask. */
    UNSET_FLAG (((struct rib *)rnode->info)->rn_status, RIB_ROUTE_QUEUED(qindex));
#if 0
  else
    {
      zlog_debug ("%s: called for route_node (%p, %d) with no ribs",
                  __func__, rnode, rnode->lock);
      zlog_backtrace(LOG_DEBUG);
    }
#endif
  route_unlock_node (rnode);
  list_delete_node (subq, lnode);
  return 1;
}

/* Dispatch the meta queue by picking, processing and unlocking the next RN from
 * a non-empty sub-queue with lowest priority. wq is equal to zebra->ribq and data
 * is pointed to the meta queue structure.
 */
static wq_item_status
meta_queue_process (struct work_queue *dummy, void *data)
{
  struct meta_queue * mq = data;
  unsigned i;

  for (i = 0; i < MQ_SIZE; i++)
    if (process_subq (mq->subq[i], i))
      {
	mq->size--;
	break;
      }
  return mq->size ? WQ_REQUEUE : WQ_SUCCESS;
}

/* Map from rib types to queue type (priority) in meta queue */
static const u_char meta_queue_map[ZEBRA_ROUTE_MAX] = {
  [ZEBRA_ROUTE_SYSTEM]  = 4,
  [ZEBRA_ROUTE_KERNEL]  = 0,
  [ZEBRA_ROUTE_CONNECT] = 0,
  [ZEBRA_ROUTE_STATIC]  = 1,
  [ZEBRA_ROUTE_RIP]     = 2,
  [ZEBRA_ROUTE_RIPNG]   = 2,
  [ZEBRA_ROUTE_OSPF]    = 2,
  [ZEBRA_ROUTE_OSPF6]   = 2,
  [ZEBRA_ROUTE_ISIS]    = 2,
  [ZEBRA_ROUTE_BGP]     = 3,
  [ZEBRA_ROUTE_HSLS]    = 4,
};

/* Look into the RN and queue it into one or more priority queues,
 * increasing the size for each data push done.
 */
static void
rib_meta_queue_add (struct meta_queue *mq, struct route_node *rn)
{
  struct rib *rib;
  char buf[INET6_ADDRSTRLEN];

  if (IS_ZEBRA_DEBUG_RIB_Q)
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);

  for (rib = rn->info; rib; rib = rib->next)
    {
      u_char qindex = meta_queue_map[rib->type];

      /* Invariant: at this point we always have rn->info set. */
      if (CHECK_FLAG (((struct rib *)rn->info)->rn_status, RIB_ROUTE_QUEUED(qindex)))
	{
	  if (IS_ZEBRA_DEBUG_RIB_Q)
	    zlog_debug ("%s: %s/%d: rn %p is already queued in sub-queue %u",
			__func__, buf, rn->p.prefixlen, rn, qindex);
	  continue;
	}

      SET_FLAG (((struct rib *)rn->info)->rn_status, RIB_ROUTE_QUEUED(qindex));
      listnode_add (mq->subq[qindex], rn);
      route_lock_node (rn);
      mq->size++;

      if (IS_ZEBRA_DEBUG_RIB_Q)
	zlog_debug ("%s: %s/%d: queued rn %p into sub-queue %u",
		    __func__, buf, rn->p.prefixlen, rn, qindex);
    }
}

/* Add route_node to work queue and schedule processing */
static void
rib_queue_add (struct zebra_t *zebra, struct route_node *rn)
{
  char buf[INET6_ADDRSTRLEN];
  assert (zebra && rn);
  
  if (IS_ZEBRA_DEBUG_RIB_Q)
    inet_ntop (AF_INET, &rn->p.u.prefix, buf, sizeof(buf));

  /* Pointless to queue a route_node with no RIB entries to add or remove */
  if (!rn->info)
    {
      zlog_debug ("%s: called for route_node (%p, %d) with no ribs",
                  __func__, rn, rn->lock);
      zlog_backtrace(LOG_DEBUG);
      return;
    }

  if (IS_ZEBRA_DEBUG_RIB_Q)
    zlog_info ("%s: %s/%d: work queue added", __func__, buf, rn->p.prefixlen);

  assert (zebra);

  if (zebra->ribq == NULL)
    {
      zlog_err ("%s: work_queue does not exist!", __func__);
      return;
    }

  /* The RIB queue should normally be either empty or holding the only work_queue_item
   * element. In the latter case this element would hold a pointer to the meta queue
   * structure, which must be used to actually queue the route nodes to process. So
   * create the MQ holder, if necessary, then push the work into it in any case.
   * This semantics was introduced after 0.99.9 release.
   */

  /* Should I invent work_queue_empty() and use it, or it's Ok to do as follows? */
  if (!zebra->ribq->items->count)
    work_queue_add (zebra->ribq, zebra->mq);

  rib_meta_queue_add (zebra->mq, rn);

  if (IS_ZEBRA_DEBUG_RIB_Q)
    zlog_debug ("%s: %s/%d: rn %p queued", __func__, buf, rn->p.prefixlen, rn);

  return;
}

/* Create new meta queue.
   A destructor function doesn't seem to be necessary here.
 */
static struct meta_queue *
meta_queue_new (void)
{
  struct meta_queue *new;
  unsigned i;

  new = XCALLOC (MTYPE_WORK_QUEUE, sizeof (struct meta_queue));
  assert(new);

  for (i = 0; i < MQ_SIZE; i++)
    {
      new->subq[i] = list_new ();
      assert(new->subq[i]);
    }

  return new;
}

/* initialise zebra rib work queue */
static void
rib_queue_init (struct zebra_t *zebra)
{
  assert (zebra);
  
  if (! (zebra->ribq = work_queue_new (zebra->master, 
                                       "route_node processing")))
    {
      zlog_err ("%s: could not initialise work queue!", __func__);
      return;
    }

  /* fill in the work queue spec */
  zebra->ribq->spec.workfunc = &meta_queue_process;
  zebra->ribq->spec.errorfunc = NULL;
  /* XXX: TODO: These should be runtime configurable via vty */
  zebra->ribq->spec.max_retries = 3;
  zebra->ribq->spec.hold = rib_process_hold_time;
  
  if (!(zebra->mq = meta_queue_new ()))
  {
    zlog_err ("%s: could not initialise meta queue!", __func__);
    return;
  }
  return;
}

/* RIB updates are processed via a queue of pointers to route_nodes.
 *
 * The queue length is bounded by the maximal size of the routing table,
 * as a route_node will not be requeued, if already queued.
 *
 * RIBs are submitted via rib_addnode or rib_delnode which set minimal
 * state, or static_install (when an existing RIB is updated) and then
 * submit route_node to queue for best-path selection later.  Order of
 * add/delete state changes are preserved for any given RIB.
 *
 * Deleted RIBs are reaped during best-path selection.
 *
 * rib_addnode
 * |-> rib_link or unset RIB_ENTRY_REMOVE        |->Update kernel with
 *       |-------->|                             |  best RIB, if required
 *                 |                             |
 * static_install->|->rib_addqueue...... -> rib_process
 *                 |                             |
 *       |-------->|                             |-> rib_unlink
 * |-> set RIB_ENTRY_REMOVE                           |
 * rib_delnode                                  (RIB freed)
 *
 *
 * Queueing state for a route_node is kept in the head RIB entry, this
 * state must be preserved as and when the head RIB entry of a
 * route_node is changed by rib_unlink / rib_link. A small complication,
 * but saves having to allocate a dedicated object for this.
 * 
 * Refcounting (aka "locking" throughout the GNU Zebra and Quagga code):
 *
 * - route_nodes: refcounted by:
 *   - RIBs attached to route_node:
 *     - managed by: rib_link/unlink
 *   - route_node processing queue
 *     - managed by: rib_addqueue, rib_process.
 *
 */
 
/* Add RIB to head of the route node. */
static void
rib_link (struct route_node *rn, struct rib *rib)
{
  struct rib *head;
  char buf[INET6_ADDRSTRLEN];
  
  assert (rib && rn);
  
  route_lock_node (rn); /* rn route table reference */

  if (IS_ZEBRA_DEBUG_RIB)
  {
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
    zlog_debug ("%s: %s/%d: rn %p, rib %p", __func__,
      buf, rn->p.prefixlen, rn, rib);
  }

  head = rn->info;
  if (head)
    {
      if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: %s/%d: new head, rn_status copied over", __func__,
          buf, rn->p.prefixlen);
      head->prev = rib;
      /* Transfer the rn status flags to the new head RIB */
      rib->rn_status = head->rn_status;
    }
  rib->next = head;
  rn->info = rib;
  rib_queue_add (&zebrad, rn);
}

static void
rib_addnode (struct route_node *rn, struct rib *rib)
{
  /* RIB node has been un-removed before route-node is processed. 
   * route_node must hence already be on the queue for processing.. 
   */
  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
    {
      if (IS_ZEBRA_DEBUG_RIB)
      {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
        zlog_debug ("%s: %s/%d: rn %p, un-removed rib %p",
                    __func__, buf, rn->p.prefixlen, rn, rib);
      }
      UNSET_FLAG (rib->status, RIB_ENTRY_REMOVED);
      return;
    }
  rib_link (rn, rib);
}

static void
rib_unlink (struct route_node *rn, struct rib *rib)
{
  struct nexthop *nexthop, *next;
  char buf[INET6_ADDRSTRLEN];

  assert (rn && rib);

  if (IS_ZEBRA_DEBUG_RIB)
  {
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
    zlog_debug ("%s: %s/%d: rn %p, rib %p",
                __func__, buf, rn->p.prefixlen, rn, rib);
  }

  if (rib->next)
    rib->next->prev = rib->prev;

  if (rib->prev)
    rib->prev->next = rib->next;
  else
    {
      rn->info = rib->next;
      
      if (rn->info)
        {
          if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: %s/%d: rn %p, rib %p, new head copy",
                        __func__, buf, rn->p.prefixlen, rn, rib);
          rib->next->rn_status = rib->rn_status;
        }
    }

  /* free RIB and nexthops */
  for (nexthop = rib->nexthop; nexthop; nexthop = next)
    {
      next = nexthop->next;
      nexthop_free (nexthop);
    }
  XFREE (MTYPE_RIB, rib);

  route_unlock_node (rn); /* rn route table reference */
}

static void
rib_delnode (struct route_node *rn, struct rib *rib)
{
  if (IS_ZEBRA_DEBUG_RIB)
  {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
    zlog_debug ("%s: %s/%d: rn %p, rib %p, removing", __func__,
      buf, rn->p.prefixlen, rn, rib);
  }
  SET_FLAG (rib->status, RIB_ENTRY_REMOVED);
  rib_queue_add (&zebrad, rn);
}

int
rib_add (int type, int flags, struct prefix *p, 
	      struct prefix *gate, struct prefix *src,
	      unsigned int ifindex, u_int32_t vrf_id,
	      u_int32_t metric, u_char distance)
{
  struct rib *rib;
  struct rib *same = NULL;
  struct route_table *table;
  struct route_node *rn;
  struct nexthop *nexthop;

  /* Lookup table.  */
  table = vrf_table (family2afi (p->family), SAFI_UNICAST, 0);
  if (! table)
    return 0;
  
  if (gate)
    assert (gate->family == p->family);

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask (p);

  /* Set default distance by route type. */
  if (distance == 0)
    {
      distance = route_info[type].distance;

      /* iBGP distance is 200. */
      if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
	distance = 200;
    }

  /* Lookup route node.*/
  rn = route_node_get (table, (struct prefix *) p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;
      
      if (rib->type != type)
	continue;
      if (rib->type != ZEBRA_ROUTE_CONNECT)
        {
          same = rib;
          break;
        }
      /* Duplicate connected route comes in. */
      else if ((nexthop = rib->nexthop) &&
	       nexthop->ifindex != IFINDEX_INTERNAL &&
	       nexthop->ifindex == ifindex &&
	       !CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	{
	  rib->refcnt++;
	  return 0 ;
	}
    }

  /* Allocate new rib structure. */
  rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
  rib->type = type;
  rib->distance = distance;
  rib->flags = flags;
  rib->metric = metric;
  rib->table = vrf_id;
  rib->nexthop_num = 0;
  rib->uptime = time (NULL);

  /* Nexthop settings. */
  rib_nexthop_add (rib, gate, src, ifindex);

  /* If this route is kernel route, set FIB flag to the route. */
  if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  if (IS_ZEBRA_DEBUG_RIB)
    zlog_debug ("%s: calling rib_addnode (%p, %p)", __func__, rn, rib);
  rib_addnode (rn, rib);
  
  /* Free implicit route.*/
  if (same)
  {
    if (IS_ZEBRA_DEBUG_RIB)
      zlog_debug ("%s: calling rib_delnode (%p, %p)", __func__, rn, rib);
    rib_delnode (rn, same);
  }
  
  route_unlock_node (rn);
  return 0;
}

/* This function dumps the contents of a given RIB entry into
 * standard debug log. Calling function name and IP prefix in
 * question are passed as 1st and 2nd arguments.
 */

void rib_dump (const char *func, const struct prefix *p, const struct rib *rib)
{
  char straddr1[INET6_ADDRSTRLEN], straddr2[INET6_ADDRSTRLEN];
  struct nexthop *nexthop;

  inet_ntop (AF_INET, &p->u.prefix, straddr1, sizeof(straddr1));
  zlog_debug ("%s: dumping RIB entry %p for %s/%d", func, rib, straddr1, p->prefixlen);
  zlog_debug
  (
    "%s: refcnt == %lu, uptime == %lu, type == %u, table == %d",
    func,
    rib->refcnt,
    rib->uptime,
    rib->type,
    rib->table
  );
  zlog_debug
  (
    "%s: metric == %u, distance == %u, flags == %u, status == %u",
    func,
    rib->metric,
    rib->distance,
    rib->flags,
    rib->status
  );
  zlog_debug
  (
    "%s: nexthop_num == %u, nexthop_active_num == %u, nexthop_fib_num == %u",
    func,
    rib->nexthop_num,
    rib->nexthop_active_num,
    rib->nexthop_fib_num
  );
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
  {
    prefix2str (nexthop->gate, straddr1, sizeof(straddr1));
    prefix2str (nexthop->rgate, straddr2, sizeof(straddr2));
    zlog_debug
    (
      "%s: NH %s (%s) with flags %s%s%s",
      func,
      straddr1,
      straddr2,
      (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE) ? "ACTIVE " : ""),
      (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? "FIB " : ""),
      (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE) ? "RECURSIVE" : "")
    );
  }
  zlog_debug ("%s: dump complete", func);
}

/* This is an exported helper to rtm_read() to dump the strange
 * RIB entry found by rib_lookup_ipv4_route()
 */

void rib_lookup_and_dump (struct prefix *p)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  char prefix_buf[INET6_ADDRSTRLEN];

  /* Lookup table.  */
  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (! table)
  {
    zlog_err ("%s: vrf_table() returned NULL", __func__);
    return;
  }

  inet_ntop (AF_INET, &p->u.prefix, prefix_buf, INET6_ADDRSTRLEN);
  /* Scan the RIB table for exactly matching RIB entry. */
  rn = route_node_lookup (table, (struct prefix *) p);

  /* No route for this prefix. */
  if (! rn)
  {
    zlog_debug ("%s: lookup failed for %s/%d", __func__, prefix_buf, p->prefixlen);
    return;
  }

  /* Unlock node. */
  route_unlock_node (rn);

  /* let's go */
  for (rib = rn->info; rib; rib = rib->next)
  {
    zlog_debug
    (
      "%s: rn %p, rib %p: %s, %s",
      __func__,
      rn,
      rib,
      (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED) ? "removed" : "NOT removed"),
      (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED) ? "selected" : "NOT selected")
    );
    rib_dump (__func__, p, rib);
  }
}

int
rib_add_multipath (struct prefix *p, struct rib *rib)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *same;
  struct nexthop *nexthop;
  
  /* Lookup table.  */
  table = vrf_table (family2afi (p->family), SAFI_UNICAST, 0);
  
  if (! table)
    return 0;
  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask (p);

  /* Set default distance by route type. */
  if (rib->distance == 0)
    {
      rib->distance = route_info[rib->type].distance;

      /* iBGP distance is 200. */
      if (rib->type == ZEBRA_ROUTE_BGP 
	  && CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP))
	rib->distance = 200;
    }

  /* Lookup route node.*/
  rn = route_node_get (table, (struct prefix *) p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (same = rn->info; same; same = same->next)
    {
      if (CHECK_FLAG (same->status, RIB_ENTRY_REMOVED))
        continue;
      
      if (same->type == rib->type && same->table == rib->table
	  && same->type != ZEBRA_ROUTE_CONNECT)
        break;
    }
  
  /* If this route is kernel route, set FIB flag to the route. */
  if (rib->type == ZEBRA_ROUTE_KERNEL || rib->type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  rib_addnode (rn, rib);
  if (IS_ZEBRA_DEBUG_RIB)
  {
    zlog_debug ("%s: called rib_addnode (%p, %p) on new RIB entry",
      __func__, rn, rib);
    rib_dump (__func__, p, rib);
  }

  /* Free implicit route.*/
  if (same)
  {
    if (IS_ZEBRA_DEBUG_RIB)
    {
      zlog_debug ("%s: calling rib_delnode (%p, %p) on existing RIB entry",
        __func__, rn, same);
      rib_dump (__func__, p, same);
    }
    rib_delnode (rn, same);
  }
  
  route_unlock_node (rn);
  return 0;
}

/* XXX factor with rib_delete_ipv6 */
int
rib_delete (int type, int flags, struct prefix *p, struct prefix *gate,
            unsigned int ifindex, u_int32_t vrf_id)
{
  struct route_table *table;
  struct route_node *rn;
  struct rib *rib;
  struct rib *fib = NULL;
  struct rib *same = NULL;
  struct nexthop *nexthop;
  char buf1[INET6_ADDRSTRLEN];
  char buf2[INET6_ADDRSTRLEN];

  /* Lookup table.  */
  table = vrf_table (family2afi (p->family), SAFI_UNICAST, 0);
  if (! table)
    return 0;
  
  if (gate)
    assert (gate->family == p->family);
  
  if (IS_ZEBRA_DEBUG_KERNEL)
    {
      if (gate)
        prefix2str (gate, buf2, sizeof(buf2));
      prefix2str (p, buf1, sizeof(buf1));
    }
  
  /* Apply mask. */
  apply_mask (p);

  if (IS_ZEBRA_DEBUG_KERNEL && gate) 
    zlog_debug ("%s: route delete %s via %s ifindex %d",
                __func__, buf1, buf2, ifindex);

  /* Lookup route node. */
  rn = route_node_lookup (table, (struct prefix *) p);
  if (! rn)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
	{
	  if (gate)
	    zlog_debug ("route %s via %s ifindex %d doesn't exist in rib",
		        buf1, buf2, ifindex);
	  else
	    zlog_debug ("route %s ifindex %d doesn't exist in rib",
		        buf1, ifindex);
	}
      return ZEBRA_ERR_RTNOEXIST;
    }

  /* Lookup same type route. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;

      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
	fib = rib;

      if (rib->type != type)
	continue;
      if (rib->type == ZEBRA_ROUTE_CONNECT && (nexthop = rib->nexthop) &&
	  nexthop->ifindex != IFINDEX_INTERNAL && nexthop->ifindex == ifindex)
	{
	  if (rib->refcnt)
	    {
	      rib->refcnt--;
	      route_unlock_node (rn);
	      route_unlock_node (rn);
	      return 0;
	    }
	  same = rib;
	  break;
	}
      /* Make sure that the route found has the same gateway. */
      else if (gate == NULL ||
	       ((nexthop = rib->nexthop) &&
	        (prefix_same (nexthop->gate, gate) || 
	         prefix_same (nexthop->rgate, gate))))
        {
	  same = rib;
	  break;
	}
    }

  /* If same type of route can't be found and this message is from
     kernel. */
  if (! same)
    {
      if (fib && type == ZEBRA_ROUTE_KERNEL)
	{
	  /* Unset flags. */
	  for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
	    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

	  UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
	}
      else
	{
	  if (IS_ZEBRA_DEBUG_KERNEL)
	    {
	      if (gate)
		zlog_debug ("route %s via %s ifindex %d type %d doesn't exist in rib",
			   buf1, buf2, ifindex, type);
	      else
		zlog_debug ("route %s ifindex %d type %d doesn't exist in rib",
			   buf1, ifindex, type);
	    }
	  route_unlock_node (rn);
	  return ZEBRA_ERR_RTNOEXIST;
	}
    }
  
  if (same)
    rib_delnode (rn, same);
  
  route_unlock_node (rn);
  return 0;
}

/* Compare the target of each static route. Deliberately does not
 * compare distances.
 *
 * If exact is not set, then only those fields in the 'specification'
 * that are set (non-0/NULL) are considered.
 */
static int
static_same_target (struct static_route *spec, struct static_route *candidate,
                    int exact)
{
  if ((exact || spec->flags) &&
      (spec->flags != candidate->flags))
    return 0;
  
  if ((exact || spec->gate) &&
      (spec->gate || candidate->gate))
    {
      if (!(spec->gate && candidate->gate))
        return 0;
      
      if (!prefix_same (spec->gate, candidate->gate))
        return 0;
    }
  
  if ((exact || spec->ifname) &&
      (spec->ifname || candidate->ifname))
    {
      if (!(spec->ifname && candidate->ifname))
        return 0;
      
      if (strncmp (spec->ifname, candidate->ifname, INTERFACE_NAMSIZ) != 0)
        return 0;
    }
  
  /* Must be same */
  return 1;
}

static int
static_nexthop_same (struct nexthop *nexthop, struct static_route *si)
{
  /* If set on either, then blackhole flag must be set on both */
  if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_BLACKHOLE)
      || CHECK_FLAG (si->flags, ZEBRA_FLAG_BLACKHOLE))
    {
      return (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_BLACKHOLE)
              && CHECK_FLAG (si->flags, ZEBRA_FLAG_BLACKHOLE));
    }
  
  if (nexthop->gate || si->gate)
    {
      if (!nexthop->gate || !si->gate)
        return 0;
      
      if (!prefix_same (nexthop->gate, si->gate))
        return 0;
    }
  
  if (nexthop->ifindex != IFINDEX_INTERNAL ||
      si->ifname)
    {
      if (nexthop->ifindex == IFINDEX_INTERNAL ||
          !si->ifname)
        return 0;
      
      if (strcmp (ifindex2ifname (nexthop->ifindex), si->ifname) != 0)
        return 0;
    }
  /* everything must be the same */
  return 1;
}

/* Setup RIB nexthops for the static_route */
static void
static_add_nexthops (struct rib *rib, struct static_route *si)
{
  if (CHECK_FLAG (si->flags, ZEBRA_FLAG_BLACKHOLE))
    rib_nexthop_blackhole_add (rib);
  else
    rib_nexthop_add (rib, si->gate, NULL, ifname2ifindex (si->ifname));
  /* preserve ZEBRA_FLAG_REJECT, if set */
  rib->flags = si->flags;
}

/* Initialise a static route structure from the given information */
static void
static_init (struct static_route *si, struct prefix *gate, 
            const char *ifname, u_char flags, u_char distance)
{
  si->flags = flags;
  si->distance = distance;
  si->gate = NULL;
  si->ifname = NULL;
  
  /* blackhole route can't have a gate */
  if (CHECK_FLAG (si->flags, ZEBRA_FLAG_BLACKHOLE))
    return;
  
  if (ifname && strcasecmp (ifname, "Null0") == 0)
    {
      SET_FLAG (si->flags, ZEBRA_FLAG_BLACKHOLE);
      return;
    }
  
  if (ifname)
    si->ifname = ifname;
  if (gate)
    si->gate = gate;
}

/* Install static route into rib. */
static void
static_install (struct prefix *p, struct static_route *si)
{
  struct rib *rib;
  struct route_node *rn;
  struct route_table *table;

  /* Lookup table.  */
  table = vrf_table (family2afi (p->family), SAFI_UNICAST, 0);
  if (! table)
    return;

  /* Lookup existing route */
  rn = route_node_get (table, p);
  for (rib = rn->info; rib; rib = rib->next)
    {
       if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
         continue;
        
       if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
         break;
    }

  if (rib)
    {
      /* Same distance static route is there.  Update it with new
         nexthop. */
      route_unlock_node (rn);
      static_add_nexthops (rib, si);
      rib_queue_add (&zebrad, rn);
    }
  else
    {
      /* This is new static route. */
      rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
      
      rib->type = ZEBRA_ROUTE_STATIC;
      rib->distance = si->distance;
      rib->metric = 0;
      rib->nexthop_num = 0;
      
      static_add_nexthops (rib, si);
      
      /* Link this rib to the tree. */
      rib_addnode (rn, rib);
    }
}

/* Uninstall static route from RIB. */
static void
static_uninstall (struct prefix *p, struct static_route *si)
{
  struct route_node *rn;
  struct rib *rib;
  struct nexthop *nexthop;
  struct route_table *table;

  /* Lookup table.  */
  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (! table)
    return;
  
  /* Lookup existing route with type and distance. */
  rn = route_node_lookup (table, p);
  if (! rn)
    return;

  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        continue;

      if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
        break;
    }

  if (! rib)
    {
      route_unlock_node (rn);
      return;
    }

  /* Lookup nexthop. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    if (static_nexthop_same (nexthop, si))
      break;

  /* Can't find nexthop. */
  if (! nexthop)
    {
      route_unlock_node (rn);
      return;
    }
  
  /* Check nexthop. */
  if (rib->nexthop_num == 1)
    rib_delnode (rn, rib);
  else
    {
      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
        rib_uninstall (rn, rib);
      NEXTHOP_DEL (&rib->nexthop, nexthop, rib->nexthop_num);
      nexthop_free (nexthop);
      rib_queue_add (&zebrad, rn);
    }
  /* Unlock node. */
  route_unlock_node (rn);
}

/* Add static route into static route configuration. */
int
static_add (struct prefix *p, struct prefix *gate, 
            const char *ifname, u_char flags, u_char distance,
            u_int32_t vrf_id)
{
  struct route_node *rn;
  struct static_route *si;
  struct static_route *pp;
  struct static_route *cp;
  struct static_route *update = NULL;
  struct static_route new_si;
  struct route_table *stable;
  
  /* Lookup table.  */
  stable = vrf_static_table (family2afi (p->family), SAFI_UNICAST, vrf_id);

  if (! stable)
    return -1;
  
  if (gate)
    assert (gate->family == p->family);
  
  /* Lookup static route prefix. */
  rn = route_node_get (stable, p);
  
  static_init (&new_si, gate, ifname, flags, distance);
  
  /* Do nothing if there is a same static route.  */
  for (si = rn->info; si; si = si->next)
    {
      if (static_same_target (&new_si, si, 1))
	{
	  if (distance == si->distance)
	    {
	      route_unlock_node (rn);
	      return 0;
	    }
	  else
	    update = si;
	}
    }

  /* Distance changed.  */
  if (update)
    static_delete (p, gate, ifname, update->distance, vrf_id);

  /* Make new static route structure. */
  si = XCALLOC (MTYPE_STATIC_ROUTE, sizeof (struct static_route));

  si->distance = distance;
  si->flags = flags;

  if (gate)
    prefix_copy ((si->gate = prefix_new ()), gate);
  if (ifname)
    si->ifname = XSTRDUP (MTYPE_STATIC_ROUTE_IFNAME, ifname);

  /* Add new static route information to the tree with sort by
     distance value */
  for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
      if (si->distance < cp->distance)
	break;
      if (si->distance > cp->distance)
	continue;
      /* We used to sort IPv4 by gateway address here, that's harder to do
       * with AF independent gateway addresses though.
       *
       * This memcmp is now purely to keep things deterministic.. */
      if (si->gate && cp->gate)
        {
          int cmp = memcmp (si->gate, cp->gate, sizeof (struct prefix));
          
          if (cmp < 0)
            break;
          if (cmp > 0)
            continue;
        }
    }

  /* Make linked list. */
  if (pp)
    pp->next = si;
  else
    rn->info = si;
  if (cp)
    cp->prev = si;
  si->prev = pp;
  si->next = cp;

  /* Install into rib. */
  static_install (p, si);

  return 1;
}

/* Delete static route from static route configuration. */
int
static_delete (struct prefix *p, struct prefix *gate, const char *ifname,
		    u_char distance, u_int32_t vrf_id)
{
  struct route_node *rn;
  struct static_route *si;
  struct static_route new_si;
  struct route_table *stable;

  /* Lookup table.  */
  stable = vrf_static_table (family2afi (p->family), SAFI_UNICAST, vrf_id);
  if (! stable)
    return -1;

  /* Lookup static route prefix. */
  rn = route_node_lookup (stable, p);
  if (! rn)
    return 0;

  if (gate)
    assert (gate->family == p->family);
  
  static_init (&new_si, gate, ifname, 0, distance);
  
  /* Find same static route is the tree */
  for (si = rn->info; si; si = si->next)
    if (static_same_target (&new_si,si, 0))
      break;

  /* Can't find static route. */
  if (! si)
    {
      route_unlock_node (rn);
      return 0;
    }

  /* Install into rib. */
  static_uninstall (p, si);

  /* Unlink static route from linked list. */
  if (si->prev)
    si->prev->next = si->next;
  else
    rn->info = si->next;
  if (si->next)
    si->next->prev = si->prev;
  route_unlock_node (rn);
  
  /* Free static route configuration. */
  if (si->ifname)
    XFREE (MTYPE_STATIC_ROUTE_IFNAME, (si->ifname));
  if (si->gate)
    prefix_free (si->gate);
  XFREE (MTYPE_STATIC_ROUTE, si);

  route_unlock_node (rn);

  return 1;
}


#ifdef HAVE_IPV6
static int
rib_bogus_ipv6 (int type, struct prefix_ipv6 *p,
		struct in6_addr *gate, unsigned int ifindex, int table)
{
  if (type == ZEBRA_ROUTE_CONNECT && IN6_IS_ADDR_UNSPECIFIED (&p->prefix)) {
#if defined (MUSICA) || defined (LINUX)
    /* IN6_IS_ADDR_V4COMPAT(&p->prefix) */
    if (p->prefixlen == 96)
      return 0;
#endif /* MUSICA */
    return 1;
  }
  if (type == ZEBRA_ROUTE_KERNEL && IN6_IS_ADDR_UNSPECIFIED (&p->prefix)
      && p->prefixlen == 96 && gate && IN6_IS_ADDR_UNSPECIFIED (gate))
    {
      kernel_delete_ipv6_old (p, gate, ifindex, 0, table);
      return 1;
    }
  return 0;
}
#endif /* HAVE_IPV6 */

/* RIB update function. */
void
rib_update (void)
{
  struct route_node *rn;
  struct route_table *table;
  
  table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      if (rn->info)
        rib_queue_add (&zebrad, rn);

  table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      if (rn->info)
        rib_queue_add (&zebrad, rn);
}

/* Interface goes up. */
static void
rib_if_up (struct interface *ifp)
{
  rib_update ();
}

/* Interface goes down. */
static void
rib_if_down (struct interface *ifp)
{
  rib_update ();
}

/* Remove all routes which comes from non main table.  */
static void
rib_weed_table (struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      for (rib = rn->info; rib; rib = next)
	{
	  next = rib->next;

	  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	    continue;

	  if (rib->table != zebrad.rtm_table_default &&
	      rib->table != RT_TABLE_MAIN)
            rib_delnode (rn, rib);
	}
}

/* Delete all routes from non main table. */
void
rib_weed_tables (void)
{
  rib_weed_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
  rib_weed_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}

/* Delete self installed routes after zebra is relaunched.  */
static void
rib_sweep_table (struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;
  int ret = 0;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      for (rib = rn->info; rib; rib = next)
	{
	  next = rib->next;

	  if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
	    continue;

	  if (rib->type == ZEBRA_ROUTE_KERNEL && 
	      CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELFROUTE))
	    {
	      ret = rib_uninstall_kernel (rn, rib);
	      if (! ret)
                rib_delnode (rn, rib);
	    }
	}
}

/* Sweep all RIB tables.  */
void
rib_sweep_route (void)
{
  rib_sweep_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
  rib_sweep_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}

/* Close RIB and clean up kernel routes. */
static void
rib_close_table (struct route_table *table)
{
  struct route_node *rn;
  struct rib *rib;

  if (table)
    for (rn = route_top (table); rn; rn = route_next (rn))
      for (rib = rn->info; rib; rib = rib->next)
        {
          if (! RIB_SYSTEM_ROUTE (rib)
	      && CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            rib_uninstall_kernel (rn, rib);
        }
}

/* Close all RIB tables.  */
void
rib_close (void)
{
  rib_close_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
  rib_close_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}

/* Routing information base initialize. */
void
rib_init (void)
{
  rib_queue_init (&zebrad);
  /* VRF initialization.  */
  vrf_init ();
}
