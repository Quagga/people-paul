/*
 * Memory type definitions. This file is parsed by memtypes.awk to extract
 * MTYPE_ and memory_list_.. information in order to autogenerate 
 * memtypes.h.
 *
 * The script is sensitive to the format (though not whitespace), see
 * the top of memtypes.awk for more details.
 *
 * $Id$
 */

#include "zebra.h"
#include "memory.h"

struct memory_list memory_list_lib[] =
{
  { MTYPE_TMP,			"Temporary memory",	MTYPE_NOCACHE,	},
  { MTYPE_STRVEC,		"String vector",	MTYPE_NOCACHE,	},
  { MTYPE_VECTOR,		"Vector",		MTYPE_CACHE,	},
  { MTYPE_VECTOR_INDEX,		"Vector index",		MTYPE_NOCACHE	},
  { MTYPE_LINK_LIST,		"Link List",		MTYPE_CACHE	},
  { MTYPE_LINK_NODE,		"Link Node",		MTYPE_CACHE	},
  { MTYPE_THREAD,		"Thread",		MTYPE_CACHE	},
  { MTYPE_THREAD_MASTER,	"Thread master",	MTYPE_CACHE	},
  { MTYPE_THREAD_STATS,		"Thread stats",		MTYPE_NOCACHE	},
  { MTYPE_THREAD_FUNCNAME,	"Thread function name", MTYPE_NOCACHE	},
  { MTYPE_VTY,			"VTY",			MTYPE_NOCACHE	},
  { MTYPE_VTY_OUT_BUF,		"VTY output buffer",	MTYPE_NOCACHE	},
  { MTYPE_VTY_HIST,		"VTY history",		MTYPE_CACHE	},
  { MTYPE_IF,			"Interface",		MTYPE_CACHE	},
  { MTYPE_CONNECTED,		"Connected", 		MTYPE_CACHE	},
  { MTYPE_CONNECTED_LABEL,	"Connected label",	MTYPE_NOCACHE	},
  { MTYPE_BUFFER,		"Buffer",		MTYPE_CACHE	},
  { MTYPE_BUFFER_DATA,		"Buffer data",		MTYPE_CACHE	},
  { MTYPE_STREAM,		"Stream",		MTYPE_CACHE	},
  { MTYPE_STREAM_DATA,		"Stream data",		MTYPE_NOCACHE	},
  { MTYPE_STREAM_FIFO,		"Stream FIFO",		MTYPE_CACHE	},
  { MTYPE_PREFIX,		"Prefix",		MTYPE_CACHE	},
  { MTYPE_PREFIX_IPV4,		"Prefix IPv4",		MTYPE_NOCACHE	},
  { MTYPE_PREFIX_IPV6,		"Prefix IPv6",		MTYPE_NOCACHE	},
  { MTYPE_HASH,			"Hash",			MTYPE_CACHE	},
  { MTYPE_HASH_BACKET,		"Hash Bucket",		MTYPE_CACHE	},
  { MTYPE_HASH_INDEX,		"Hash Index",		MTYPE_CACHE	},
  { MTYPE_ROUTE_TABLE,		"Route table",		MTYPE_CACHE	},
  { MTYPE_ROUTE_NODE,		"Route node",		MTYPE_CACHE	},
  { MTYPE_DISTRIBUTE,		"Distribute list",	MTYPE_NOCACHE	},
  { MTYPE_DISTRIBUTE_IFNAME,	"Dist-list ifname",	MTYPE_NOCACHE	},
  { MTYPE_ACCESS_LIST,		"Access List",		MTYPE_NOCACHE	},
  { MTYPE_ACCESS_LIST_STR,	"Access List Str",	MTYPE_NOCACHE	},
  { MTYPE_ACCESS_FILTER,	"Access Filter",	MTYPE_NOCACHE	},
  { MTYPE_PREFIX_LIST,		"Prefix List",		MTYPE_NOCACHE	},
  { MTYPE_PREFIX_LIST_ENTRY,	"Prefix List Entry",	MTYPE_NOCACHE	},
  { MTYPE_PREFIX_LIST_STR,	"Prefix List Str",	MTYPE_NOCACHE	},
  { MTYPE_ROUTE_MAP,		"Route map",		MTYPE_NOCACHE	},
  { MTYPE_ROUTE_MAP_NAME,	"Route map name",	MTYPE_NOCACHE	},
  { MTYPE_ROUTE_MAP_INDEX,	"Route map index",	MTYPE_NOCACHE	},
  { MTYPE_ROUTE_MAP_RULE,	"Route map rule",	MTYPE_NOCACHE	},
  { MTYPE_ROUTE_MAP_RULE_STR,	"Route map rule str",	MTYPE_NOCACHE	},
  { MTYPE_ROUTE_MAP_COMPILED,	"Route map compiled",	MTYPE_NOCACHE	},
  { MTYPE_DESC,			"Command desc",		MTYPE_NOCACHE	},
  { MTYPE_KEY,			"Key",			MTYPE_NOCACHE	},
  { MTYPE_KEYCHAIN,		"Key chain",		MTYPE_NOCACHE	},
  { MTYPE_IF_RMAP,		"Interface route map",	MTYPE_NOCACHE	},
  { MTYPE_IF_RMAP_NAME,		"I.f. route map name",	MTYPE_CACHE	},
  { MTYPE_SOCKUNION,		"Socket union",		MTYPE_CACHE	},
  { MTYPE_PRIVS,		"Privilege information", MTYPE_NOCACHE	},
  { MTYPE_ZLOG,			"Logging",		MTYPE_NOCACHE	},
  { MTYPE_ZCLIENT,		"Zclient",		MTYPE_NOCACHE	},
  { MTYPE_WORK_QUEUE,		"Work queue",		MTYPE_NOCACHE	},
  { MTYPE_WORK_QUEUE_ITEM,	"Work queue item",	MTYPE_CACHE	},
  { MTYPE_WORK_QUEUE_NAME,	"Work queue name string", MTYPE_NOCACHE	},
  { MTYPE_PQUEUE,		"Priority queue",	MTYPE_CACHE	},
  { MTYPE_PQUEUE_DATA,		"Priority queue data",	MTYPE_CACHE	},
  { MTYPE_HOST,			"Host config",		MTYPE_NOCACHE	},
  { -1, NULL },
};

struct memory_list memory_list_zebra[] = 
{
  { MTYPE_RTADV_PREFIX,	"Router Advertisement Prefix",	MTYPE_NOCACHE	},
  { MTYPE_VRF,		"VRF",				MTYPE_NOCACHE	},
  { MTYPE_VRF_NAME,	"VRF name",			MTYPE_NOCACHE	},
  { MTYPE_NEXTHOP,	"Nexthop",			MTYPE_CACHE	},
  { MTYPE_RIB,		"RIB",				MTYPE_CACHE	},
  { MTYPE_RIB_QUEUE,	"RIB process work queue",	MTYPE_CACHE	},
  { MTYPE_STATIC_IPV4,	"Static IPv4 route",		MTYPE_NOCACHE	},
  { MTYPE_STATIC_IPV6,	"Static IPv6 route",		MTYPE_NOCACHE	},
  { -1, NULL },
};

struct memory_list memory_list_bgp[] =
{
  { MTYPE_BGP,			"BGP instance",		MTYPE_NOCACHE	},
  { MTYPE_BGP_PEER,		"BGP peer",		MTYPE_CACHE	},
  { MTYPE_BGP_PEER_HOST,	"BGP peer hostname",	MTYPE_NOCACHE	},
  { MTYPE_PEER_GROUP,		"Peer group",		MTYPE_CACHE	},
  { MTYPE_PEER_DESC,		"Peer description",	MTYPE_NOCACHE	},
  { MTYPE_ATTR,			"BGP attribute",	MTYPE_CACHE	},
  { MTYPE_ATTR_EXTRA,		"BGP extra attributes",	MTYPE_CACHE	},
  { MTYPE_AS_PATH,		"BGP aspath",		MTYPE_CACHE	},
  { MTYPE_AS_SEG,		"BGP aspath seg",	MTYPE_CACHE	},
  { MTYPE_AS_SEG_DATA,	"BGP aspath segment data",	MTYPE_NOCACHE	},
  { MTYPE_AS_STR,		"BGP aspath str",	MTYPE_NOCACHE	},
  { 0, NULL },
  { MTYPE_BGP_TABLE,		"BGP table",		MTYPE_CACHE	},
  { MTYPE_BGP_NODE,		"BGP node",		MTYPE_CACHE	},
  { MTYPE_BGP_ROUTE,		"BGP route",		MTYPE_CACHE	},
  { MTYPE_BGP_ROUTE_EXTRA,	"BGP ancillary route info", MTYPE_CACHE	},
  { MTYPE_BGP_STATIC,		"BGP static",		MTYPE_NOCACHE	},
  { MTYPE_BGP_ADVERTISE_ATTR,	"BGP adv attr",		MTYPE_CACHE	},
  { MTYPE_BGP_ADVERTISE,	"BGP adv",		MTYPE_CACHE	},
  { MTYPE_BGP_SYNCHRONISE,	"BGP synchronise",	MTYPE_NOCACHE	},
  { MTYPE_BGP_ADJ_IN,		"BGP adj in",		MTYPE_CACHE	},
  { MTYPE_BGP_ADJ_OUT,		"BGP adj out",		MTYPE_CACHE	},
  { 0, NULL },
  { MTYPE_AS_LIST,		"BGP AS list",		MTYPE_NOCACHE	},
  { MTYPE_AS_FILTER,		"BGP AS filter",	MTYPE_NOCACHE	},
  { MTYPE_AS_FILTER_STR,	"BGP AS filter str",	MTYPE_NOCACHE	},
  { 0, NULL },
  { MTYPE_COMMUNITY,		"community",		MTYPE_CACHE	},
  { MTYPE_COMMUNITY_VAL,	"community val",	MTYPE_NOCACHE	},
  { MTYPE_COMMUNITY_STR,	"community str",	MTYPE_NOCACHE	},
  { 0, NULL },
  { MTYPE_ECOMMUNITY,		"extcommunity",		MTYPE_CACHE	},
  { MTYPE_ECOMMUNITY_VAL,	"extcommunity val",	MTYPE_NOCACHE	},
  { MTYPE_ECOMMUNITY_STR,	"extcommunity str",	MTYPE_NOCACHE	},
  { 0, NULL },
  { MTYPE_COMMUNITY_LIST,	"community-list",	MTYPE_NOCACHE	},
  { MTYPE_COMMUNITY_LIST_NAME,	"community-list name",	MTYPE_NOCACHE	},
  { MTYPE_COMMUNITY_LIST_ENTRY,	"community-list entry",	MTYPE_NOCACHE	},
  { MTYPE_COMMUNITY_LIST_CONFIG,  "community-list config",  MTYPE_NOCACHE },
  { MTYPE_COMMUNITY_LIST_HANDLER, "community-list handler", MTYPE_NOCACHE },
  { 0, NULL },
  { MTYPE_CLUSTER,		"Cluster list",		MTYPE_NOCACHE	},
  { MTYPE_CLUSTER_VAL,		"Cluster list val",	MTYPE_NOCACHE	},
  { 0, NULL },
  { MTYPE_BGP_PROCESS_QUEUE,	"BGP Process queue",	MTYPE_CACHE	},
  { MTYPE_BGP_CLEAR_NODE_QUEUE, "BGP node clear queue",	MTYPE_NOCACHE	},
  { 0, NULL },
  { MTYPE_TRANSIT,		"BGP transit attr",	MTYPE_NOCACHE	},
  { MTYPE_TRANSIT_VAL,		"BGP transit val",	MTYPE_NOCACHE	},
  { 0, NULL },
  { MTYPE_BGP_DISTANCE,		"BGP distance",		MTYPE_NOCACHE	},
  { MTYPE_BGP_NEXTHOP_CACHE,	"BGP nexthop",		MTYPE_CACHE	},
  { MTYPE_BGP_CONFED_LIST,	"BGP confed list",	MTYPE_NOCACHE	},
  { MTYPE_PEER_UPDATE_SOURCE,	"BGP peer update interface", MTYPE_NOCACHE },
  { MTYPE_BGP_DAMP_INFO,	"Dampening info",	MTYPE_NOCACHE	},
  { MTYPE_BGP_DAMP_ARRAY,	"BGP Dampening array",	MTYPE_NOCACHE	},
  { MTYPE_BGP_REGEXP,		"BGP regexp",		MTYPE_NOCACHE	},
  { MTYPE_BGP_AGGREGATE,	"BGP aggregate",	MTYPE_NOCACHE	},
  { -1, NULL }
};

struct memory_list memory_list_rip[] =
{
  { MTYPE_RIP,                "RIP structure",		MTYPE_NOCACHE	},
  { MTYPE_RIP_INFO,           "RIP route info",		MTYPE_NOCACHE	},
  { MTYPE_RIP_INTERFACE,      "RIP interface",		MTYPE_NOCACHE	},
  { MTYPE_RIP_PEER,           "RIP peer",		MTYPE_NOCACHE	},
  { MTYPE_RIP_OFFSET_LIST,    "RIP offset list",	MTYPE_NOCACHE	},
  { MTYPE_RIP_DISTANCE,       "RIP distance",		MTYPE_NOCACHE	},
  { -1, NULL }
};

struct memory_list memory_list_ripng[] =
{
  { MTYPE_RIPNG,              "RIPng structure",	MTYPE_NOCACHE	},
  { MTYPE_RIPNG_ROUTE,        "RIPng route info",	MTYPE_NOCACHE	},
  { MTYPE_RIPNG_AGGREGATE,    "RIPng aggregate",	MTYPE_NOCACHE	},
  { MTYPE_RIPNG_PEER,         "RIPng peer",		MTYPE_NOCACHE	},
  { MTYPE_RIPNG_OFFSET_LIST,  "RIPng offset lst",	MTYPE_NOCACHE	},
  { MTYPE_RIPNG_RTE_DATA,     "RIPng rte data",		MTYPE_NOCACHE	},
  { -1, NULL }
};

struct memory_list memory_list_ospf[] =
{
  { MTYPE_OSPF_TOP,           "OSPF top",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_AREA,          "OSPF area",		MTYPE_CACHE	},
  { MTYPE_OSPF_AREA_RANGE,    "OSPF area range",	MTYPE_NOCACHE	},
  { MTYPE_OSPF_NETWORK,       "OSPF network",		MTYPE_CACHE	},
  { MTYPE_OSPF_NEIGHBOR_STATIC,"OSPF static nbr",	MTYPE_NOCACHE	},
  { MTYPE_OSPF_IF,            "OSPF interface",		MTYPE_CACHE	},
  { MTYPE_OSPF_NEIGHBOR,      "OSPF neighbor",		MTYPE_CACHE	},
  { MTYPE_OSPF_ROUTE,         "OSPF route",		MTYPE_CACHE	},
  { MTYPE_OSPF_TMP,           "OSPF tmp mem",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_LSA,           "OSPF LSA",		MTYPE_CACHE	},
  { MTYPE_OSPF_LSA_DATA,      "OSPF LSA data",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_LSDB,          "OSPF LSDB",		MTYPE_CACHE	},
  { MTYPE_OSPF_PACKET,        "OSPF packet",		MTYPE_CACHE	},
  { MTYPE_OSPF_FIFO,          "OSPF FIFO queue",	MTYPE_NOCACHE	},
  { MTYPE_OSPF_VERTEX,        "OSPF vertex",		MTYPE_CACHE	},
  { MTYPE_OSPF_VERTEX_PARENT, "OSPF vertex parent",	MTYPE_CACHE	},
  { MTYPE_OSPF_NEXTHOP,       "OSPF nexthop",		MTYPE_CACHE	},
  { MTYPE_OSPF_PATH,	      "OSPF path",		MTYPE_CACHE	},
  { MTYPE_OSPF_VL_DATA,       "OSPF VL data",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_CRYPT_KEY,     "OSPF crypt key",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_EXTERNAL_INFO, "OSPF ext. info",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_DISTANCE,      "OSPF distance",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_IF_INFO,       "OSPF if info",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_IF_PARAMS,     "OSPF if params",		MTYPE_NOCACHE	},
  { MTYPE_OSPF_MESSAGE,		"OSPF message",		MTYPE_NOCACHE	},
  { -1, NULL },
};

struct memory_list memory_list_ospf6[] =
{
  { MTYPE_OSPF6_TOP,          "OSPF6 top",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_AREA,         "OSPF6 area",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_IF,           "OSPF6 interface",	MTYPE_NOCACHE	},
  { MTYPE_OSPF6_NEIGHBOR,     "OSPF6 neighbor",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_ROUTE,        "OSPF6 route",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_PREFIX,       "OSPF6 prefix",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_MESSAGE,      "OSPF6 message",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_LSA,          "OSPF6 LSA",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_LSA_SUMMARY,  "OSPF6 LSA summary",	MTYPE_NOCACHE	},
  { MTYPE_OSPF6_LSDB,         "OSPF6 LSA database",	MTYPE_NOCACHE	},
  { MTYPE_OSPF6_VERTEX,       "OSPF6 vertex",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_SPFTREE,      "OSPF6 SPF tree",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_NEXTHOP,      "OSPF6 nexthop",		MTYPE_NOCACHE	},
  { MTYPE_OSPF6_EXTERNAL_INFO,"OSPF6 ext. info",	MTYPE_NOCACHE	},
  { MTYPE_OSPF6_OTHER,        "OSPF6 other",		MTYPE_NOCACHE	},
  { -1, NULL },
};

struct memory_list memory_list_isis[] =
{
  { MTYPE_ISIS,               "ISIS",			MTYPE_NOCACHE	},
  { MTYPE_ISIS_TMP,           "ISIS TMP",		MTYPE_NOCACHE	},
  { MTYPE_ISIS_CIRCUIT,       "ISIS circuit",		MTYPE_NOCACHE	},
  { MTYPE_ISIS_LSP,           "ISIS LSP",		MTYPE_NOCACHE	},
  { MTYPE_ISIS_ADJACENCY,     "ISIS adjacency",		MTYPE_NOCACHE	},
  { MTYPE_ISIS_AREA,          "ISIS area",		MTYPE_NOCACHE	},
  { MTYPE_ISIS_AREA_ADDR,     "ISIS area address",	MTYPE_NOCACHE	},
  { MTYPE_ISIS_TLV,           "ISIS TLV",		MTYPE_NOCACHE	},
  { MTYPE_ISIS_DYNHN,         "ISIS dyn hostname",	MTYPE_NOCACHE	},
  { MTYPE_ISIS_SPFTREE,       "ISIS SPFtree",		MTYPE_NOCACHE	},
  { MTYPE_ISIS_VERTEX,        "ISIS vertex",		MTYPE_CACHE	},
  { MTYPE_ISIS_ROUTE_INFO,    "ISIS route info",	MTYPE_NOCACHE	},
  { MTYPE_ISIS_NEXTHOP,       "ISIS nexthop",		MTYPE_NOCACHE	},
  { MTYPE_ISIS_NEXTHOP6,      "ISIS nexthop6",		MTYPE_NOCACHE	},
  { -1, NULL },
};

struct memory_list memory_list_vtysh[] =
{
  { MTYPE_VTYSH_CONFIG,		"Vtysh configuration",	MTYPE_NOCACHE	},
  { MTYPE_VTYSH_CONFIG_LINE,	"Vtysh configuration line", MTYPE_NOCACHE },
  { -1, NULL },
};

struct mlist mlists[] __attribute__ ((unused)) = 
{
  { memory_list_lib,	"LIB"	},
  { memory_list_zebra,	"ZEBRA"	},
  { memory_list_rip,	"RIP"	},
  { memory_list_ripng,	"RIPNG"	},
  { memory_list_ospf,	"OSPF"	},
  { memory_list_ospf6,	"OSPF6"	},
  { memory_list_isis,	"ISIS"	},
  { memory_list_bgp,	"BGP"	},
  { NULL, NULL},
};
