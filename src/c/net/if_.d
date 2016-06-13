module c.net.if_;

import core.sys.posix.sys.socket;
import core.sys.posix.sys.types;
import core.sys.posix.net.if_;

extern (C) nothrow @nogc:

version (linux){

/* Standard interface flags. */
enum
{
	IFF_UP = 0x1,           /* Interface is up.  */
	IFF_BROADCAST = 0x2,    /* Broadcast address valid.  */
	IFF_DEBUG = 0x4,        /* Turn on debugging.  */
	IFF_LOOPBACK = 0x8,     /* Is a loopback net.  */
	IFF_POINTOPOINT = 0x10, /* Interface is point-to-point link.  */
	IFF_NOTRAILERS = 0x20,  /* Avoid use of trailers.  */
	IFF_RUNNING = 0x40,     /* Resources allocated.  */
	IFF_NOARP = 0x80,       /* No address resolution protocol.  */
	IFF_PROMISC = 0x100,    /* Receive all packets.  */

	/* Not supported */
	IFF_ALLMULTI = 0x200,   /* Receive all multicast packets.  */

	IFF_MASTER = 0x400,     /* Master of a load balancer.  */
	IFF_SLAVE = 0x800,      /* Slave of a load balancer.  */

	IFF_MULTICAST = 0x1000, /* Supports multicast.  */

	IFF_PORTSEL = 0x2000,   /* Can set media type.  */
	IFF_AUTOMEDIA = 0x4000, /* Auto media select active.  */
	IFF_DYNAMIC = 0x8000    /* Dialup device with changing addresses.  */
}

enum IFHWADDRLEN = 6;
enum IFNAMSIZ    = IF_NAMESIZE;

struct ifreq
{
	union ifr_ifrn
	{
		char[IFNAMSIZ]  ifrn_name; /* Interface name, e.g. "en0".  */
	}

	union ifr_ifru
	{
		sockaddr        ifru_addr;
		sockaddr        ifru_dstaddr;
		sockaddr        ifru_broadaddr;
		sockaddr        ifru_netmask;
		sockaddr        ifru_hwaddr;
		short           ifru_flags;
		int             ifru_ivalue;
		int             ifru_mtu;
		ifmap           ifru_map;
		char[IFNAMSIZ]  ifru_slave; /* Just fits the size */
		char[IFNAMSIZ]  ifru_newname;
		void*           ifru_data;
	}
}

struct ifmap {
	uint    mem_start;
	uint    mem_end;
	ushort  base_addr;
	ubyte   irq;
	ubyte   dma;
	ubyte   port;
}

struct ifconf
{
	int	  ifc_len;     /* Size of buffer.  */
	union ifc_ifcu
	{
		void*  ifcu_buf;
		ifreq* ifcu_req;
	}
}
}