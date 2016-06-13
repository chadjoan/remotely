module c.ifaddrs;

import core.sys.posix.sys.socket;
import core.sys.posix.sys.types;
//import core.sys.posix.netinet.in_;

version (Posix):
extern (C) nothrow @nogc:

struct ifaddrs {
	ifaddrs*  ifa_next;    /* Next item in list */
	char*     ifa_name;    /* Name of interface */
	uint      ifa_flags;   /* Flags from SIOCGIFFLAGS */
	sockaddr* ifa_addr;    /* Address of interface */
	sockaddr* ifa_netmask; /* Netmask of interface */
	union     ifa_ifu
	{
		sockaddr* ifu_broadaddr; /* Broadcast address of interface */
		sockaddr* ifu_dstaddr;   /* Point-to-point destination address */
	}
	void*     ifa_data;    /* Address-specific data */
};

int getifaddrs(ifaddrs** ifap);
void freeifaddrs(ifaddrs* ifa);