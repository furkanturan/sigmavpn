//
//  intf_tuntap.h
//  Sigma TUN/TAP interface code
//
//  Copyright (c) 2011, Neil Alexander T.
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with
//  or without modification, are permitted provided that the following
//  conditions are met:
//
//  - Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  - Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "../intf.h"

#ifdef linux
#include <net/if.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

typedef union
{
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
}
sigma_address;

typedef struct sigma_intf_tuntap
{
    sigma_intf baseintf;

    sigma_address lastrecvaddr;

    int filedesc;
    char nodename[16];
    int tunmode;
    int protocolinfo;
}
sigma_intf_tuntap;

static ssize_t intf_write(sigma_intf *instance, const uint8_t* input, size_t len)
{
    sigma_intf_tuntap* tuntap = (sigma_intf_tuntap*) instance;

    if (!tuntap->filedesc < 0)
        return -1;

    return write(tuntap->baseintf.filedesc, input, len);
}

static ssize_t intf_read(sigma_intf *instance, uint8_t* output, size_t len)
{
    sigma_intf_tuntap* tuntap = (sigma_intf_tuntap*) instance;

    u_int16_t i = 0;

    if (!tuntap->filedesc < 0)
        return -1;

    ssize_t ret = read(tuntap->baseintf.filedesc, output, len);

    printf("\nETH Frame (%d) (%d): ", (int)len, (int)ret);

	for(i=0; i<(int)len; i++)
	{
		printf("%x ", output[i]);

	}

	return ret;
}

static int intf_init(sigma_intf* instance)
{
	sigma_intf_tuntap* tuntap = (sigma_intf_tuntap*) instance;

    if (!tuntap->nodename)
        strcpy(tuntap->nodename, "/dev/tap0");

    #ifdef __linux__
        if ((tuntap->baseintf.filedesc = open("/dev/net/tun", O_RDWR)) < 0)
        {
            fprintf(stderr, "Unable to find /dev/net/tun\n");
            return -1;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

	// Set interface name
        strncpy(ifr.ifr_name, tuntap->nodename, IFNAMSIZ);

	// TUN or TAP interface?
       	ifr.ifr_flags = tuntap->tunmode == 1 ? IFF_TUN : IFF_TAP;

	// Enable or disable proto info for TUN mode
	if (tuntap->protocolinfo == 0 && tuntap->tunmode == 1)
	        ifr.ifr_flags |= IFF_NO_PI;

        if (ioctl(tuntap->baseintf.filedesc, TUNSETIFF, (void *) &ifr) < 0)
        {
            fprintf(stderr, "Unable to configure tuntap device: ");
	    perror("ioctl");
            return -1;
        }
    #else
        if ((tuntap->baseintf.filedesc = open(tuntap->nodename, O_RDWR)) < 0)
        {
            fprintf(stderr, "Unable to open tuntap device '%s': ", tuntap->nodename);
            perror("ioctl");
            return -1;
        }
    #endif

        printf("TUN/TAP Interface is initialized for %s.\n", tuntap->nodename);

    return 0;

//	sigma_intf_tuntap* tuntap = (sigma_intf_tuntap*) instance;
//
//	char sender[INET6_ADDRSTRLEN];
//	int ret, i;
//	int sockopt;
//	ssize_t numbytes;
//	struct ifreq ifopts;	/* set promiscuous mode */
//	struct ifreq if_ip;	/* get ip addr */
//	struct sockaddr_storage their_addr;
//	uint8_t buf[1024];
//	char ifName[IFNAMSIZ];
//
//	strcpy(ifName, "eth1");
//
//	memset(&if_ip, 0, sizeof(struct ifreq));
//
//	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
//	if ((tuntap->baseintf.filedesc = socket(PF_PACKET, SOCK_RAW, htons(0x0800))) == -1) {
//		perror("listener: socket");
//		return -1;
//	}
//
//	/* Set interface to promiscuous mode - do we need to do this every time? */
//	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
//	ioctl(tuntap->baseintf.filedesc, SIOCGIFFLAGS, &ifopts);
//	ifopts.ifr_flags |= IFF_PROMISC;
//	ioctl(tuntap->baseintf.filedesc, SIOCSIFFLAGS, &ifopts);
//
//	/* Allow the socket to be reused - incase connection is closed prematurely */
//	if (setsockopt(tuntap->baseintf.filedesc, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
//		perror("setsockopt");
//		close(tuntap->baseintf.filedesc);
//		exit(EXIT_FAILURE);
//	}
//
//	/* Bind to device */
//	if (setsockopt(tuntap->baseintf.filedesc, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
//		perror("SO_BINDTODEVICE");
//		close(tuntap->baseintf.filedesc);
//		exit(EXIT_FAILURE);
//	}
}

static int intf_set(sigma_intf* instance, char* param, char* value)
{
    sigma_intf_tuntap* tuntap = (sigma_intf_tuntap*) instance;

    if (strcmp(param, "interface") == 0)
        memcpy(tuntap->nodename, value, 16);

    if (strcmp(param, "tunmode") == 0)
        tuntap->tunmode = atoi(value);

    if (strcmp(param, "protocolinfo") == 0)
        tuntap->protocolinfo = atoi(value);

    return 0;
}

static int intf_reload(sigma_intf* instance)
{
	sigma_intf_tuntap* tuntap = (sigma_intf_tuntap*) instance;

	if (close(tuntap->baseintf.filedesc) == -1)
	{
			printf("Interface close failed\n");
			return -1;
	}

	tuntap->baseintf.filedesc = -1;

	intf_init(instance);

	return 0;
}

extern sigma_intf* intf_descriptor()
{
    sigma_intf_tuntap* intf_tuntap = calloc(1, sizeof(sigma_intf_tuntap));

    intf_tuntap->baseintf.init = intf_init;
    intf_tuntap->baseintf.read = intf_read;
    intf_tuntap->baseintf.write = intf_write;
    intf_tuntap->baseintf.set = intf_set;
    intf_tuntap->baseintf.reload = intf_reload;
    intf_tuntap->baseintf.updateremote = NULL;

    return (sigma_intf*) intf_tuntap;
}
