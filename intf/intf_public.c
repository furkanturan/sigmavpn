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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

/*For file descriptors*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>


typedef union
{
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
}
sigma_address;

typedef struct sigma_intf_priv
{
    sigma_intf baseintf;

    sigma_address lastrecvaddr;

    int filedesc;
    char nodename[16];
    int tunmode;
    int protocolinfo;
}
sigma_intf_priv;


pcap_t* descr;

static ssize_t intf_write(sigma_intf *instance, const uint8_t* input, size_t len)
{
    sigma_intf_priv* tuntap = (sigma_intf_priv*) instance;

    if (!tuntap->filedesc < 0)
        return -1;

    return write(tuntap->baseintf.filedesc, input, len);
}

void my_callback(u_char* args, const struct pcap_pkthdr* pkthdr, u_char* packet)
{
    u_int16_t i = 0;

    printf("\n");

	for(i=0; i< pkthdr->len; i++)
	{
		printf("%x ", packet[i]);
	}
}

static ssize_t intf_read(sigma_intf *instance, uint8_t* output, size_t len)
{
    pcap_dispatch(descr, 1, (void *) my_callback, NULL);

    return 0;
}

static int intf_init(sigma_intf* instance)
{
	sigma_intf_priv* tuntap = (sigma_intf_priv*) instance;

	if (strcmp(tuntap->nodename, "") == 0)
	{
		fprintf(stderr, "You should specify a device name (eth0, wlan1, e.g.) for public interface.\n");
    	return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	descr = pcap_open_live(tuntap->nodename, BUFSIZ, 0, -1, errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf);
		return -1;
	}

	if(pcap_setdirection(descr, PCAP_D_IN) != 0)
	{
		printf("pcap_setdirection(): error\n");
	}

	printf("Public Interface is initialized for %s.\n", tuntap->nodename);

	tuntap->baseintf.filedesc = pcap_get_selectable_fd(descr);

    return 0;
}

static int intf_set(sigma_intf* instance, char* param, char* value)
{
    sigma_intf_priv* tuntap = (sigma_intf_priv*) instance;

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
	sigma_intf_priv* tuntap = (sigma_intf_priv*) instance;

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
    sigma_intf_priv* intf_tuntap = calloc(1, sizeof(sigma_intf_priv));

    intf_tuntap->baseintf.init = intf_init;
    intf_tuntap->baseintf.read = intf_read;
    intf_tuntap->baseintf.write = intf_write;
    intf_tuntap->baseintf.set = intf_set;
    intf_tuntap->baseintf.reload = intf_reload;
    intf_tuntap->baseintf.updateremote = NULL;

    return (sigma_intf*) intf_tuntap;
}
