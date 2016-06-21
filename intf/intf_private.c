//
//  intf_private.h
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


#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>

#include <pcap.h>
#include <errno.h>

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

int sockfd;
pcap_t* descr;

struct sockaddr_ll socket_address;

static ssize_t intf_write(  sigma_intf *instance, 
                            const uint8_t* input, 
                            size_t len)
{
	/* Destination MAC */
	memcpy(socket_address.sll_addr, input+4, 6);

    return  sendto( sockfd,
                    input+4, 
                    len-4, 
                    0, 
                    (struct sockaddr*)&socket_address, 
                    sizeof(struct sockaddr_ll));
}

static ssize_t intf_read(   sigma_intf *instance, 
                            uint8_t* output, 
                            size_t len)
{
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	if(pcap_next_ex( descr, &header, &pkt_data)==1)
	{
		output[0] = 0;
		output[1] = 0;
		output[2] = pkt_data[12];
		output[3] = pkt_data[13];

		memcpy(output+4, pkt_data, header->len);
	    return header->len+4;
	}

	return 0;

}

static int intf_init(sigma_intf* instance)
{
	sigma_intf_priv* private = (sigma_intf_priv*) instance;

	if (strcmp(private->nodename, "") == 0)
	{
		fprintf(stderr, "You should specify a device name (eth0, wlan1, e.g.) for public interface.\n");
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	descr = pcap_open_live(private->nodename, BUFSIZ, 0, -1, errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf);
		return -1;
	}

	if(pcap_setnonblock(descr, 1, errbuf) == -1)
	{
		printf("Could not set device to non-blocking.\n");
		return -1;
	}

	if(pcap_setdirection(descr, PCAP_D_IN) != 0)
	{
		printf("pcap_setdirection(): error\n");
		return -1;
	}

	private->baseintf.filedesc = pcap_fileno(descr);


	///////////////

	struct ifreq if_mac;
	struct ifreq if_idx;

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, private->nodename, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, private->nodename, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;



	printf("Private Interface is initialized for %s.\n", private->nodename);

	return 0;

}

static int intf_set(sigma_intf* instance, char* param, char* value)
{
    sigma_intf_priv* private = (sigma_intf_priv*) instance;

    if (strcmp(param, "interface") == 0)
        memcpy(private->nodename, value, 16);

    if (strcmp(param, "tunmode") == 0)
        private->tunmode = atoi(value);

    if (strcmp(param, "protocolinfo") == 0)
        private->protocolinfo = atoi(value);

    return 0;
}

static int intf_reload(sigma_intf* instance)
{
	sigma_intf_priv* private = (sigma_intf_priv*) instance;

	if (close(private->baseintf.filedesc) == -1)
	{
			printf("Interface close failed\n");
			return -1;
	}

	private->baseintf.filedesc = -1;

	intf_init(instance);

	return 0;
}

extern sigma_intf* intf_descriptor()
{
    sigma_intf_priv* intf_private = calloc(1, sizeof(sigma_intf_priv));

    intf_private->baseintf.init         = intf_init;
    intf_private->baseintf.read         = intf_read;
    intf_private->baseintf.write        = intf_write;
    intf_private->baseintf.set          = intf_set;
    intf_private->baseintf.reload       = intf_reload;
    intf_private->baseintf.updateremote = NULL;

    return (sigma_intf*) intf_private;
}

