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
ssize_t bufferlength;
uint8_t buffer[1536];

static ssize_t intf_write(sigma_intf *instance, const uint8_t* input, size_t len)
{
	sigma_intf_priv* private = (sigma_intf_priv*) instance;

	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0]='\0';
	pcap_t* pcap=pcap_open_live(private->nodename, 96, 0, 0, pcap_errbuf);

	if (pcap_errbuf[0]!='\0')
	{
		fprintf(stderr,"%s",pcap_errbuf);
	}

	if (!pcap) {
		exit(1);
	}

	if (pcap_inject(pcap, input+4, len-4) == -1)
	{
		pcap_perror(pcap,0);
		pcap_close(pcap);
		exit(1);
	}

	pcap_close(pcap);

	return 0;
}

void my_callback(u_char* args, const struct pcap_pkthdr* pkthdr, u_char* packet)
{
    u_int16_t i = 0;

	buffer[2] = packet[12];
	buffer[3] = packet[13];

    bufferlength = pkthdr->len+4;
    memcpy(buffer+4, packet, bufferlength);
}

static ssize_t intf_read(sigma_intf *instance, uint8_t* output, size_t len)
{
	bufferlength = 0;

	pcap_dispatch(descr, 1, (void *) my_callback, NULL);

	memcpy(output, buffer, bufferlength+4);
    return bufferlength;
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

	printf("Public Interface is initialized for %s.\n", private->nodename);

	private->baseintf.filedesc = pcap_fileno(descr);

	buffer[0] = 0;
	buffer[1] = 0;

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

    intf_private->baseintf.init = intf_init;
    intf_private->baseintf.read = intf_read;
    intf_private->baseintf.write = intf_write;
    intf_private->baseintf.set = intf_set;
    intf_private->baseintf.reload = intf_reload;
    intf_private->baseintf.updateremote = NULL;

    return (sigma_intf*) intf_private;
}
