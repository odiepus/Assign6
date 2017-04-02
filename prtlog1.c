#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include "pcap.h"
#include "dnet.h"


#define ETH_TYPE_PUP    0x0200      /*PUP protocol*/
#define EHT_TYPE_IP     0x0800      /*IP protocol*/
#define ETH_TYPE_ARP    0x0806      /*address resolution protocol*/
#define ETH_TYPE_REVARP 0x8035      /*reverse address resolution protocol*/
#define ETH_TYPE_8021Q  0x8100      /*IEE 802.1Q VLAN tagging*/
#define ETH_TYPE_IPV6   0x86DD      /*IPv6 protocol*/
#define ETH_TYPE_MPLS   0x8847      /*MPLS*/
#define ETH_TYPE_MPLS_MCAST 0x8848  /*MPLS multicast*/
#define ETH_TYPE_PPPOEDISC  0x8863  /*PPP Over Ethernet Discovery Stage*/
#define ETH_TYPE_PPOE   0x8864      /*PPP Over Ethernet Session Stage*/
#define ETH_TYPE_LOOPBACK   0x9000  /*used to test interfaces*/

/*
 * ARP operations
 */

#define ARP_OP_REQUEST          1       /*request to resolve ha given pa*/
#define ARP_OP_REPLY            2       /*response giving hardware address*/
#define ARP_OP_REVREQUEST       3       /*request to resolve pa given ha*/
#define ARP_OP_REVREPLY         4       /*response giving protocol address*/

struct timev{
    unsigned int tv_sec;
    unsigned int tv_usec;
};

struct my_pkthdr{
    struct timev ts;
    int caplen;
    int len;
};

typedef enum {false, true} bool;

void printGlobalHeader(struct pcap_file_header *pcapHdr);
struct pcap_file_header getGlobalHeader(int fd);
bool getPacketHeader(int fd, struct my_pkthdr *my_PacketHdr);
void savePayload(int fd, int *dataBuf, int len);
void printPacketHdr(struct my_pkthdr *my_PacketHdr);

int main(int argc, char* argv[]) {



    struct pcap_file_header pcapHdr;
    struct my_pkthdr my_PacketHdr;
    struct eth_hdr my_EtherHdr;
    struct arp_hdr my_ArpHdr;
    struct ip_hdr my_IpHdr;

    int pktNum = 0;
    int dataBuf[65535];
    int bytesRead = 1;
    bool flag = true;

    //used to calculate packet times
    unsigned static int firstTime = 1;
    unsigned static int b_sec = 0;
    static int b_usec = 0;
    static int c_usec = 0;
    unsigned static int c_sec = 0;

    char *x = "network.nonip.log";
    //open file descriptor for binary file
    int fd = open(x, O_RDONLY);
    if (fd == -1)
    {
        perror("Failed to open file\n");
        exit(-1);
    }

    pcapHdr = getGlobalHeader(fd);
    printGlobalHeader(&pcapHdr);

    do{

        flag = getPacketHeader(fd, &my_PacketHdr);
        printPacketHdr(&my_PacketHdr);
        int dataLen = my_PacketHdr.caplen;
        savePayload(fd, dataBuf, dataLen);
        printf("loop %d\n", pktNum++);
    }
     while(flag);


    return 0;

}


void printGlobalHeader(struct pcap_file_header *pcapHdr) {
    //print out all global header info
    printf("PCAP_MAGIC\n");
    printf("Version major number = %d\n", pcapHdr->version_major);
    printf("Version minor number = %d\n", pcapHdr->version_minor);
    printf("GMT to local correction = %d\n", pcapHdr->thiszone);
    printf("Timestamp accuracy = %d\n", pcapHdr->sigfigs);
    printf("Snaplen = %d\n", pcapHdr->snaplen);
    printf("Linktype = %d\n\n", pcapHdr->linktype);
}

struct pcap_file_header getGlobalHeader(int fd)
{
    struct pcap_file_header returnThis;
    if((read(fd, &returnThis, sizeof(returnThis))) == -1)
    {
        perror("Failed to read from file to Pcap Header\n");
        exit(-1);
    }
    return returnThis;
}

bool getPacketHeader(int fd, struct my_pkthdr *my_PacketHdr)
{

    int bytesRead = 0;
    if(( bytesRead = read(fd, my_PacketHdr, sizeof(my_PacketHdr))) == -1)
    {
        perror("Failed to read from binary into Packet Header struct\n");
        exit(-1);
    }
    if(bytesRead == 0)
    {
        return false;
    }
    else
    {
        return  true;
    }
}


void savePayload(int fd, int *dataBuf, int len)
{
    if((read(fd, dataBuf, len)) == -1)
    {
        perror("Failed to read from binary file to data buffer\n");
    }
}

void printPacketHdr(struct my_pkthdr *my_PacketHdr)
{
    //used to calculate packet times
    unsigned static int firstTime = 1;
    unsigned static int b_sec = 0;
    static int b_usec = 0;
    static int c_usec = 0;
    unsigned static int c_sec = 0;

    if (firstTime)
    {
        firstTime = 0;

        b_sec = my_PacketHdr->ts.tv_sec;
        b_usec = my_PacketHdr->ts.tv_usec;
    }

    c_sec = (unsigned)my_PacketHdr->ts.tv_sec - b_sec;
    c_usec = (unsigned)my_PacketHdr->ts.tv_usec - b_usec;

    while(c_usec < 0)
    {
        c_usec += 1000000;
        c_sec--;
    }

    printf("%05u.%06u\n",(unsigned)c_sec, (unsigned)c_usec);
    printf("Captured Packet Length = %d\n", my_PacketHdr->caplen);
    printf("Actual Packet Length = %d\n", my_PacketHdr->len);
}