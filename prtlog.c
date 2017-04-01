//
// Created by odiep on 3/31/2017.
//
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

struct timev{
    unsigned int tv_sec;
    unsigned int tv_usec;
};

struct my_pkthdr{
    struct timev ts;
    int caplen;
    int len;
};


int main(int argc, char* argv[]) {

    // struct to hold individual packet data
    struct my_pkthdr myStruct;

    //packet count
    int pnum = 0;

    //Global header buffer
    int x[24];

    //Packet data buffer
    int buf[65535];

    //used to calculate packet times
    unsigned static int firstTime = 1;
    unsigned static int b_sec = 0;
    static int b_usec = 0;
    static int c_usec = 0;
    unsigned static int c_sec = 0;

    //used to hold packet header times
    struct my_pkthdr phdr;
    struct pcap_file_header pcapHdr;
    struct eth_hdr etherHdr;

    //open file descriptor for binary file
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1)
    {
        perror("Failed to open file\n");
    }
    //Remove global header
    read(fd, &pcapHdr, sizeof(pcapHdr));
    printf("PCAP_MAGIC\n");
    printf("Version major number = %d\n", pcapHdr.version_major);
    printf("Version minor number = %d\n", pcapHdr.version_minor);
    printf("GMT to local correction = %d\n", pcapHdr.thiszone);
    printf("Timestamp accuracy = %d\n", pcapHdr.sigfigs);
    printf("Snaplen = %d\n", pcapHdr.snaplen);
    printf("Linktype = %d\n\n", pcapHdr.linktype);


    int bytesread = 1;
    while(  (bytesread = read(fd,&myStruct, sizeof(myStruct))) > 0 ) {

        if (bytesread == -1)
        {
            perror("Failed to read from buffer\n");
        }

        if (firstTime)
        {
            firstTime = 0;

            b_sec = myStruct.ts.tv_sec;
            b_usec = myStruct.ts.tv_usec;
        }

        c_sec = (unsigned)myStruct.ts.tv_sec - b_sec;
        c_usec = (unsigned)myStruct.ts.tv_usec - b_usec;

        while(c_usec < 0)
        {
            c_usec += 1000000;
            c_sec--;
        }

        printf("Packet %d\n", pnum++);
        printf("%05u.%06u\n",(unsigned)c_sec, (unsigned)c_usec);
        printf("Captured Packet Length = %d\n", myStruct.caplen);
        printf("Actual Packet Length = %d\n", myStruct.len);

        read(fd, &etherHdr, sizeof(etherHdr));

        if (ntohs (etherHdr.eth_type) == ETH_TYPE_IP)
        {
            printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                   ntohs(etherHdr.eth_type),
                   ntohs(etherHdr.eth_type));
        }else  if (ntohs (etherHdr.eth_type) == ETH_TYPE_ARP)
        {
            printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                   ntohs(etherHdr.eth_type),
                   ntohs(etherHdr.eth_type));
        }else {
            printf("Ethernet type %x not IP", ntohs(etherHdr.eth_type));
            exit(1);
        }


        printf("\n\n");

        read(fd, buf, myStruct.caplen);
    }


    return 0;
}
