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

void printGlobalHeader(struct pcap_file_header *pcapHdr);
void printEtherType(int fd, int packetHeaderLen, int *dataBuf, struct eth_hdr *my_EtherHdr, struct ip_hdr *my_IpHdr, struct arp_hdr *my_ArpHdr);

int main(int argc, char* argv[]) {



    struct pcap_file_header pcapHdr;
    struct my_pkthdr my_PacketHdr;
    struct eth_hdr my_EtherHdr;
    struct arp_hdr my_ArpHdr;
    struct ip_hdr my_IpHdr;

    int pktNum = 0;
    int dataBuf[65535];
    int bytesRead = 1;

    //used to calculate packet times
    unsigned static int firstTime = 1;
    unsigned static int b_sec = 0;
    static int b_usec = 0;
    static int c_usec = 0;
    unsigned static int c_sec = 0;

    char * x = "C:\\Users\\odiep\\CLionProjects\\cs3423Assign6\\network.nonip.log";
    //open file descriptor for binary file
    int fd = open(x, O_RDONLY);
    if (fd == -1)
    {
        perror("Failed to open file\n");
        exit(-1);
    }

    read(fd, &pcapHdr, sizeof(pcapHdr));
    printGlobalHeader(&pcapHdr);

    while((bytesRead = read(fd, &my_PacketHdr, sizeof(my_PacketHdr)) ) > 0 ) {

        if (firstTime)
        {
            firstTime = 0;

            b_sec = my_PacketHdr.ts.tv_sec;
            b_usec = my_PacketHdr.ts.tv_usec;
        }

        c_sec = (unsigned)my_PacketHdr.ts.tv_sec - b_sec;
        c_usec = (unsigned)my_PacketHdr.ts.tv_usec - b_usec;

        while(c_usec < 0)
        {
            c_usec += 1000000;
            c_sec--;
        }

        printf("Packet %d\n", pktNum++);
        printf("%05u.%06u\n",(unsigned)c_sec, (unsigned)c_usec);
        printf("Captured Packet Length = %d\n", my_PacketHdr.caplen);
        printf("Actual Packet Length = %d\n", my_PacketHdr.len);
        printf("Ethernet Header\n");

        if ((read(fd, &my_EtherHdr, sizeof(my_EtherHdr))) == -1)
        {
            perror("Read from file descriptor to Ethernet Header Struct failed");
            exit(-1);
        }

        int packetHeaderLen = my_PacketHdr.len;
         printEtherType(fd, packetHeaderLen, dataBuf, &my_EtherHdr, &my_IpHdr, &my_ArpHdr);
//         if (ntohs (my_EtherHdr.eth_type) == ETH_TYPE_IP)
//        {
//            printf("   IP\n");
//
//            if ((read(fd, &my_IpHdr, sizeof(my_IpHdr))) == -1)
//            {
//                perror("Read from file descriptor to IP Header Struct failed");
//                exit(-1);
//            }
//
//            switch (my_IpHdr.ip_p) {
//                case 1:
//                    printf("      ICMP\n");
//                    break;
//                case 2:
//                    printf("      IGMP\n");
//                    break;
//                case 6:
//                    printf("      TCP\n");
//                    break;
//                case 17:
//                    printf("      UDP\n");
//                    break;
//                default:
//                    printf("URECOGNIZED\n");
//                    break;
//            }
//
//            printf("\n");
//
//            if ((read(fd, dataBuf, packetHeaderLen - sizeof(my_EtherHdr) - sizeof(my_IpHdr)) == -1))
//            {
//                perror("Read from file descriptor to dataBuffer failed");
//                exit(-1);
//            }
//
//        }
//        else if (ntohs (my_EtherHdr.eth_type) == ETH_TYPE_ARP)
//        {
//            printf("   ARP\n");
//
//            if ((read(fd, &my_ArpHdr, sizeof(my_ArpHdr)) == -1))
//            {
//                perror("Read from file descriptor to ARP Header struct failed");
//                exit(-1);
//            }
//
//            switch (ntohs(my_ArpHdr.ar_op)) {
//                case 1:
//                    printf("      Arp Reply\n");
//                    break;
//                case 2:
//                    printf("      Arp Request\n");
//                    break;
//                case 3:
//                    printf("      Arp RevRequest\n");
//                    break;
//                case 4:
//                    printf("      Arp RevReply\n");
//                    break;
//                default:
//                    printf("URECOGNIZED\n");
//                    break;
//            }
//            printf("\n");
//
//            read(fd, dataBuf, packetHeaderLen - sizeof(my_EtherHdr) - sizeof(my_ArpHdr));
//        } else
//        {
//            printf("URECOGNIZED\n");
//            printf("\n");
//            read(fd, dataBuf, packetHeaderLen - sizeof(my_EtherHdr));
//        }

    }

    if(bytesRead == -1)
    {
        perror("Failed to read into Packet Header Struct\n");
        exit(-1);
    }

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

void printEtherType(int fd, int packetHeaderLen, int *dataBuf, struct eth_hdr *my_EtherHdr, struct ip_hdr *my_IpHdr, struct arp_hdr *my_ArpHdr)
{
    if (ntohs (my_EtherHdr->eth_type) == ETH_TYPE_IP)
        {
            printf("   IP\n");

            if ((read(fd, &my_IpHdr, sizeof(my_IpHdr))) == -1)
            {
                perror("Read from file descriptor to IP Header Struct failed");
                exit(-1);
            }

            switch (my_IpHdr->ip_p) {
                case 1:
                    printf("      ICMP\n");
                    break;
                case 2:
                    printf("      IGMP\n");
                    break;
                case 6:
                    printf("      TCP\n");
                    break;
                case 17:
                    printf("      UDP\n");
                    break;
                default:
                    printf("URECOGNIZED\n");
                    break;
            }

            printf("\n");

            if ((read(fd, dataBuf, packetHeaderLen - sizeof(my_EtherHdr) - sizeof(my_IpHdr)) == -1))
            {
                perror("Read from file descriptor to dataBuffer failed");
                exit(-1);
            }

        }
        else if (ntohs (my_EtherHdr->eth_type) == ETH_TYPE_ARP)
        {
            printf("   ARP\n");

            if ((read(fd, &my_ArpHdr, sizeof(my_ArpHdr)) == -1))
            {
                perror("Read from file descriptor to ARP Header struct failed");
                exit(-1);
            }

            switch (ntohs(my_ArpHdr->ar_op)) {
                case 1:
                    printf("      Arp Reply\n");
                    break;
                case 2:
                    printf("      Arp Request\n");
                    break;
                case 3:
                    printf("      Arp RevRequest\n");
                    break;
                case 4:
                    printf("      Arp RevReply\n");
                    break;
                default:
                    printf("URECOGNIZED\n");
                    break;
            }
            printf("\n");

            read(fd, dataBuf, packetHeaderLen - sizeof(my_EtherHdr) - sizeof(my_ArpHdr));
        } else
        {
            printf("URECOGNIZED\n");
            printf("\n");
            read(fd, dataBuf, packetHeaderLen - sizeof(my_EtherHdr));
        }
}
