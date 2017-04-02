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
#include "prtlog.h"


typedef enum {false, true} bool;

void printGlobalHeader(struct pcap_file_header *pcapHdr);
struct pcap_file_header getGlobalHeader(int fd);
bool getPacketHeader(int fd, struct my_pkthdr *my_PacketHdr);
void savePayload(int fd, int *dataBuf, int len);
void printPacketHdr(struct my_pkthdr *my_PacketHdr);
int printEtherData(int fd);


int main(int argc, char* argv[]) {

    struct pcap_file_header pcapHdr;
    struct my_pkthdr my_PacketHdr;
    struct eth_hdr my_EtherHdr;
    struct arp_hdr my_ArpHdr;
    struct ip_hdr my_IpHdr;

    int fd = 0;
    int dataBuf[65535];
    int bytesRead = 1;
    bool flag = true;

    //used to calculate packet times
    unsigned static int firstTime = 1;
    unsigned static int b_sec = 0;
    static int b_usec = 0;
    static int c_usec = 0;
    unsigned static int c_sec = 0;

    printf("%ld\n", sizeof(my_PacketHdr));

    //char *x = "network.nonip.log";
    //open file descriptor for binary file
    //int fd = open(x, O_RDONLY);

    for(int i = 1; i < argc; i++)
    {
        int pktNum = 0;
        fd = open(argv[i], O_RDONLY);
        if (fd == -1)
        {
            perror("Failed to open file\n");
            exit(-1);
        }


        pcapHdr = getGlobalHeader(fd);
        printGlobalHeader(&pcapHdr);

        while(getPacketHeader(fd, &my_PacketHdr) != false)
        {
            printf("Packet %d\n", pktNum++);
            printPacketHdr(&my_PacketHdr);
            int dataLen = my_PacketHdr.caplen;
            int lengthRead = printEtherData(fd);
            savePayload(fd, dataBuf, dataLen - lengthRead);
        }
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
    struct my_pkthdr header;
    int bytesRead = 0;
    if(( bytesRead = read(fd, &header, sizeof(header))) == -1)
    {
        perror("Failed to read from binary into Packet Header struct\n");
        exit(-1);
    }
    if(bytesRead == 0)
    {
        *my_PacketHdr = header;
        return false;
    }
    else
    {
        *my_PacketHdr = header;
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

int printEtherData(int fd)
{
    struct eth_hdr my_EtherHdr;
    struct ip_hdr my_IpHdr;
    struct arp_hdr my_ArpHdr;

    if ((read(fd, &my_EtherHdr, sizeof(my_EtherHdr))) == -1)
    {
        perror("Read from file descriptor to Ethernet Header Struct failed");
        exit(-1);
    }
     if (ntohs (my_EtherHdr.eth_type) == ETH_TYPE_IP)
    {
        printf("   IP\n");

       if ((read(fd, &my_IpHdr, sizeof(my_IpHdr))) == -1)
       {
           perror("Read from file descriptor to IP Header Struct failed");
           exit(-1);
       }

       switch (my_IpHdr.ip_p) {
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
        return sizeof(my_EtherHdr) + sizeof(my_IpHdr);
   }
   else if (ntohs (my_EtherHdr.eth_type) == ETH_TYPE_ARP)
   {
       printf("   ARP\n");

       if ((read(fd, &my_ArpHdr, sizeof(my_ArpHdr)) == -1))
       {
           perror("Read from file descriptor to ARP Header struct failed");
           exit(-1);
       }

       switch (ntohs(my_ArpHdr.ar_op)) {
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

        return sizeof(my_EtherHdr) + sizeof(my_ArpHdr);
   } else
   {
       printf("URECOGNIZED\n");
       printf("\n");
        return sizeof(my_EtherHdr);
   }
}
