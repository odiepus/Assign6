#ifndef PRTLOG_H
#define PRTLOG_H

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


#define PCAPT_MAGIC                 0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC          0xd4c3b2a1
#define PCAP_MODIFIED_MAGIC         0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC 0x34cdb2a1

typedef enum {false, true} bool;

struct timev{
    unsigned int tv_sec;
    unsigned int tv_usec;
};

struct my_pkthdr{
    struct timev ts;
    int caplen;
    int len;
};

//pass by reference the pcap header struct to function and print out the info
void printGlobalHeader(struct pcap_file_header *pcapHdr);

//create global header struct in function populate it from file
//then return the struct
struct pcap_file_header getGlobalHeader(int fd);

//pull packet header from file descriptor and point passed in
//struct to it
bool getPacketHeader(int fd, struct my_pkthdr *my_PacketHdr);

/*given length of headers that have been removed from file descriptor
* the difference between the caplen and removed headers is used to
*put the payload into the data buffer
*/
void savePayload(int fd, int *dataBuf, int len);

/* pass by reference the packet header struct and
 * print out the information contained within to
 * stdout
 */
void printPacketHdr(struct my_pkthdr *my_PacketHdr);

/*create ehternet headers inside function then based on
 * on ethernet type an ip or arp struct is created and populated.
 * The information is then printed out to stdout
 */
int printEtherData(int fd);


#endif
