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


struct timev{
    unsigned int tv_sec;
    unsigned int tv_usec;
};

struct my_pkthdr{
    struct timev ts;
    int caplen;
    int len;
};


#endif
