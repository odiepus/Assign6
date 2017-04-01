#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

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
//
//int main(int argc, char* argv[]) {
//
//    // struct to hold individual packet data
//    struct my_pkthdr myPhdr;
//    //packet count
//    int pnum = 1;
//    //Global header buffer
//    int x[24];
//    //Packet data buffer
//    int buf[65535];
//    //used to calculate packet times
//    unsigned static int firstTime = 1;
//    unsigned static int b_sec = 0;
//    static int b_usec = 0;
//    static int c_usec = 0;
//    unsigned static int c_sec = 0;
//
//    //used to hold packet header times
//    struct my_pkthdr phdr;
//
//    //open file descriptor for binary file
//    int fd = open(argv[1], O_RDONLY);
//    if (fd == -1)
//    {
//        perror("Failed to open file\n");
//    }
//    //Remove global header
//    read(fd, x, sizeof(x));
//
//    int bytesread = 1;
//    while(  (bytesread = read(fd,&myPhdr, sizeof(myPhdr))) > 0 ) {
//
//        printf("Packet %d\n", pnum++);
//        printf("Captured Packet Length = %d\n", myPhdr.caplen);
//        printf("Actual Packet Length = %d\n", myPhdr.len);
//
//        if (firstTime)
//        {
//            firstTime = 0;
//
//            b_sec = myPhdr.ts.tv_sec;
//            b_usec = myPhdr.ts.tv_usec;
//        }
//
//        c_sec = (unsigned)myPhdr.ts.tv_sec - b_sec;
//        c_usec = (unsigned)myPhdr.ts.tv_usec - b_usec;
//
//        while(c_usec < 0)
//        {
//            c_usec += 1000000;
//            c_sec--;
//        }
//
//        printf("%05u.%06u\n",(unsigned)c_sec, (unsigned)c_usec);
//        read(fd, buf, myPhdr.len);
//    }
//
//    if (bytesread == -1)
//    {
//        perror("Failed to read file\n");
//    }
//
//    return 0;
//}