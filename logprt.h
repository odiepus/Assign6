#ifndef LOGPRT_H
#define LOGPRT_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

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
