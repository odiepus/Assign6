#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include "logprt.h"


int main(int argc, char* argv[]) {

    // struct to hold individual packet data
    struct my_pkthdr myPhdr;

    //packet count
    int pnum = 0;

    //Global header buffer
    char x[24];

    //Packet data buffer
    int buf[65535];

    //used to calculate packet times
    unsigned static int firstTime = 1;
    unsigned static int b_sec = 0;
    static int b_usec = 0;
    static int c_usec = 0;
    unsigned static int c_sec = 0;

    if(argc == 1)
    {
        printf("Usage: %s [file1] [file2] [file3] ...\n", argv[0]);
        printf("Please input at least one file\n");
        exit(-1);
    }

    for(int i = 1; i < argc; i++)
    {
        //open file descriptor for binary file
        int fd = open(argv[i], O_RDONLY);
        if (fd == -1)
        {
            perror("Failed to open file\nUsage: %s [file1] [file2] ...\n");
            exit(-1);
        }
        //Remove global header
        read(fd, x, sizeof(x));

        //packet count
        int pnum = 0;

        int bytesread = 1;
        while(  (bytesread = read(fd, &myPhdr, sizeof(myPhdr))) > 0 ) {

            printf("Packet %d\n", pnum++);
            printf("Captured Packet Length = %d\n", myPhdr.caplen);
            printf("Actual Packet Length = %d\n", myPhdr.len);

            if (firstTime)
            {
                firstTime = 0;

                b_sec = myPhdr.ts.tv_sec;
                b_usec = myPhdr.ts.tv_usec;
            }

            c_sec = (unsigned)myPhdr.ts.tv_sec - b_sec;
            c_usec = (unsigned)myPhdr.ts.tv_usec - b_usec;

            while(c_usec < 0)
            {
                c_usec += 1000000;
                c_sec--;
            }

            printf("%05u.%06u\n",(unsigned)c_sec, (unsigned)c_usec);
            if((read(fd, buf, myPhdr.caplen)) == -1)
            {
                perror("Failed to read from file descriptor to data buffer\n");
                exit(-1);
            }
        }

        if (bytesread == -1)
        {
            perror("Failed to read file descriptor to Packet Header struct\n");
            exit(-1);
        }
    }

    return 0;
}
