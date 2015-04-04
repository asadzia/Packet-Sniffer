/*
* Created by: Asad Zia
* 
* Description:
* A packet sniffer created using the pcap library. 
* The default setting allows one to read live data from ALL interfaces. The -i option is used to read from a particular interface.
* The -f option is used to read recorded data from a file. The interval for displaying the data can be set by using the -d option.
* The -N option can be used to adjust the number of talkers we want to observe exchanging the packets.
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/if_ether.h>

// a structure defined for storing the live feed packet information
struct store {
    u_char dest[100];   // the destination address of the packet
    u_char src[100];    // the source address of the packet
    int dpack;          // the number of packets received by the destination point
    int dpacksize;      // the total data exchanged between the two talkers
    int spack;          // the number of packets recieved by the source point
 };

char* interface = "any";    // use "any" by default to call interfaces
int offline = 0;            // reading recorded data flag
int interval = 5;           // the interval after which livefeed is displayed
int N = 3;                  // the default value which shows the top N talkers

char ebuf[PCAP_ERRBUF_SIZE];// the error buffer used in the pcap functions 
pcap_t* descr;              // the descriptor used in the main function

struct store list[1000];    // the list of structs used for storing the configuration of the talkers
int count2 = 0;             // a counter used for traversing through the list
        

// a compare function which is used in the qsort
// basically arranges the data in the list(defined above) from the largest data exchanged to the least.
int compare2 (const void * a, const void * b)   
{
  return ( ((struct store*)b)->dpacksize - ((struct store*)a)->dpacksize );
}

// the callback function used by the pcap_loop in the main function
void processPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{

 int i = 0;
 struct ether_header *eptr; // this variable stores the MAC addressses
 u_char *ptr;               // used for pointing to the MAC addresses while printing
 int w, f = 0;              // iterators used in traversing the array of structs

 

    // typecasting the packet to extract the header information
     eptr = (struct ether_header *) packet;

     // a loop for checking the already existing src/dest pair information
     if (count2 != 0) {

        // looking at all elements of list
        for (w = 0; w < count2; w++) {

            // if both the src and dest address match then the packet count and header length is added
            if (strcmp(eptr->ether_dhost, list[w].dest) == 0) {
                if (strcmp(eptr->ether_shost, list[w].src) == 0) {
                     list[w].dpacksize += pkthdr->len;
                     list[w].dpack += 1;
                     goto next;
                }
            }
            // in case the dest sends packets to the src in our pair, then increment packet count for src packets 
            if (strcmp(eptr->ether_dhost, list[w].src) == 0) {
                if (strcmp(eptr->ether_shost, list[w].dest) == 0) {
                     list[w].dpacksize += pkthdr->len;
                     list[w].spack += 1;
                     goto next;
                }
            }
        }

         // If the MAC addresses don't exist, make a new entry in list       
         u_int8_t* sourceHex1;
         u_int8_t* destHex1;  
         sourceHex1 = eptr->ether_shost; 
         destHex1 = eptr->ether_dhost;
         char sourceAddr1[18];
         char destAddr1[18];
         sprintf( destAddr1,  "%02x:%02x:%02x:%02x:%02x:%02x",destHex1[0],destHex1[1],destHex1[2],destHex1[3],destHex1[4],destHex1[5] );
         sprintf( sourceAddr1,  "%02x:%02x:%02x:%02x:%02x:%02x",sourceHex1[0],sourceHex1[1],sourceHex1[2],sourceHex1[3],sourceHex1[4],sourceHex1[5] );
         strcpy(list[count2].dest, destAddr1);
         strcpy(list[count2].src, sourceAddr1);
         list[count2].dpacksize = pkthdr->len;
         list[count2].dpack = 1;
         list[count2].spack = 0;
         count2++;  
    }


    // the case when the program starts and the first packet is analyzed and its information is added to list
    if (count2 == 0) {
        u_int8_t* sourceHex;
        u_int8_t* destHex;  
        sourceHex = eptr->ether_shost; 
        destHex = eptr->ether_dhost;
        char sourceAddr[18];
        char destAddr[18];
        sprintf( destAddr,  "%02x:%02x:%02x:%02x:%02x:%02x",destHex[0], destHex[1], destHex[2], destHex[3],destHex[4], destHex[5] );
        sprintf( sourceAddr,  "%02x:%02x:%02x:%02x:%02x:%02x",sourceHex[0],sourceHex[1], sourceHex[2],sourceHex[3], sourceHex[4], sourceHex[5] );
        strcpy(list[count2].dest, destAddr);
        strcpy(list[count2].src, sourceAddr);
        list[count2].dpacksize = pkthdr->len;
        list[count2].dpack = 1;
        list[count2].spack = 0;
        count2++;  
    }
     
    // the goto statement references to this point from the loop above in order to break out of the outer loops
    // this is done to avoid making a new pair since a src/dest pair already exists for the packet observed
    next:

    // sorting all the elements in the list array
    qsort (list, count2, sizeof(struct store), compare2);

    // a for-loop which runs for N-times to display the top-N talkers
    for (f = 0; f < N; f++) {

        ptr = list[f].src;
        i = ETHER_ADDR_LEN;

        printf("src            dst | ");

        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);
        printf(" | ");

        ptr = list[f].dest;
        i = ETHER_ADDR_LEN;

        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);

        printf("  |\n");
        printf("------------------+----------------------+--------------------+\n");

         ptr = list[f].src;
        i = ETHER_ADDR_LEN;

        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);

        printf(" | ");
        printf("    0 p,  0 B      ");

        // here conversion to kilobytes in case we cross 1000 bytes
        if (list[f].dpacksize <= 1000) {
            printf(" |      %d p, %d B     |\n", list[f].dpack, list[f].dpacksize);
        }else{
            int p = list[f].dpacksize/1000;
            printf(" |      %d p, %d kB    |\n", list[f].dpack, p);
        }

        ptr = list[f].dest;
        i = ETHER_ADDR_LEN;

        do{
            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);


        // here conversion to kilobytes in case we cross 1000 bytes
        if (list[f].dpacksize <= 1000) {
        printf(" |       %d p, %d B     |", list[f].spack, list[f].dpacksize);
        }else{
        int q = list[f].dpacksize/1000;
        printf(" |      %d p, %d kB     |", list[f].spack, q);
        }

        printf("    0 p,  0 B      |\n\n\n");

    }
    printf("*************************************************************************\n\n");
    // the feed is displayed after an interval as set in the main function or just by default.
    sleep(interval);
}

// the function for parsing the commands written in the stdin while running the program
void parsing(int argc, char** argv)
{
    int opt;
    while( (opt = getopt(argc, argv, "i:f:d:N:")) != -1 ){
        switch(opt){
            case 'i':
                interface = optarg;
                
                break;
            case 'f':
                interface = optarg;
                offline = 1;
                break;
            case 'd':
                interval = atoi(optarg);
                break;
            case 'N':
                N = atoi(optarg);
                break;
            default:
            // in case the wrong command is input
                fprintf(stderr, "Usage: %s [-i interface] [-f file] [-d Interval] [-N Station]\n", argv[0]);
                exit(1);
        }
    }

}

// the main function
int main(int argc, char** argv)
{
    parsing(argc, argv);
    int count = 0;

    // reading all interfaces or a particular interface
    if( offline == 0 ) {
        if ((descr = pcap_create(interface, ebuf)) == NULL) {
            fprintf(stderr, "ERROR: %s\n", ebuf);
            exit(1);
        }
    }else{
        if ((descr = pcap_open_offline(interface, ebuf)) == NULL) {
            fprintf(stderr, "ERROR: %s\n", ebuf);
            exit(1);
        }
    }
    pcap_activate(descr);

    // running the pcap_loop 
    if (pcap_loop(descr, -1, processPacket, (u_char *) &count) == -1) {
        fprintf(stderr, "failed to process packets: %s\n", pcap_geterr(descr));
        exit(5);
    }



    return 0;
}
