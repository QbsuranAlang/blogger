//
//  offline-filter.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2017/01/19.
//
//  Filter a offline file using filter.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

int main(int argc, const char * argv[]) {

    const char *filter = "";
    if(argc == 2) {
        filter = argv[1];
    }//end if

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *filename = "saved.pcap";

    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }//end if
    printf("Open: %s\n", filename);

    //compile filter
    struct bpf_program fcode;
    if(-1 == pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN)) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }//end if

    if(strlen(filter) != 0) {
        printf("Filter: %s\n", filter);
    }//end if
    
    int total_amount = 0;
    int total_bytes = 0;
    while(1) {
        struct pcap_pkthdr *header = NULL;
        const u_char *content = NULL;
        int ret =
        pcap_next_ex(handle, &header, &content);
        if(ret == 1) {
            if(pcap_offline_filter(&fcode, header, content) != 0) {  
                total_amount++;
                total_bytes += header->caplen;
            }//end if match
        }//end if success
        else if(ret == 0) {
            printf("Timeout\n");
        }//end if timeout
        else if(ret == -1) {
            fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handle));
        }//end if fail
        else if(ret == -2) {
            printf("No more packet from file\n");
            break;
        }//end if read no more packet
    }//end while

    //result
    printf("Read: %d, byte: %d bytes\n", total_amount, total_bytes);

    //free
    pcap_freecode(&fcode);
    pcap_close(handle);
    
    return 0;
}//end main