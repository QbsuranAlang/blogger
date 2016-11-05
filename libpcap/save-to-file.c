//
//  save-to-file.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/05.
//
//  Save frames to file.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);

int main(int argc, const char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;

    //get default interface name
    device = pcap_lookupdev(errbuf);
    if(!device) {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }//end if

    printf("Sniffing: %s\n", device);
    
    //open interface
    pcap_t *handle = pcap_open_live(device, 65535, 1, 1, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }//end if
    
    //open file handler
    const char *filename = "saved.pcap";
    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if(!dumper) {
        fprintf(stderr, "pcap_dump_open(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }//end if
    
    printf("Saving to %s...\n", filename);

    //start capture loop
    if(0 != pcap_loop(handle, 1000, pcap_callback, (u_char *)dumper)) {
        fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(handle));
    }//end if
    
    //flush and close
    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    printf("\nDone\n");
    
    //free
    pcap_close(handle);
    
    return 0;
}//end main

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    printf("\rNo.%5d captured", ++d);
    fflush(stdout);
    
    //dump to file
    pcap_dump(arg, header, content);
}//end pcap_callback