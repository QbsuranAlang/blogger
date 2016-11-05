//
//  capture-pcap_next_ex.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/05.
//
//  Capture frame using pcap_next_ex().
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>

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
    pcap_t *handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }//end if
    
    //start capture
    struct pcap_pkthdr *header = NULL;
    const u_char *content = NULL;
    int ret =
    pcap_next_ex(handle, &header, &content);
    if(ret == 1) {
        struct tm *ltime;
        char timestr[16];
        time_t local_tv_sec;
        
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        
        //print header
        printf("Time: %s.%.6d\n", timestr, (int)header->ts.tv_usec);
        printf("Length: %d bytes\n", header->len);
        printf("Capture length: %d bytes\n", header->caplen);
        
        //print packet in hex dump
        for(int i = 0 ; i < header->caplen ; i++) {
            printf("%02x ", content[i]);
        }//end for
        printf("\n\n");
    }//end if success
    else if(ret == 0) {
        printf("Timeout\n");
    }//end if timeout
    else if(ret == -1) {
        fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handle));
    }//end if fail
    else if(ret == -2) {
        printf("No more packet from file\n");
    }//end if read no more packet
    
    //free
    pcap_close(handle);
    
    return 0;
}