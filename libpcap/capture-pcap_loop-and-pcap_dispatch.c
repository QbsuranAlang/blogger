//
//  capture-pcap_loop-and-pcap_dispatch.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/04.
//
//  Capture frame using pcap_loop() and pcap_dispatch().
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>

void pcap_callback1(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);
void pcap_callback2(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);

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

    pcap_t *handle = NULL;
    //open interface
    handle = pcap_open_live(device, 65535, 1, 1, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }//end if
    
    //start capture pcap_loop()
    if(0 > pcap_loop(handle, 10, pcap_callback1, NULL)) {
        fprintf(stderr, "pcap_loop(): %s\n", pcap_geterr(handle));
    }//end if
    
    //start capture pcap_dispatch()
    int ret = pcap_dispatch(handle, -1, pcap_callback2, (u_char *)handle);
    if(0 > ret) {
        fprintf(stderr, "pcap_dispatch(): %s\n", pcap_geterr(handle));
    }//end if
    else {
        printf("Captured: %d\n", ret);
    }//end else

    //free
    pcap_close(handle);
    
    return 0;
}//end main

void pcap_callback1(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    printf("%3d: captured\n", ++d);
}//end pcap_callback1

void pcap_callback2(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    
    printf("No. %3d\n", ++d);

    //format timestamp
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    //print header
    printf("    Time: %s.%.6d\n", timestr, (int)header->ts.tv_usec);
    printf("    Length: %d bytes\n", header->len);
    printf("    Capture length: %d bytes\n", header->caplen);
    
    //print packet in hex dump
    for(int i = 0 ; i < header->caplen ; i++) {
        printf("%02x ", content[i]);
    }//end for
    printf("\n\n");

    //break when captured 20 frames    
    if(d == 20) {
        pcap_t *handle = (pcap_t *)arg;
        pcap_breakloop(handle);
    }//end if
}//end pcap_callback2