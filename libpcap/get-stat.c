//
//  get-stat.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2017/01/20.
//
//  Get current status.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>

static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);

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
    pcap_t *handle = pcap_open_live(device, 65535, 1, 5000, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }//end if
    
    //generate bpf filter
    bpf_u_int32 net, mask;
    struct bpf_program fcode;

    //get network and mask
    if(-1 == pcap_lookupnet(device, &net, &mask, errbuf)) {
        fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
        mask = PCAP_NETMASK_UNKNOWN;
    }//end if
    
    //compile filter
    if(-1 == pcap_compile(handle, &fcode, "tcp or udp", 1, mask)) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }//end if
    
    //set filter
    if(-1 == pcap_setfilter(handle, &fcode)) {
        fprintf(stderr, "pcap_pcap_setfilter(): %s\n", pcap_geterr(handle));
        pcap_freecode(&fcode);
        pcap_close(handle);
        exit(1);
    }//end if
    
    //free bpf code
    pcap_freecode(&fcode);
    
    //start capture
    int capture = 0;
    pcap_dispatch(handle, -1, pcap_callback, (u_char *)&capture);

    //get stat
    struct pcap_stat ps;
    if(pcap_stats(handle, &ps) != 0) {
        fprintf(stderr, "pcap_stats(): %s\n", pcap_geterr(handle));
    }//end if
    else {
        printf("Receive: %d\n", capture);
        printf("Receive by filter: %d\n", ps.ps_recv);
        printf("Drop by kernel: %d\n", ps.ps_drop);
        printf("Drop by interface: %d\n", ps.ps_ifdrop);
    }//end else
    
    //free
    pcap_close(handle);
    
    return 0;
}//end main

static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    int *capture = (int *)arg;
    (*capture)++;
    return;
}//end pcap_callback