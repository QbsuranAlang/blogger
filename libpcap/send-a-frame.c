//
//  send a frame.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2017/01/19.
//
//  Send a frame.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main(int argc, const char * argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;

    //get default interface name
    device = pcap_lookupdev(errbuf);
    if(!device) {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }//end if
    
    pcap_t *handle = pcap_open_live(device, 65535, 1, 1, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }//end if
    
    u_char frame[] = "\x01\x02\x03\x04\x05\x06\xff\xff\xff\xff\xff\xff\x81\x00";
    int length = sizeof(frame) - 1;
    //send packet
    if(pcap_sendpacket(handle, frame, length) < 0) {
        fprintf(stderr, "pcap_sendpacket(): %s\n", pcap_geterr(handle));
    }//end if
    
    //free
    pcap_close(handle);
    return 0;
}