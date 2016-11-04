//
//  default-device.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/03.
//
//  Get default device name.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;

    //get default interface name
    device = pcap_lookupdev(errbuf);
    if(!device) {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }//end if
    
    printf("Default: %s\n", device);

    bpf_u_int32 net, mask;
    //get network and netmask
    if(-1 == pcap_lookupnet(device, &net, &mask, errbuf)) {
        fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
        exit(1);
    }//end if

    char ntop_buf[256];
    //network
    inet_ntop(AF_INET, &net, ntop_buf, sizeof(ntop_buf));
    printf("Network: %s\n", ntop_buf);

    //netmask
    inet_ntop(AF_INET, &mask, ntop_buf, sizeof(ntop_buf));
    printf("Netmask: %s\n", ntop_buf);

    return 0;
}//end main
