//
//  list-data-link-type.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2017/01/20.
//
//  List data-link supoort type.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main(int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;

    //get default interface name
    device = pcap_lookupdev(errbuf);
    if(!device) {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }//end if
    
    printf("Device: %s\n", device);

    //open handle
    pcap_t *handle = pcap_open_live(device, 65535, 1, 1, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }//end if

    //get defalt data-link type
    int default_dlt = pcap_datalink(handle);

    //get data-link list
    int *dlts = NULL;
    int dlt_len = 0;
    if((dlt_len = pcap_list_datalinks(handle, &dlts)) == -1) {
        fprintf(stderr, "pcap_list_datalinks(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }//end if

    for(int i = 0 ; i < dlt_len ; i++) {
        printf("%d", i + 1);
        printf(": %s(%s)",
            pcap_datalink_val_to_name(dlts[i]),
            pcap_datalink_val_to_description(dlts[i]));

        if(default_dlt == dlts[i]) {
            printf(" [default]");
        }//end if data-link type is default
        printf("\n");
    }//end for
    
    //free
    pcap_free_datalinks(dlts);
    pcap_close(handle);

    return 0;
}//end main
