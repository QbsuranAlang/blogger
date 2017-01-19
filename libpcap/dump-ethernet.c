//
//  dump-ethernet.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/07.
//
//  Dump Ethernet frame header.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#else /* if BSD */
#define __FAVOR_BSD
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#endif /* if linux */

#define MAC_ADDRSTRLEN 2*6+5+1
static const char *mac_ntoa(u_int8_t *d);
static void dump_ethernet(u_int32_t length, const u_char *content);
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
    
    pcap_t *handle = pcap_open_live(device, 65535, 1, 1, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        exit(1);
    }//end if
    
    //start capture
    pcap_loop(handle, 3, pcap_callback, NULL);
    
    //free
    pcap_close(handle);
    return 0;
}//end main

static const char *mac_ntoa(u_int8_t *d) {
#define STR_BUF 16
    static char mac[STR_BUF][MAC_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(mac[which], 0, MAC_ADDRSTRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return mac[which];
}//end mac_ntoa

static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    
    printf("No. %d\n", ++d);
    
    //print header
    printf("\tTime: %s.%.6d\n", timestr, (int)header->ts.tv_usec);
    printf("\tLength: %d bytes\n", header->len);
    printf("\tCapture length: %d bytes\n", header->caplen);
    
    //dump ethernet
    dump_ethernet(header->caplen, content);
    
    printf("\n");
}//end pcap_callback

static void dump_ethernet(u_int32_t length, const u_char *content) {
    char dst_mac[MAC_ADDRSTRLEN] = {0};
    char src_mac[MAC_ADDRSTRLEN] = {0};
    u_int16_t type;
    
    struct ether_header *ethernet = (struct ether_header *)content;

    //copy header
    snprintf(dst_mac, sizeof(dst_mac), "%s", mac_ntoa(ethernet->ether_dhost));
    snprintf(src_mac, sizeof(src_mac), "%s", mac_ntoa(ethernet->ether_shost));
    type = ntohs(ethernet->ether_type);
    
    //print
    if(type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");
    
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Destination MAC Address:                                   %17s|\n", dst_mac);
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Source MAC Address:                                        %17s|\n", src_mac);
    printf("+-------------------------+-------------------------+-------------------------+\n");
    if (type < 1500)
        printf("| Length:            %5u|\n", type);
    else
        printf("| Ethernet Type:    0x%04x|\n", type);
    printf("+-------------------------+\n");
    
    printf("Next protocol is ");
    switch (type) {
        case ETHERTYPE_ARP:
            printf("ARP\n");
            break;
            
        case ETHERTYPE_IP:
            printf("IP\n");
            break;
            
        case ETHERTYPE_REVARP:
            printf("RARP\n");
            break;
            
        case ETHERTYPE_IPV6:
            printf("IPv6\n");
            break;
            
        default:
            printf("%#06x\n", type);
            break;
    }//end switch
}//end dump_ethernet