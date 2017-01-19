//
//  dump-arp.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/09.
//
//  Dump ARP frame header.
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
#include <netinet/if_ether.h>
#else /* if BSD */
#define __FAVOR_BSD
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#endif /* if linux */

#include <net/if_arp.h>

#define MAC_ADDRSTRLEN 2*6+5+1
#define STR_BUF 16
static const char *mac_ntoa(u_int8_t *d);
static const char *ip_ntoa(void *i);
static void dump_ethernet(u_int32_t length, const u_char *content);
static void dump_arp(u_int32_t length, const u_char *content);
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
    
    //generate bpf filter
    bpf_u_int32 net, mask;
    struct bpf_program fcode;

    //get network and mask
    if(-1 == pcap_lookupnet(device, &net, &mask, errbuf)) {
        fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
        mask = PCAP_NETMASK_UNKNOWN;
    }//end if
    
    //compile filter
    if(-1 == pcap_compile(handle, &fcode, "arp", 1, mask)) {
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
    pcap_loop(handle, 2, pcap_callback, NULL);
    
    //free
    pcap_close(handle);
    return 0;
}//end main

static const char *mac_ntoa(u_int8_t *d) {
    static char mac[STR_BUF][MAC_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(mac[which], 0, MAC_ADDRSTRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return mac[which];
}//end mac_ntoa

static const char *ip_ntoa(void *i) {
    static char ip[STR_BUF][INET_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);
    
    memset(ip[which], 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, i, ip[which], sizeof(ip[which]));
    
    return ip[which];
}//end ip_ntoa

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
            dump_arp(length, content);
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

static void dump_arp(u_int32_t length, const u_char *content) {
    u_short hdr_type;
    u_short pro_type;
    u_char hdr_len;
    u_char pro_len;
    u_short op;
    char sender_mac[MAC_ADDRSTRLEN] = {0};
    char sender_ip[INET_ADDRSTRLEN] = {0};
    char target_mac[MAC_ADDRSTRLEN] = {0};
    char target_ip[INET_ADDRSTRLEN] = {0};

    struct ether_arp *arp = (struct ether_arp *)(content + ETHER_HDR_LEN);

    //copy header
    hdr_type = ntohs(arp->arp_hrd);
    pro_type = ntohs(arp->arp_pro);
    hdr_len = arp->arp_hln;
    pro_len = arp->arp_pln;
    op = ntohs(arp->arp_op);
    snprintf(sender_mac, sizeof(sender_mac), "%s", mac_ntoa(arp->arp_sha));
    snprintf(sender_ip, sizeof(sender_ip), "%s", ip_ntoa(arp->arp_spa));
    snprintf(target_mac, sizeof(target_mac), "%s", mac_ntoa(arp->arp_tha));
    snprintf(target_ip, sizeof(target_ip), "%s", ip_ntoa(arp->arp_tpa));

    static char *arp_op_name[] = {
        "Undefine",
        "(ARP Request)",
        "(ARP Reply)",
        "(RARP Request)",
        "(RARP Reply)"
    }; //arp option type
    
    if(op < 0 || sizeof(arp_op_name)/sizeof(arp_op_name[0]) < op)
        op = 0;
    
    //print
    printf("Protocol: ARP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Hard Type: %2u%-11s| Protocol: %#06x%-8s|\n",
           hdr_type, (hdr_type == ARPHRD_ETHER) ? "(Ethernet)" : "(Not Ether)",
           pro_type, (pro_type == ETHERTYPE_IP) ? "(IP)" : "(Not IP)");
    printf("+------------+------------+-------------------------+\n");
    printf("| Hard Len:%2u| Addr Len:%2u| OP: %4d%16s|\n",
           hdr_len, pro_len, op, arp_op_name[op]);
    printf("+------------+------------+-------------------------+-------------------------+\n");
    printf("| Sender MAC Address:                                        %17s|\n", sender_mac);
    printf("+---------------------------------------------------+-------------------------+\n");
    printf("| Sender IP Address:                 %15s|\n", sender_ip);
    printf("+---------------------------------------------------+-------------------------+\n");
    printf("| Target MAC Address:                                        %17s|\n", target_mac);
    printf("+---------------------------------------------------+-------------------------+\n");
    printf("| Target IP Address:                 %15s|\n", target_ip);
    printf("+---------------------------------------------------+\n");
}//end dump_arp