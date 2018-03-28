//
//  dump-wol.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2017/01/22.
//
//  Dump Wake-On-LAN frame and datagram header.
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

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#define MAC_ADDRSTRLEN 2*6+5+1
#define ETHERTYPE_WOL 0x0842
#define WOL_DEFAULT_PORT 9

struct wol_hdr {
    u_char sync[6];
    u_char mac_addr[16][6];
    u_char pass[6];
    int pass_len;
} __attribute__((packed));

#define STR_BUF 16
static const char *mac_ntoa(u_int8_t *d);
static const char *ip_ntoa(void *i);
static const char *ip6_ntoa(void *i);
static const char *sync_ntoa(u_int8_t *s);
static void dump_wol(u_int32_t length, const u_char *content);
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
    char filter[256];
    snprintf(filter, sizeof(filter), "ether proto %d or udp dst port %d", ETHERTYPE_WOL, WOL_DEFAULT_PORT);
    if(-1 == pcap_compile(handle, &fcode, filter, 1, mask)) {
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
    pcap_loop(handle, -1, pcap_callback, NULL);
    
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

static const char *ip6_ntoa(void *i) {
    static char ip[STR_BUF][INET6_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);
    
    memset(ip[which], 0, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, i, ip[which], sizeof(ip[which]));
    
    return ip[which];
}//end ip6_ntoa

static const char *sync_ntoa(u_int8_t *s) {
#define SYNC_STRLEN 2*6+1
    static char sync_str[STR_BUF][SYNC_STRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(sync_str[which], 0, sizeof(sync_str[which]));
    snprintf(sync_str[which], sizeof(sync_str[which]), "%02x%02x%02x%02x%02x%02x", s[0], s[1], s[2], s[3], s[4], s[5]);

    return sync_str[which];
}//end sync_ntoa

static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    int len = 0;
    u_char *wol_ptr = NULL;
    
    struct ether_header *ethernet = (struct ether_header *)content;
    u_int16_t type = ntohs(ethernet->ether_type);

    if(type == ETHERTYPE_WOL) {
        char dst_mac[MAC_ADDRSTRLEN] = {0};
        char src_mac[MAC_ADDRSTRLEN] = {0};

        snprintf(dst_mac, sizeof(dst_mac), "%s", mac_ntoa(ethernet->ether_dhost));
        snprintf(src_mac, sizeof(src_mac), "%s", mac_ntoa(ethernet->ether_shost));

        len = header->caplen - ETHER_HDR_LEN;
        wol_ptr = (u_char *)(content + ETHER_HDR_LEN);

        printf("%s -> %s\n", src_mac, dst_mac);
    }//end if wol
    else if(type == ETHERTYPE_IP) {
        struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
        struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
        
        char src_ip[INET_ADDRSTRLEN] = {0};
        char dst_ip[INET_ADDRSTRLEN] = {0};

        snprintf(src_ip, sizeof(src_ip), "%s", ip_ntoa(&ip->ip_src));
        snprintf(dst_ip, sizeof(dst_ip), "%s", ip_ntoa(&ip->ip_dst));

        //port
        u_int16_t source_port = ntohs(udp->uh_sport);
        u_int16_t destination_port = ntohs(udp->uh_dport);

        wol_ptr = (u_char *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2) + 8);
        len = header->caplen - ETHER_HDR_LEN - (ip->ip_hl << 2) - 8;

        printf("%s(%u) -> %s(%u)\n", src_ip, source_port, dst_ip, destination_port);
    }//end if ipv4
    else if(type == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(content + ETHER_HDR_LEN);
        struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + 40);

        char src_ip[INET6_ADDRSTRLEN] = {0};
        char dst_ip[INET6_ADDRSTRLEN] = {0};

        snprintf(src_ip, sizeof(src_ip), "%s", ip6_ntoa(&ip6->ip6_src));
        snprintf(dst_ip, sizeof(dst_ip), "%s", ip6_ntoa(&ip6->ip6_dst));

        //port
        u_int16_t source_port = ntohs(udp->uh_sport);
        u_int16_t destination_port = ntohs(udp->uh_dport);

        wol_ptr = (u_char *)(content + ETHER_HDR_LEN + 40 + 8);
        len = header->caplen - ETHER_HDR_LEN - 40 - 8;

        printf("%s(%u) -> %s(%u)\n", src_ip, source_port, dst_ip, destination_port);
    }//end if ipv6

    if(wol_ptr) {
        dump_wol(len, wol_ptr);
        printf("\n");
    }//end if
    
}//end pcap_callback

static void dump_wol(u_int32_t length, const u_char *content) {
    struct wol_hdr wol;
    memset(&wol, 0, sizeof(wol));

    //copy header
    memcpy(wol.sync, content, sizeof(wol.sync));
    length -= sizeof(wol.sync);
    content += sizeof(wol.sync);
    for(int i = 0 ; i < sizeof(wol.mac_addr)/sizeof(wol.mac_addr[0]) ; i++) {
        memcpy(&wol.mac_addr[i], content, sizeof(wol.mac_addr[i]));
        length -= sizeof(wol.mac_addr[i]);
        content += sizeof(wol.mac_addr[i]);
    }//end for
    wol.pass_len = length;
    if(wol.pass_len == 4 || wol.pass_len == 6) {
        memcpy(wol.pass, content, wol.pass_len);
    }//end if

    //print
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Sync stream:                                               %17s|\n", sync_ntoa(wol.sync));
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| MAC Address:                                               %17s|\n", mac_ntoa(wol.mac_addr[0]));
    printf("+-------------------------+-------------------------+-------------------------+\n");
    if(wol.pass_len == 4) {
        printf("| Password:                          %15s|\n", ip_ntoa(wol.pass));
        printf("+---------------------------------------------------+\n");
    }//end if len 4
    else if(wol.pass_len == 6) {
        printf("| Password:                                                  %17s|\n", mac_ntoa(wol.pass));
        printf("+-------------------------+-------------------------+-------------------------+\n");
    }//end if len 6

    printf("\n");
}//end dump_wol