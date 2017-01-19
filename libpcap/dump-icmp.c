//
//  dump-icmp.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/23.
//
//  Dump ICMP datagram header.
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
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define MAC_ADDRSTRLEN 2*6+5+1
#define STR_BUF 16
static const char *mac_ntoa(u_int8_t *d);
static const char *ip_ntoa(void *i);
static const char *ip_ttoa(u_int8_t flag);
static const char *ip_ftoa(u_int16_t flag);
static const char *tcp_ftoa(u_int8_t flag);
static void dump_ethernet(u_int32_t length, const u_char *content);
static void dump_ip(struct ip *ip);
static void dump_tcp(struct tcphdr *tcp);
static void dump_tcp_mini(struct tcphdr *tcp);
static void dump_udp(struct udphdr *udp);
static void dump_icmp(struct icmp *icmp);
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
    if(-1 == pcap_compile(handle, &fcode, "icmp", 1, mask)) {
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
    pcap_loop(handle, 1, pcap_callback, NULL);
    
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

static const char *ip_ttoa(u_int8_t flag) {
    static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
#define TOS_MAX (sizeof(f)/sizeof(f[0]))
    static char str[TOS_MAX + 1]; //return buffer
    u_int8_t mask = 1 << 7; //mask
    int i;
    
    for(i = 0 ; i < TOS_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;
    
    return str;
}//end ip_ttoa

static const char *ip_ftoa(u_int16_t flag) {
    static int f[] = {'R', 'D', 'M'}; //flag
#define IP_FLG_MAX (sizeof(f)/sizeof(f[0]))
    static char str[IP_FLG_MAX + 1]; //return buffer
    u_int16_t mask = 1 << 15; //mask
    int i;
    
    for(i = 0 ; i < IP_FLG_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;
    
    return str;
}//end ip_ftoa

static const char *tcp_ftoa(u_int8_t flag) {
    static int  f[] = {'W', 'E', 'U', 'A', 'P', 'R', 'S', 'F'};
#define TCP_FLG_MAX (sizeof f / sizeof f[0])
    static char str[TCP_FLG_MAX + 1];
    u_int32_t mask = 1 << 7;
    int i;
    
    for (i = 0; i < TCP_FLG_MAX; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = '\0';
    
    return str;
}//end tcp_ftoa

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
            dump_ip((struct ip *)(content + ETHER_HDR_LEN));
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

static void dump_ip(struct ip *ip) {

    //copy header
    u_int version = ip->ip_v;
    u_int header_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);
    u_int16_t id = ntohs(ip->ip_id);
    u_int16_t offset = ntohs(ip->ip_off);
    u_char ttl = ip->ip_ttl;
    u_char protocol = ip->ip_p;
    u_int16_t checksum = ntohs(ip->ip_sum);
    char src_ip[INET_ADDRSTRLEN] = {0};
    char dst_ip[INET_ADDRSTRLEN] = {0};

    //copy ip address
    snprintf(src_ip, sizeof(src_ip), "%s", ip_ntoa(&ip->ip_src));
    snprintf(dst_ip, sizeof(dst_ip), "%s", ip_ntoa(&ip->ip_dst));
    
    //print
    printf("Protocol: IP\n");
    printf("+-----+------+------------+-------------------------+\n");
    printf("| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|\n",
           version, header_len, ip_ttoa(tos), total_len);
    printf("+-----+------+------------+-------+-----------------+\n");
    printf("| Identifier:        %5u| FF:%3s| FO:        %5u|\n",
           id, ip_ftoa(offset), offset & IP_OFFMASK);
    printf("+------------+------------+-------+-----------------+\n");
    printf("| TTL:    %3u| Pro:    %3u| Header Checksum:  %#06x|\n",
           ttl, protocol, checksum);
    printf("+------------+------------+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n", src_ip);
    printf("+---------------------------------------------------+\n");
    printf("| Destination IP Address:            %15s|\n", dst_ip);
    printf("+---------------------------------------------------+\n");
    
    char *p = (char *)ip + (ip->ip_hl << 2);
    switch (protocol) {
        case IPPROTO_UDP:
            printf("Next is UDP\n");
            break;
            
        case IPPROTO_TCP:
            printf("Next is TCP\n");
            break;
            
        case IPPROTO_ICMP:
            printf("Next is ICMP\n");
            dump_icmp((struct icmp *)p);
            break;
            
        default:
            printf("Next is %d\n", protocol);
            break;
    }//end switch
}//end dump_ip

static void dump_tcp(struct tcphdr *tcp) {

    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);
    u_int32_t ack = ntohl(tcp->th_ack);
    u_int8_t header_len = tcp->th_off << 2;
    u_int8_t flags = tcp->th_flags;
    u_int16_t window = ntohs(tcp->th_win);
    u_int16_t checksum = ntohs(tcp->th_sum);
    u_int16_t urgent = ntohs(tcp->th_urp);
    
    //print
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10u|\n", sequence);
    printf("+---------------------------------------------------+\n");
    printf("| Acknowledgement Number:                 %10u|\n", ack);
    printf("+------+-------+----------+-------------------------+\n");
    printf("| HL:%2u|  RSV  |F:%8s| Window Size:       %5u|\n", header_len, tcp_ftoa(flags), window);
    printf("+------+-------+----------+-------------------------+\n");
    printf("| Checksum:          %5u| Urgent Pointer:    %5u|\n", checksum, urgent);
    printf("+-------------------------+-------------------------+\n");
}//end dump_tcp

static void dump_tcp_mini(struct tcphdr *tcp) {
    
    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);
    
    //print
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10u|\n", sequence);
    printf("+---------------------------------------------------+\n");
}//end dump_tcp_mini

static void dump_udp(struct udphdr *udp) {

    //copy header
    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);
    
    printf("Protocol: UDP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Length:            %5u| Checksum:          %5u|\n", len, checksum);
    printf("+-------------------------+-------------------------+\n");
}//end dump_udp

static void dump_icmp(struct icmp *icmp) {
    
    //copy header
    u_char type = icmp->icmp_type;
    u_char code = icmp->icmp_code;
    u_char checksum = ntohs(icmp->icmp_cksum);
    
    static char *type_name[] = {
        "Echo Reply",               /* Type  0 */
        "Undefine",                 /* Type  1 */
        "Undefine",                 /* Type  2 */
        "Destination Unreachable",  /* Type  3 */
        "Source Quench",            /* Type  4 */
        "Redirect (change route)",  /* Type  5 */
        "Undefine",                 /* Type  6 */
        "Undefine",                 /* Type  7 */
        "Echo Request",             /* Type  8 */
        "Undefine",                 /* Type  9 */
        "Undefine",                 /* Type 10 */
        "Time Exceeded",            /* Type 11 */
        "Parameter Problem",        /* Type 12 */
        "Timestamp Request",        /* Type 13 */
        "Timestamp Reply",          /* Type 14 */
        "Information Request",      /* Type 15 */
        "Information Reply",        /* Type 16 */
        "Address Mask Request",     /* Type 17 */
        "Address Mask Reply",       /* Type 18 */
        "Unknown"                   /* Type 19 */
    }; //icmp type
#define ICMP_TYPE_MAX (sizeof type_name / sizeof type_name[0])
    
    if (type < 0 || ICMP_TYPE_MAX <= type)
        type = ICMP_TYPE_MAX - 1;
    
    printf("Protocol: ICMP (%s)\n", type_name[type]);
    
    printf("+------------+------------+-------------------------+\n");
    printf("| Type:   %3u| Code:   %3u| Checksum:          %5u|\n", type, code, checksum);
    printf("+------------+------------+-------------------------+\n");
    
    if (type == ICMP_ECHOREPLY || type == ICMP_ECHO) {
        printf("| Identification:    %5u| Sequence Number:   %5u|\n", ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
        printf("+-------------------------+-------------------------+\n");
    }//end if
    else if (type == ICMP_UNREACH) {
        if (code == ICMP_UNREACH_NEEDFRAG) {
            printf("| void:          %5u| Next MTU:          %5u|\n", ntohs(icmp->icmp_pmvoid), ntohs(icmp->icmp_nextmtu));
            printf("+-------------------------+-------------------------+\n");
        }//end if
        else {
            printf("| Unused:                                 %10lu|\n", (unsigned long) ntohl(icmp->icmp_void));
            printf("+-------------------------+-------------------------+\n");
        }//end else
    }//end if
    else if (type == ICMP_REDIRECT) {
        printf("| Router IP Address:                 %15s|\n", ip_ntoa(&(icmp->icmp_gwaddr)));
        printf("+---------------------------------------------------+\n");
    }//end if
    else if (type == ICMP_TIMXCEED) {
        printf("| Unused:                                 %10lu|\n", (unsigned long)ntohl(icmp->icmp_void));
        printf("+---------------------------------------------------+\n");
    }//end else
    
    //if the icmp packet carry ip header
    if (type == ICMP_UNREACH || type == ICMP_REDIRECT || type == ICMP_TIMXCEED) {
        struct ip *ip = (struct ip *)icmp->icmp_data;
        char *p = (char *)ip + (ip->ip_hl << 2);
        dump_ip(ip);
        
        switch (ip->ip_p) {
            case IPPROTO_TCP:
                if(type == ICMP_REDIRECT) {
                    /**
                     * RFC 792: Page 12
                     * 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Gateway Internet Address                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     * only 8 bytes
                     */
                    dump_tcp_mini((struct tcphdr *)p);
                }//end if
                else {
                    dump_tcp((struct tcphdr *)p);
                }//end else
                break;
            case IPPROTO_UDP:
                dump_udp((struct udphdr *)p);
                break;
        }//end switch
    }//end if
}//end dump_icmp