//
//  dump-dns.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2017/01/16.
//
//  Dump DNS message.
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

#define STR_BUF 16
/**
 * RFC 1035: 2.3.4
 * http://www.freesoft.org/CIE/RFC/1035/9.htm
 * labels          63 octets or less
 * names           255 octets or less
 * UDP messages    512 octets or less
 */
#define DNS_DOMAIN_MAX_LEN (255 + 1)
#define DNS_MAX_LEN (512 + 1)
#define DNS_HDR_LEN (12)

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_LOC 29
#define DNS_TYPE_SRV 33
#define DNS_TYPE_ANY 255
/**
 * A: www.google.com
 * NS: isc.org
 * CNAME: 5-edge-chat.facebook.com(Use A record)
 * SOA: www.google.com
 * PTR: 8.8.8.8 or 2404:6800:4008:c05::63 
 * MX: google.com
 * TXT: google.com
 * AAAA: www.google.com
 * LOC: SW1A2AA.find.me.uk
 * SRV: _http._tcp.mxtoolbox.com
 */

#define DNS_CLASS_IN 1

struct dns_hdr {
    u_int16_t dns_id;
    u_int16_t dns_flags;
    u_int16_t dns_question;
    u_int16_t dns_answer;
    u_int16_t dns_authority;
    u_int16_t dns_additional;
} __attribute__((packed));

struct dns_entry {
    int offset; /* dns entry data length */
    int response; /* is response */

    char dns_name[DNS_DOMAIN_MAX_LEN];
    u_int16_t dns_type;
    u_int16_t dns_class;
    int32_t dns_ttl;
    u_int16_t dns_data_length;
    union {
        struct {
            char addr[INET_ADDRSTRLEN];
        } type_a;
        struct {
            char addr[INET6_ADDRSTRLEN];
        } type_aaaa;
        struct {
            char name[DNS_DOMAIN_MAX_LEN];
        } type_ptr;
        struct {
            char cname[DNS_DOMAIN_MAX_LEN];
        } type_cname;
        struct {
            u_char txt_len;
            char txt[DNS_MAX_LEN];
        } type_txt;
        struct {
            u_int16_t preference;
            char name[DNS_DOMAIN_MAX_LEN];
        } type_mx;
        struct {
            char name[DNS_DOMAIN_MAX_LEN];
        } type_ns;
        struct {
            u_char version;
            u_char size;
            u_char horizontal;
            u_char vertial;
            u_int32_t latitude;
            u_int32_t longitude;
            u_int32_t altitude;
        } type_loc;
        struct {
            char service[DNS_DOMAIN_MAX_LEN];
            char proto[DNS_DOMAIN_MAX_LEN];
            char name[DNS_DOMAIN_MAX_LEN];
            u_int16_t priority;
            u_int16_t weight;
            u_int16_t port;
            char target[DNS_DOMAIN_MAX_LEN];
        } type_srv;
        struct {
            char name1[DNS_DOMAIN_MAX_LEN];
            char name2[DNS_DOMAIN_MAX_LEN];
            u_int32_t serial;
            u_int32_t refresh;
            u_int32_t retry;
            u_int32_t expire;
            u_int32_t minTTL;
        } type_soa;
    } u;
} __attribute__((packed));

static const char *ip_ntoa(void *i);
static const char *ip6_ntoa(void *i);
static void dump_dns(u_int32_t length, const u_char *message);
static int dump_domain_name(u_char *dns_start_ptr, u_char *current_ptr, char *buf, ssize_t buf_len);
static struct dns_entry *dump_dns_data(u_char *dns_start_ptr, u_char *current_ptr, int response);
static void dump_dns_entry(struct dns_entry *dns);
static void free_dns_entry(struct dns_entry *dns);
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
    if(-1 == pcap_compile(handle, &fcode, "udp port 53", 1, mask)) {
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

static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {

    struct ether_header *ethernet = (struct ether_header *)content;
    u_int16_t type = ntohs(ethernet->ether_type);

    if(type == ETHERTYPE_IP) {
        struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
        struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
        
        char src_ip[INET_ADDRSTRLEN] = {0};
        char dst_ip[INET_ADDRSTRLEN] = {0};

        snprintf(src_ip, sizeof(src_ip), "%s", ip_ntoa(&ip->ip_src));
        snprintf(dst_ip, sizeof(dst_ip), "%s", ip_ntoa(&ip->ip_dst));

        //port
        u_int16_t source_port = ntohs(udp->uh_sport);
        u_int16_t destination_port = ntohs(udp->uh_dport);

        printf("%s(%u) -> %s(%u)\n", src_ip, source_port, dst_ip, destination_port);

        u_char *message = (u_char *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2) + 8);
        u_int32_t length = header->caplen - ETHER_HDR_LEN - (ip->ip_hl << 2) - 8;
        dump_dns(length, message);
    }//end if ip
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

        printf("%s(%u) -> %s(%u)\n", src_ip, source_port, dst_ip, destination_port);

        u_char *message = (u_char *)(content + ETHER_HDR_LEN + 40 + 8);
        u_int32_t length = header->caplen - ETHER_HDR_LEN - 40 - 8;
        dump_dns(length, message);
    }//end if ipv6

    printf("\n");
}//end pcap_callback

static void dump_dns(u_int32_t length, const u_char *message) {

    struct dns_hdr *dns = (struct dns_hdr *)message;

    u_int16_t dns_id = ntohs(dns->dns_id);
    u_int16_t dns_flags = ntohs(dns->dns_flags);
    u_int16_t dns_question = ntohs(dns->dns_question);
    u_int16_t dns_answer = ntohs(dns->dns_answer);
    u_int16_t dns_authority = ntohs(dns->dns_authority);
    u_int16_t dns_additional = ntohs(dns->dns_additional);

    //dump dns header first
    printf("Protocol DNS:\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Transaction ID:    %5u| Flags:            0x%04x|\n", dns_id, dns_flags);
    printf("+-------------------------+-------------------------+\n");
    printf("| Questions:         %5u| Answer:            %5u|\n", dns_question, dns_answer);
    printf("+-------------------------+-------------------------+\n");
    printf("| Authority:         %5u| Additional:        %5u|\n", dns_authority, dns_additional);
    printf("+-------------------------+-------------------------+\n");

    //request and response
    printf("\n");
    u_char *dns_start_ptr = (u_char *)message;
    u_char *current_ptr = (u_char *)(message + DNS_HDR_LEN);
    struct {
        char *prompt;
        int count;
        int response;
    } output[] = {
        {.prompt = "Questions", .count = dns_question, .response = 0},
        {.prompt = "Answers", .count = dns_answer, .response = 1},
        {.prompt = "Authority", .count = dns_authority, .response = 1},
        {"Additional", dns_additional, 1}
    };

    int unknown = 0;
    for(int i = 0 ; i < sizeof(output)/sizeof(output[0]) ; i++) {
        if(output[i].count) {
            printf("%s:\n", output[i].prompt);
        }//end if
        for(int j = 0 ; j < output[i].count ; j++) {
            struct dns_entry *dns = dump_dns_data(dns_start_ptr, current_ptr, output[i].response);
            if(dns == NULL) {
                unknown = 1;
                break;
            }//end if
            dump_dns_entry(dns);
            current_ptr += dns->offset;
            free_dns_entry(dns);
            printf("\n");
        }//end for
        if(output[i].count) {
            printf("\n");
        }//end if

        if(unknown) {
            break;
        }//end if
    }//end for each

}//end dump_dns

static int dump_domain_name(u_char *dns_start_ptr, u_char *current_ptr, char *buf, ssize_t buf_len) {
    
    u_char *ptr = current_ptr;
    int index = 0;
    int contain_name_pointer = 0;

    while(*ptr) {

        if(*ptr == 0xc0) {
            ptr = dns_start_ptr + *(ptr + 1); //next byte is the pointer from start
            contain_name_pointer = 1;
        }//end if

        int length = *ptr;
        ptr++; //move to data
        memcpy(buf + index, ptr, length); //copy data
        ptr += length; //move length offset
        if(*ptr) {
            *(buf + index + length) = '.'; //just give the dot
            index += length + 1; //dot
        }//end if still more data
    }//end while

    //count offset
    ptr = current_ptr;
    int offset = 0;
    while(*ptr) {
        offset++;
        if(*ptr == 0xc0) {
            offset++;
            break;
        }//end if meet 0xc0, read to break
        ptr++; //0xc0 won't be any printable char
    }//end if

    return contain_name_pointer ?
    offset :
    offset + 1; //if data not contain name compression, the last '\0' will be used
}//end dump_domain_name

static struct dns_entry *dump_dns_data(u_char *dns_start_ptr, u_char *current_ptr, int response) {
    struct dns_entry *dns = (struct dns_entry *)calloc(1, sizeof(struct dns_entry));
    if(!dns) {
        perror("calloc()");
        return NULL;
    }//end if

    int offset = 0;
    dns->response = response;

    //domain name
    offset += dump_domain_name(dns_start_ptr, current_ptr, dns->dns_name, sizeof(dns->dns_name));
    dns->dns_type = ntohs(*(u_int16_t *)(current_ptr + offset)); //first two byte is type

    //dns type
    switch(dns->dns_type) {
        case DNS_TYPE_A:
        case DNS_TYPE_AAAA:
        case DNS_TYPE_PTR:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_TXT:
        case DNS_TYPE_MX:
        case DNS_TYPE_NS:
        case DNS_TYPE_LOC:
        case DNS_TYPE_SRV:
        case DNS_TYPE_SOA:
        case DNS_TYPE_ANY:  break;
        default:
            free_dns_entry(dns);
            return NULL;
    }//end switch
    offset += 2;

    //dns class
    dns->dns_class = ntohs(*(u_int16_t *)(current_ptr + offset));
    switch(dns->dns_class) {
        case DNS_CLASS_IN: break;
        default:
            free_dns_entry(dns);
            return NULL;
    }//end switch
    offset += 2;

    //if is response
    if(dns->response) {
        //ttl and data_len are universal field in the cast
        /**
         * RFC 1035: 2.3.4
         * http://www.freesoft.org/CIE/RFC/1035/9.htm
         * TTL             positive values of a signed 32 bit number.
         */
        dns->dns_ttl = ntohl(*(int32_t *)(current_ptr + offset));
        offset += 4;
        dns->dns_data_length = ntohs(*(u_int16_t *)(current_ptr + offset));
        offset += 2;

        if(dns->dns_type == DNS_TYPE_A || dns->dns_type == DNS_TYPE_AAAA) {
            const char *addr = NULL;
            if(dns->dns_type == DNS_TYPE_A) {
                addr = ip_ntoa(current_ptr + offset);
                offset += 4;
            }//end if
            else {
                addr = ip6_ntoa(current_ptr + offset);
                offset += 16;
            }//end else

            //because of union
            memcpy(dns->u.type_a.addr, addr, strlen(addr) + 1);

        }//end if a or aaaa
        else if(dns->dns_type == DNS_TYPE_PTR || dns->dns_type == DNS_TYPE_CNAME) {
            //because of union
            offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_ptr.name, sizeof(dns->u.type_ptr.name));
        }//en if ptr or cname
        else if(dns->dns_type == DNS_TYPE_TXT) {
            dns->u.type_txt.txt_len = *(current_ptr + offset);
            offset += 1;

            memcpy(dns->u.type_txt.txt, current_ptr + offset, dns->u.type_txt.txt_len);
            offset += dns->u.type_txt.txt_len;
        }//end if txt
        else if(dns->dns_type == DNS_TYPE_MX) {
            dns->u.type_mx.preference = ntohs(*(u_int16_t *)(current_ptr + offset));
            offset += 2;
            offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_mx.name, sizeof(dns->u.type_mx.name));
        }//end if mx
        else if(dns->dns_type == DNS_TYPE_NS) {
            offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_ns.name, sizeof(dns->u.type_ns.name));
        }//end if ns
        else if(dns->dns_type == DNS_TYPE_LOC) {
            dns->u.type_loc.version = *(current_ptr + offset);
            offset += 1;
            dns->u.type_loc.size = *(current_ptr + offset);
            offset += 1;
            dns->u.type_loc.horizontal = *(current_ptr + offset);
            offset += 1;
            dns->u.type_loc.vertial = *(current_ptr + offset);
            offset += 1;
            dns->u.type_loc.latitude = ntohl(*(u_int32_t *)(current_ptr + offset));
            offset += 4;
            dns->u.type_loc.longitude = ntohl(*(u_int32_t *)(current_ptr + offset));
            offset += 4;
            dns->u.type_loc.altitude = ntohl(*(u_int32_t *)(current_ptr + offset));
            offset += 4;
        }//end if loc
        else if(dns->dns_type == DNS_TYPE_SRV) {

            //some field is parse from dns name
            char temp[DNS_DOMAIN_MAX_LEN];
            memcpy(temp, dns->dns_name, strlen(dns->dns_name) + 1);

            char *temp_name = temp;
            char *service = temp_name;
            *(temp_name + strcspn(temp_name, ".")) = '\0';
            temp_name += strlen(service) + 1;
            char *proto = temp_name;
            *(temp_name + strcspn(temp_name, ".")) = '\0';
            temp_name += strlen(proto) + 1;
            char *remain_name = temp_name;
            memcpy(dns->u.type_srv.service, service, strlen(service) + 1);
            memcpy(dns->u.type_srv.proto, proto, strlen(proto) + 1);
            memcpy(dns->u.type_srv.name, remain_name, strlen(remain_name) + 1);

            dns->u.type_srv.priority = ntohs(*(u_int16_t *)(current_ptr + offset));
            offset += 2;
            dns->u.type_srv.weight = ntohs(*(u_int16_t *)(current_ptr + offset));
            offset += 2;
            dns->u.type_srv.port = ntohs(*(u_int16_t *)(current_ptr + offset));
            offset += 2;
            offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_srv.target, sizeof(dns->u.type_srv.target));
        }//end if srv
        else if(dns->dns_type == DNS_TYPE_SOA) {
            offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_soa.name1, sizeof(dns->u.type_soa.name1));
            offset += dump_domain_name(dns_start_ptr, current_ptr + offset, dns->u.type_soa.name2, sizeof(dns->u.type_soa.name2));

            dns->u.type_soa.serial = ntohl(*(u_int32_t *)(current_ptr + offset));
            offset += 4;
            dns->u.type_soa.refresh = ntohl(*(u_int32_t *)(current_ptr + offset));
            offset += 4;
            dns->u.type_soa.retry = ntohl(*(u_int32_t *)(current_ptr + offset));
            offset += 4;
            dns->u.type_soa.expire = ntohl(*(u_int32_t *)(current_ptr + offset));
            offset += 4;
            dns->u.type_soa.minTTL = ntohl(*(u_int32_t *)(current_ptr + offset));
            offset += 4;
        }//end if soa
    }//end if response

    dns->offset = offset;
    return dns;
}//end dump_dns_data

static void dump_dns_entry(struct dns_entry *dns) {
    //in srv record, name has another format
    if(dns->dns_type == DNS_TYPE_SRV && dns->response) {
        printf("    Service: %s\n", dns->u.type_srv.service);
        printf("    Protocol: %s\n", dns->u.type_srv.proto);
        printf("    Name: %s\n", dns->u.type_srv.name);
    }//end if record is srv
    else {
        if(strlen(dns->dns_name) != 0) {
            printf("    Name: %s\n", dns->dns_name);
        }//end if
        else {
            //try type A, query "ghslecstmvfk"
            printf("    Name: <Root>\n");
        }//end else
    }//end else

    //dns type
    printf("    Type: ");
    switch(dns->dns_type) {
        case DNS_TYPE_A: printf("A\n"); break;
        case DNS_TYPE_AAAA: printf("AAAA\n"); break;
        case DNS_TYPE_PTR: printf("PTR\n"); break;
        case DNS_TYPE_CNAME: printf("CNAME\n"); break;
        case DNS_TYPE_TXT: printf("TXT\n"); break;
        case DNS_TYPE_MX: printf("MX\n"); break;
        case DNS_TYPE_NS: printf("NS\n"); break;
        case DNS_TYPE_LOC: printf("LOC\n"); break;
        case DNS_TYPE_SRV: printf("SRV\n"); break;
        case DNS_TYPE_SOA: printf("SOA\n"); break;
        case DNS_TYPE_ANY: printf("ANY\n"); break;
        default:
            printf("%u(Unknown)\n", dns->dns_type);
            return;
    }//end switch

    //dns class
    printf("    Class: ");
    switch(dns->dns_class) {
        case DNS_CLASS_IN: printf("IN\n"); break;
        default:
            printf("%u(Unknown)\n", dns->dns_class);
            return;
    }//end switch

    if(dns->response) {
        printf("    TTL: %d\n", dns->dns_ttl);
        printf("    Data Length: %u\n", dns->dns_data_length);

        if(dns->dns_type == DNS_TYPE_A || dns->dns_type == DNS_TYPE_AAAA) {
            //because of union
            printf("    Address: %s\n", dns->u.type_a.addr);
        }//end if a or aaaa
        else if(dns->dns_type == DNS_TYPE_PTR) {
            printf("    Name: %s\n", dns->u.type_ptr.name);
        }//end if ptr
        else if(dns->dns_type == DNS_TYPE_CNAME) {
            printf("    CNAME: %s\n", dns->u.type_cname.cname);
        }//end if cname
        else if(dns->dns_type == DNS_TYPE_TXT) {
            printf("    TXT Length: %u\n", dns->u.type_txt.txt_len);
            printf("    TXT: %s\n", dns->u.type_txt.txt);
        }//end if txt
        else if(dns->dns_type == DNS_TYPE_MX) {
            printf("    Preference: %u\n", dns->u.type_mx.preference);
            printf("    Mail Exchange: %s\n", dns->u.type_mx.name);
        }//end if mx
        else if(dns->dns_type == DNS_TYPE_NS) {
            printf("    Name Server: %s\n", dns->u.type_ns.name);
        }//end if nx
        else if(dns->dns_type == DNS_TYPE_LOC) {
            printf("    Version: %u\n", dns->u.type_loc.version);
            printf("    Size: %u\n", dns->u.type_loc.size);
            printf("    Horizontal: %u\n", dns->u.type_loc.horizontal);
            printf("    Vertial: %u\n", dns->u.type_loc.vertial);
            printf("    Latitude: %u\n", dns->u.type_loc.latitude);
            printf("    Longitude: %u\n", dns->u.type_loc.longitude);
            printf("    Altitude: %u\n", dns->u.type_loc.altitude);
        }//end if loc
        else if(dns->dns_type == DNS_TYPE_SRV) {
            //some field already parsed before
            printf("    Priority: %u\n", dns->u.type_srv.priority);
            printf("    Weight: %u\n", dns->u.type_srv.weight);
            printf("    Port: %u\n", dns->u.type_srv.port);
            printf("    Target: %s\n", dns->u.type_srv.target);
        }//end if srv
        else if(dns->dns_type == DNS_TYPE_SOA) {
            printf("    Primary Name Server: %s\n", dns->u.type_soa.name1);
            printf("    Responsible Authority\'s Mailbox: %s\n", dns->u.type_soa.name2);
            printf("    Serial Number: %u\n", dns->u.type_soa.serial);
            printf("    Refresh Interval: %u\n", dns->u.type_soa.refresh);
            printf("    Retry Interval: %u\n", dns->u.type_soa.retry);
            printf("    Expire Time: %u\n", dns->u.type_soa.expire);
            printf("    Minimum TTL: %u\n", dns->u.type_soa.minTTL);
        }//end if soa
    }//end if response

}//end dump_dns_entry

static void free_dns_entry(struct dns_entry *dns) {
    if(dns) {
        memset(dns, 0, sizeof(struct dns_entry));
        free(dns);
    }//end if
}//end free_dns_entry