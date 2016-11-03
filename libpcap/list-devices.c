//
//  list-devices.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/03.
//
//  List all device addresses.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#else /* if BSD */
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#endif /* if linux */

int main(int argc, char *argv[]) {

    pcap_if_t *devices = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    //get all devices
    if(-1 == pcap_findalldevs(&devices, errbuf)) {
        fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
        exit(1);
    }//end if

    //list all device
    for(pcap_if_t *d = devices ; d ; d = d->next) {
        printf("Device: %s\n", d->name);
        if(d->description) {
            printf("    Description: %s\n", d->description);
        }//end if
        printf("    Loopback: %s\n",(d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
#ifdef PCAP_IF_UP
        printf("    Up: %s\n",(d->flags & PCAP_IF_UP) ? "yes" : "no");
#endif /* if PCAP_IF_UP */
#ifdef PCAP_IF_RUNNING
        printf("    Running: %s\n",(d->flags & PCAP_IF_RUNNING) ? "yes" : "no");
#endif /* if PCAP_IF_RUNNING */

        //list all address
        for(struct pcap_addr *a = d->addresses ; a ; a = a->next) {
            sa_family_t family = a->addr->sa_family;
            char ntop_buf[256];

            if(family == AF_INET || family == AF_INET6) {
                if(a->addr) {
                    printf("        Address: %s\n",
                           inet_ntop(family, &((struct sockaddr_in *)a->addr)->sin_addr, ntop_buf, sizeof(ntop_buf)));
                }//end if
                if(a->netmask) {
                    printf("        Netmask: %s\n",
                           inet_ntop(family, &((struct sockaddr_in *)a->netmask)->sin_addr, ntop_buf, sizeof(ntop_buf)));
                }//end if
                if(a->broadaddr) {
                    printf("        Broadcast Address: %s\n",
                           inet_ntop(family, &((struct sockaddr_in *)a->broadaddr)->sin_addr, ntop_buf, sizeof(ntop_buf)));
                }//end if
                if(a->dstaddr) {
                    printf("        Destination Address: %s\n",
                           inet_ntop(family, &((struct sockaddr_in *)a->dstaddr)->sin_addr, ntop_buf, sizeof(ntop_buf)));
                }//end if
            }//end else

#ifdef AF_LINK
            else if(family == AF_LINK && a->addr) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)a->addr;
                if (sdl->sdl_family == AF_LINK && sdl->sdl_alen == ETHER_ADDR_LEN) {
                    printf("        Link address: %s\n", ether_ntoa((const struct ether_addr *)(sdl->sdl_data + sdl->sdl_nlen)));
                    //printf("        Link address: %s\n", ether_ntoa((const struct ether_addr *)LLADDR(sdl)));
                }//end if
            }//end if
#elif AF_PACKET
            else if(family == AF_PACKET && a->addr) {
                struct sockaddr_ll *sll = (struct sockaddr_ll *)a->addr;
                if (sll->sll_family == AF_PACKET && sll->sll_halen == ETHER_ADDR_LEN) {
                    printf("        Link address: %s\n", ether_ntoa((const struct ether_addr *)sll->sll_addr));
                }//end if
            }//end if
#endif

            printf("\n");
        }//end for
    }//end for

    //free
    pcap_freealldevs(devices);

    return 0;
}//end main
