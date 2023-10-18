#ifndef arp_CT_H
#define arp_CT_H

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include<sys/time.h>
#include "sr_rt.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_protocol.h"



struct arp_cache
{ //一项条目
    uint32_t ip;
    unsigned char mac[ETHER_ADDR_LEN];
    struct arp_cache *next;
    struct arp_cache *prev;
    time_t save_time;
    int flag;
};

struct arp_cache *arp_check_mac_by_ip(struct sr_instance *sr,uint32_t ip);

void update_arp_cache(struct sr_instance *sr,struct sr_arphdr *arp_hdr);

void update_cache_transmit(struct sr_instance *sr);

#endif /* --  arp_CT_H -- */
