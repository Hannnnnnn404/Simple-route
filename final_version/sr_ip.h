#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "arp_cache.h"

#include <sys/socket.h>
#include <netinet/in.h>


#ifndef sr_IP_H
#define sr_IP_H

//char *best_match_interface(char *longest_match_if, struct sr_rt *rtable, struct in_addr if_ip);

struct sr_if *is_dest_me(struct sr_instance *sr, uint32_t dest_ip);

//uint16_t cksum(uint16_t *buf, int count);
int cksum(const char *header, int length);

struct sr_rt *longest_prefix_match_router(struct sr_instance* sr, struct in_addr ip_dest);

void print_IP(uint32_t ip);

#endif /* --  sr_IP_H -- */