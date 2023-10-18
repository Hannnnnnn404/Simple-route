#ifndef sr_BUF_H
#define sr_BUF_H
#include <netinet/in.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_ip.h"
#include "arp_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "sr_protocol.h"
#include <sys/socket.h>
#include <inttypes.h>


struct sr_buffer
{
    uint8_t *packet;
    struct sr_buffer *next;
    struct sr_buffer *prev;
    unsigned int len;
};

void add_packet_to_buffer(struct sr_instance* sr, uint8_t *packet, unsigned int len);

void send_buffer_packet(struct sr_instance *sr, uint32_t ip);

int packet_in_buffer(struct sr_instance *sr, struct in_addr ip_dest);

#define SWAP_UINT16(x) (((x) >> 8) |((x) << 8))
#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))

#endif /* --  sr_BUF_H -- */