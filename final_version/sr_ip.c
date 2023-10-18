#include "sr_ip.h"

/*If the destination is one of my interface. Yes, return interface. No return NULL*/
struct sr_if *is_dest_me(struct sr_instance *sr, uint32_t dest_ip){
    struct sr_if *interface_list = sr->if_list;
    print_IP(dest_ip);
    while (interface_list)
    {
        if (interface_list->ip == dest_ip)
        {
            // printf("Router is dest\n");
            return interface_list;
        }
        interface_list = interface_list->next;
    }
    return NULL;
}

int cksum(const char *header, int length) {
    u_long sum = 0;
    for (int i = 0; i < length; i += 2) {
        u_long tmp = 0;
        tmp += (u_char) header[i] << 8;
        tmp += (u_char) header[i + 1];
        sum += tmp;
    }
    u_short lWord = sum & 0x0000FFFF;
    u_short hWord = sum >> 16;
    u_short checksum = lWord + hWord;
    checksum = ~checksum;
    return checksum;
}

/*Calculate checksum of  IP and ICMP.*/
// uint16_t cksum(uint16_t *buf, int count)
// {
//     register u_int16_t sum = 0;
//     while (count--)
//     {
//         sum += *buf++;
//         if (sum & 0xFFFF0000)
//         {
//             /* carry occurred, so wrap around */
//             sum &= 0xFFFF;
//             sum++;
//         }
//     }
//     return ~(sum & 0xFFFF);
// }

/*Find the match nexthop in rtable with longest prefix match*/
struct sr_rt *longest_prefix_match_router(struct sr_instance* sr, struct in_addr ip_dest){
    // printf("longest prefix match is called\n");
    struct sr_rt *best_next_hop = NULL;
    struct sr_rt *sr_rtable = sr->routing_table;
    struct in_addr longest_match_mask;
    while (sr_rtable)
    {
        
        // print_IP(sr_rtable->dest.s_addr);
        // print_IP(ip_dest.s_addr);
        // printf("mask1 is  %u\n", sr_rtable->dest.s_addr & sr_rtable->mask.s_addr);
        // printf("mask2 is  %u\n", ip_dest.s_addr & sr_rtable->mask.s_addr);
        if ((sr_rtable->dest.s_addr & sr_rtable->mask.s_addr) == (ip_dest.s_addr & sr_rtable->mask.s_addr))
        {
            // printf("best next hop is %u\n", best_next_hop);
            // printf("match\n");
            if (!best_next_hop)/*no previous match*/
            {
                best_next_hop = sr_rtable;
            }else{/*previous matched before*/
                /*compare longest prefix*/
                if (sr_rtable->mask.s_addr > best_next_hop->mask.s_addr)
                {
                    best_next_hop = sr_rtable;
                }
            }
         
        }
        sr_rtable = sr_rtable->next;
    }
    //printf("next sr_rt entry in function is %s\n", sr_rtable->interface);
    // printf("longest prefix interface in function is %s\n", best_next_hop->interface);
    free(sr_rtable);
    return best_next_hop;
}


void print_IP(uint32_t ip)
{
    char *ip_addr;
    struct in_addr ip_addr_struct;
    ip_addr_struct.s_addr = ip;
    ip_addr = inet_ntoa(ip_addr_struct); 
    printf("print ip %s\n", ip_addr);
}

