#include "sr_buffer.h"


void add_packet_to_buffer(struct sr_instance* sr,uint8_t *packet,unsigned int len){
     
    printf("Add packet to buffer\n");
    struct sr_buffer *buffer_entry = sr->sr_buffer;
    printf("test malloc0");
    struct sr_buffer *last_entry = NULL;
    printf("test malloc1");
    struct sr_buffer *add_entry = malloc(sizeof(struct sr_buffer));
    printf("test malloc2");
    if(!buffer_entry){// no packet in buffer
        add_entry->packet = packet;
        add_entry->len = len;
        add_entry->next = NULL;
        add_entry->prev = NULL;
        sr->sr_buffer = add_entry;
        printf("No packer in buffer before, Add packet into header\n");
        struct ip *ip_hdr = (struct ip*)(add_entry->packet + sizeof(struct sr_ethernet_hdr));
        print_IP(ip_hdr->ip_dst.s_addr);
    }else{//there are packet in buffer
        printf("there are packets in buffer!\n");
        int cnt =0;
        while (buffer_entry) /*buffer entry = NULL stop*/
        {
            last_entry = buffer_entry;
            buffer_entry = buffer_entry->next;
            printf("cnt is %d\n", cnt);
            cnt++;
        }
        add_entry->packet = packet;
        add_entry->len =len;
        add_entry->next = NULL;
        add_entry->prev = NULL;
        
        last_entry->next = add_entry;
        add_entry->prev = last_entry;
        printf("Add packet to the end of buffer\n");
        struct ip *ip_hdr = (struct ip*)(add_entry->packet + sizeof(struct sr_ethernet_hdr));
        print_IP(ip_hdr->ip_dst.s_addr);
        printf("length of buffer is %d\n", cnt);
    }
}

struct in_addr get_next_hop(struct sr_instance *sr, struct ip *ip_hdr)
{
    struct sr_rt *best_match_router = longest_prefix_match_router(sr, ip_hdr->ip_dst);/*return bext match rtable entry*/
    struct in_addr next_hop_ip = best_match_router->gw; /*best match next hop ip*/
    if (next_hop_ip.s_addr == 0x00000000)
    {
        next_hop_ip = ip_hdr->ip_dst;
    }
    return next_hop_ip;
}

/*After receiving ARP reply, sending packet with arp reply ip in buffer in order(from header)*/
void send_buffer_packet(struct sr_instance *sr, uint32_t ip){

    struct sr_buffer *buffer_entry = sr->sr_buffer;
    struct sr_buffer* pre_entry = NULL; /*record buffer entry的前一个entry*/
    int cnt =0;
    while (buffer_entry)/*traverse buffer form hdr*/
    {
        pre_entry = buffer_entry->prev;
        /* buffer_entry.packet 是之前存入的没找到mac的IP Packet*/
        struct sr_ethernet_hdr* eth = (struct sr_ethernet_hdr*)buffer_entry->packet;
        struct ip *ip_hdr = (struct ip*)(buffer_entry->packet + sizeof(struct sr_ethernet_hdr));
        print_IP(ip);
        print_IP(ip_hdr->ip_dst.s_addr);
        struct in_addr next_hop= get_next_hop(sr,ip_hdr);
        print_IP(next_hop.s_addr);
        if(next_hop.s_addr == ip){ /*ARP reply ip is the IP packet in buffer, remove from buffer and ip forwarding*/
            /*remove the entry in buffer*/
            printf("ARP reply ip = ip packet to be sent, we need to remove t from buffer\n");
            handle_packets_IP_ICMP(sr, buffer_entry->packet,buffer_entry->len);
            if (!pre_entry)/*buffer entry is first*/
            {
                // printf("test19\n");
                sr->sr_buffer = buffer_entry->next;
            }else if (!buffer_entry->next)/*last*/
            {
                pre_entry->next = NULL;
            }else/*middle*/
            {
                pre_entry->next = buffer_entry->next;
                buffer_entry = buffer_entry->next;
                buffer_entry->prev = pre_entry;
            }
           
        }
        buffer_entry = buffer_entry->next;
        cnt++;
    }
    printf("cnt in send buffer function is %d\n", cnt);
    printf("I go out of send buffer packet function!\n");
}

void handle_packets_IP_ICMP(struct sr_instance *sr, uint8_t* packet, unsigned int len)
{ 
    printf("enter handle packets ip icmp\n");
    // return;
    struct sr_ethernet_hdr* eth = (struct sr_ethernet_hdr*)packet;
    struct ip *ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
    uint8_t eth_dest_address[ETHER_ADDR_LEN]; /*Received Packet Eth dest address*/
    memcpy(eth_dest_address, eth->ether_dhost, ETHER_ADDR_LEN); //eth报文的dest地址，如果是arp request, dest是询问发向的地址; 如果是reply, dest是回复返回的地址
    uint8_t eth_sor_address[ETHER_ADDR_LEN]; /*Received Packet Eth source address*/
    memcpy(eth_sor_address, eth->ether_shost, ETHER_ADDR_LEN); //eth报文的sor地址，如果是arp request, sor是询问发起的地址; 如果是reply, sor是回复发起的地址
    struct in_addr ip_dest = ip_hdr->ip_dst;
    struct in_addr ip_sorc = ip_hdr->ip_src;
    print_IP(ip_dest.s_addr);
    // uint16_t ip_len = SWAP_UINT16(ip_hdr-->ip_len);
    // unsigned int len = ip_len + sizeof(struct sr_ethernet_hdr);
    printf("*** -> re-send packet of length %d \n",len);

    
    /*Step1: If destination is one of our router*/
    struct sr_if *if_list = is_dest_me(sr, ip_hdr->ip_dst.s_addr);/*return the corresponding router's interface*/
    if (if_list)/*destiniation is router*/
    {
        printf("IP packet dest is router.\n");
        struct sr_icmp *icmp_hdr;
        icmp_hdr = (struct icmp_hdr*)(ip_hdr + 1);
        /*IF packet is ICMP echo Request*/
        if (ip_hdr->ip_p == IPPROTO_ICMP && icmp_hdr->icmp_type == ICMP_REQUEST)
        {
            ip_hdr->ip_ttl = 64;
            printf("IP Packet with ICMP echo Request.\n");
                /*upate Eth header to next hop mac address*/
            memcpy(eth->ether_dhost, eth_sor_address, ETHER_ADDR_LEN);
            struct sr_if* out_if = sr_get_interface(sr, if_list);
            memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
            /*ICMP reply*/
            /*Send ICMP rely to original sender*/
            /*update ip header*/
            ip_hdr->ip_dst = ip_sorc;
            ip_hdr->ip_src = ip_dest;
            /* Change Type to Reply */
            icmp_hdr->icmp_type = ICMP_REPLY;
            icmp_hdr->icmp_code = 0;
            /*Upddate Checksum*/
            icmp_hdr->icmp_checksum = 0;
            uint16_t new_checksum  = htons(cksum((const char *)icmp_hdr, len-sizeof(struct sr_ethernet_hdr) - sizeof(struct ip)));
            icmp_hdr->icmp_checksum = new_checksum;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = htons(cksum((const char *)ip_hdr, ip_hdr->ip_hl * 4));
            
            // printf("test23\n");
            sr_send_packet(sr, sr, len, out_if->name);
            
            printf("Send ICMP echo Reply back to original sneder ip");
        }else{/*otherwise discard*/
            printf("Discard the packet.\n");
        }
    }else{/* Dest is not a router, must forward continously witout doing anything extra*/
        printf("IP packer dest is not router.\n");
        /*Step2: Decremnet TTL by 1*/
        ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
        if (ip_hdr->ip_ttl != 0)
        {
            struct sr_rt *best_match_router = longest_prefix_match_router(sr, ip_hdr->ip_dst);/*return bext match rtable entry*/
            struct in_addr next_hop_ip = best_match_router->gw; /*best match next hop ip*/
            // printf("next hop ip is %s\n", inet_ntoa(next_hop_ip));
            struct sr_if *next_if = sr_get_interface(sr, best_match_router->interface);/*best match next interface*/
            struct arp_cache* temp = malloc(sizeof(struct arp_cache));
            if (next_hop_ip.s_addr == 0x00000000)
            {
                temp = arp_check_mac_by_ip(sr,ip_hdr->ip_dst.s_addr);
                memcpy(eth->ether_dhost, temp->mac , ETHER_ADDR_LEN);
                next_hop_ip = ip_hdr->ip_dst;
            }else{
                temp = arp_check_mac_by_ip(sr,next_hop_ip.s_addr);
                memcpy(eth->ether_dhost, temp->mac, ETHER_ADDR_LEN);
            }
            if (temp->flag==0)/*No corresponding mac in ARP cache*/
            {
                // printf("test12\n");
                /*Buffer any packet until Receive ARP Reply*/
               
                /*Send ARP Request broadcast, packet is ip packet, so rebuild a new arp packet*/
                int len_arp_request = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
                uint8_t *arp_request_packet = malloc(len_arp_request);
                struct sr_ethernet_hdr *eth_new = (struct sr_ethernet_hdr *)arp_request_packet;
                struct sr_arphdr *arp_hdr_new = (struct sr_arphdr *)(arp_request_packet + sizeof(struct sr_ethernet_hdr));
                /*ADD new ethernet header*/
                
                // char *outgoing_if = best_match_router->interface;
                // struct sr_if * out_interface = sr_get_interface(sr, outgoing_if); /*Given an interface name return the interface record or 0 if it doesn't exist.*/
                eth_new->ether_type = htons(ETHERTYPE_ARP);
                for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                    eth_new->ether_dhost[i] = 0xFF; 
                    eth_new->ether_shost[i] = next_if->addr[i]; // set source to be outgoing if
                    arp_hdr_new->ar_tha[i] = 0x00;
                }
                
                /*ADD new arp header*/
                arp_hdr_new->ar_hrd = htons(ARPHDR_ETHER);
                arp_hdr_new->ar_pro = htons(ETHERTYPE_IP);
                arp_hdr_new->ar_hln = ETHER_ADDR_LEN;
                arp_hdr_new->ar_pln = PROTO_ADDR_LEN;
                arp_hdr_new->ar_op = htons(ARP_REQUEST);
                memcpy(arp_hdr_new->ar_sha, eth_new->ether_shost, ETHER_ADDR_LEN);
                arp_hdr_new->ar_sip = next_if->ip;
                arp_hdr_new->ar_tip = next_hop_ip.s_addr;
                add_packet_to_buffer(sr,packet,len);
                sr_send_packet(sr, arp_request_packet, len_arp_request, next_if->name);
                free(arp_request_packet);
                printf("Recieved IP packet, but not find mac, Asend ARP broadcast.\n");
            }else if(temp->flag ==1){/*Find mac in ARP Cache, IP Forwarding in order in buffer*/
                // if (packet_in_buffer(sr, ip_hdr->ip_dst))/*Already In buffer, wait in order*/
                // {
                //     add_packet_to_buffer(packet,len);
                //     printf("There are packets waiting for the same mac, add buffer to waiting to maintain the order\n");
                // }else{/*Not in buffer, I'm the first can find mac current, drectly forwarding*/
                    printf("IP packet is the first find this mac currently, directly IP forwarding\n");
                    memcpy(eth->ether_shost, next_if->addr, ETHER_ADDR_LEN);
                    struct sr_icmp *icmp_hdr = (struct sr_icmp *) (ip_hdr + 1); 
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = htons(cksum((const char *)ip_hdr, ip_hdr->ip_hl * 4));
                    /*IP forwarind*/
                    sr_send_packet(sr, packet, len, next_if->name);
                    // sr_print_eth_hdr(packet);
                    // sr_print_ip_hdr(packet);
                    printf("IP Forwarding\n");
                    // free(best_match_router);
                // }
            }
            free(temp);
        }else{
            /* discard */
            printf("IP packet TTL=0, dscard");
        }
        }


}


/*Whether IP packet in the buffer*/
int packet_in_buffer(struct sr_instance *sr, struct in_addr ip_dest){
    struct sr_buffer* buffer_entry = sr->sr_buffer;
    while (buffer_entry)
    {
        struct ip* ip_hdr_buffer = (struct ip*)(buffer_entry->packet + sizeof(struct sr_ethernet_hdr));
        if (ip_dest.s_addr == ip_hdr_buffer->ip_dst.s_addr)
        {
            printf("the ip is in\n");
            print_IP(ip_dest.s_addr);
            return 1;
        }
        buffer_entry = buffer_entry->next;
    }
    return 0;
}



