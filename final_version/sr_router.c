/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 * #1693354266
 * 
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include <netinet/in.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include <string.h>

#include "arp_cache.h"
#include "sr_ip.h"
// #include "sr_buffer.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

struct sr_rt *search_route_table(struct sr_instance *sr, struct in_addr ip);

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    sr->arp_cache = NULL;
    sr->sr_buffer = NULL;
    
    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr, 
        uint8_t *packet/* lent */,
        unsigned int len,
        char *interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);


    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *) packet; /*Ethernet header*/
    uint16_t EType = ntohs(eth->ether_type); /*Ethernet Type*/
    struct sr_if *if_come = sr_get_interface(sr, interface); /*coming interface*/
    uint32_t come_if_ip = if_come->ip; /*coming interface ip*/
    unsigned char come_if_mac[ETHER_ADDR_LEN]; /*come mac = ethernet address of coming interface*/
    memcpy(come_if_mac, if_come->addr, ETHER_ADDR_LEN);
    uint8_t eth_dest_address[ETHER_ADDR_LEN]; /*Received Packet Eth dest address*/
    memcpy(eth_dest_address, eth->ether_dhost, ETHER_ADDR_LEN); //eth报文的dest地址，如果是arp request, dest是询问发向的地址; 如果是reply, dest是回复返回的地址
    uint8_t eth_sor_address[ETHER_ADDR_LEN]; /*Received Packet Eth source address*/
    memcpy(eth_sor_address, eth->ether_shost, ETHER_ADDR_LEN); //eth报文的sor地址，如果是arp request, sor是询问发起的地址; 如果是reply, sor是回复发起的地址



    switch (EType)
    {
        case ETHERTYPE_ARP:
        {   
            struct sr_arphdr *arp_hdr; /*ARP header*/
            arp_hdr = (struct sr_arphdr*)(uint8_t *)(packet + sizeof(struct sr_ethernet_hdr));
            uint16_t arp_type = ntohs(arp_hdr->ar_op);
            // printf("arp hrd type is %u \n", ntohs(arp_hdr->ar_op));
            uint32_t arp_target_ip = htonl(arp_hdr->ar_tip); //arp报文的target ip, 如果是request,target_ip是要询问的目标ip; 如果是reply,target_ip是回复给询问的ip
            uint32_t arp_sender_ip = htonl(arp_hdr-> ar_sip); //arp报文的sender ip, 如果是request,sender_ip是要发起询问的ip; 如果是reply,sender_ip是给出回复的ip
            unsigned char arp_target_mac[ETHER_ADDR_LEN];
            memcpy(arp_target_mac, arp_hdr->ar_tha, ETHER_ADDR_LEN); //arp报文的target mac, 如果是request,target_mac是要询问的目标mac; 如果是reply, target_mac是回复给询问的mac
            unsigned char arp_sender_mac[ETHER_ADDR_LEN];
            memcpy(arp_sender_mac, arp_hdr->ar_sha, ETHER_ADDR_LEN); //arp报文的sender mac, 如果是request,sender_mac是要发起询问的mac; 如果是reply, sender_mac是给出回复给的mac
            
            update_arp_cache(sr,arp_hdr);//update cache whenever ARP request or reply
            if (arp_type == ARP_REQUEST){
                //Check ARP Cache
                struct sr_if* if_list = is_dest_me(sr, ntohl(arp_target_ip));
                struct arp_cache* temp = arp_check_mac_by_ip(sr,ntohl(arp_target_ip));
                if(temp->flag == 1 || if_list){//从ARP表中查找到,原路返回
                    //ARP REPLY
                    printf("Send Reply from router ARP Cache to interface: %s\n", interface);
                    memcpy(eth->ether_dhost, eth_sor_address, ETHER_ADDR_LEN);
                    memcpy(eth->ether_shost, if_come->addr, ETHER_ADDR_LEN);
                    arp_hdr->ar_op = htons(ARP_REPLY);
                    arp_hdr->ar_tip = arp_sender_ip;
                    arp_hdr->ar_sip = come_if_ip;
                    memcpy(arp_hdr->ar_tha, arp_sender_mac, ETHER_ADDR_LEN);
                    memcpy(arp_hdr->ar_sha, if_come->addr, ETHER_ADDR_LEN);
                    //send reply to sender
                    sr_send_packet(sr,packet, len, interface);//interface不变 
                    // printf("test24\n");
                }
                else if (temp->flag == 0){
                    printf("Not find mac in router ARP Cache, Continously Send ARP Request by broadcast from interface %s to host\n", interface);
                    // print_IP(ntohl(arp_target_ip));
                    //ARP表查不到(never saved or discrad)target ip对应的mac, ARP REQUEST广播
                    /*get outgoing interface by rt table*/
                    struct in_addr target_ip_addr;
                    target_ip_addr.s_addr = ntohl(arp_target_ip);/*in rtable, the format of ip is struct in_addr,only has one attribut s_addr represent ip*/
                    struct sr_rt *best_match_router;
                    best_match_router = longest_prefix_match_router(sr, target_ip_addr);/*return bext match rtable entry*/
                    char *outgoing_if = best_match_router->interface;
                    struct sr_if * out_interface = sr_get_interface(sr, outgoing_if); /*Given an interface name return the interface record or 0 if it doesn't exist.*/
                    // printf("routing node interface is %s\n", out_interface);
                    // printf("test8\n");
                    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                        eth->ether_dhost[i] = 0xFF; 
                        eth->ether_shost[i] = out_interface->addr[i]; // set source to be outgoing if
                        arp_hdr->ar_tha[i] = 0x00;
                    }
                   
                    arp_hdr->ar_op = htons(ARP_REQUEST);
                    arp_hdr->ar_tip = ntohl(arp_target_ip);
                    arp_hdr->ar_sip = out_interface->ip;
                    memcpy(arp_hdr->ar_sha, out_interface->addr, ETHER_ADDR_LEN);
                    // printf("test9\n");
                    sr_send_packet(sr, packet,len, out_interface->name);
                    //free(best_match_router);
                }
            } else if (arp_type == ARP_REPLY)
            {
                printf("ARP reply\n");
                /* Send corresponding packet in buffer in order */
                send_buffer_packet(sr, arp_hdr->ar_sip);
                
                printf("send buffer packet!\n");
            }
            else
            {
                printf("no match ARP!\n");
            }    
        }   
        break;
        case ETHERTYPE_IP:
        {
            struct ip *ip_hdr;
            ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
            struct in_addr ip_dest = ip_hdr->ip_dst;
            struct in_addr ip_sorc = ip_hdr->ip_src;
            
            
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
                    struct sr_if* out_if = sr_get_interface(sr, interface);
                    memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
                    /*ICMP reply*/
                    // printf("test22\n");
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
                    sr_send_packet(sr, packet, len, out_if->name);
                    
                    // printf("Send ICMP echo Reply back to original sneder ip");
                }else{/*otherwise discard*/
                    // printf("Discard the packet.\n");
                }
            }else{/* Dest is not a router, must forward continously witout doing anything extra*/
                // printf("IP packer dest is not router.\n");
                /*Step2: Decremnet TTL by 1*/
                ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
                if (ip_hdr->ip_ttl != 0)
                {
                    // printf("test10\n");
                    /*calculate checksum and save result*/
                    
                    /*Look up rtable, find best match next-hop IP and interface*/ 
                    // print_IP(ip_hdr->ip_dst.s_addr);
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
                        // sr_print_eth_hdr(arp_request_packet);
                        // sr_print_arp_hdr(arp_request_packet);
                        free(arp_request_packet);
                        printf("Recieved IP packet, but not find mac, Asend ARP broadcast.\n");
                    }else if(temp->flag ==1){/*Find mac in ARP Cache, IP Forwarding in order in buffer*/
                        if (packet_in_buffer(sr, ip_hdr->ip_dst))/*Already In buffer, wait in order*/
                        {
                            printf("There are packets waiting for the same mac, add buffer to waiting to maintain the order\n");
                            add_packet_to_buffer(packet,len);     
                        }else{/*Not in buffer, I'm the first can find mac current, drectly forwarding*/
                            printf("IP packet is the first find this mac currently, directly IP forwarding\n");
                            memcpy(eth->ether_shost, next_if->addr, ETHER_ADDR_LEN);
                            // print_hardware_address(eth->ether_shost, 6);
                            // print_hardware_address(eth->ether_dhost, 6);
                            struct sr_icmp *icmp_hdr = (struct sr_icmp *) (ip_hdr + 1);
                            // printf("\t\t\tICMP Type: %01x\n", icmp_hdr->icmp_type);
                            // printf("\t\t\tICMP Code: %01x\n", icmp_hdr->icmp_code);
                            // unsigned short checksum = SWAP_UINT16(icmp_hdr->icmp_checksum);
                            // printf("\t\t\tICMP Checksum: %02x\n", checksum);
                            /*update checksum*/
                            ip_hdr->ip_sum = 0;
                            ip_hdr->ip_sum = htons(cksum((const char *)ip_hdr, ip_hdr->ip_hl * 4));
                            /*IP forwarind*/
                            sr_send_packet(sr, packet, len, next_if->name);
                            // sr_print_eth_hdr(packet);
                            // sr_print_ip_hdr(packet);
                            printf("IP Forwarding\n");
                            // free(best_match_router);
                        }
                    }
                    free(temp);
                }else{
                    /* discard */
                    printf("IP packet TTL=0, dscard");
                }
            }
            update_cache_transmit(sr);
        }    
        break;
        default:
            printf("no match header!\n");
            break;
    }
}/* end sr_ForwardPacket */



void print_hardware_address(uint8_t *addr_ptr, int len){
    for (int i = 0; i < len; i++) {
        printf("%01x", addr_ptr[i]);
        if (i != len - 1) 
            printf(":");
    }
    printf("\n");
}

void print_ip_addr(uint32_t ip_32){
    struct in_addr ip_addr_struct;
    ip_addr_struct.s_addr = ip_32; 
    printf("%s\n", inet_ntoa(ip_addr_struct)); // method to convert struct in_addr to IP string
}

void sr_print_eth_hdr(uint8_t * p) {
	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) p;
	uint16_t eth_type = eth_hdr->ether_type;
	eth_type = SWAP_UINT16(eth_type);
	// ethernet header
	printf("\tEthernet Header Destination Address: ");
    print_hardware_address(eth_hdr->ether_dhost, ETHER_ADDR_LEN);
	printf("\tEthernet Header Source Address: ");
    print_hardware_address(eth_hdr->ether_shost, ETHER_ADDR_LEN);
	printf("\tType of next protocol: %04x\n", eth_type);

	// ARP/IP
	p = p + sizeof(struct sr_ethernet_hdr);
	if (eth_type == ETHERTYPE_ARP) {
		sr_print_arp_hdr(p);
		p = p + sizeof(struct sr_arphdr);
	}
	else if (eth_type == ETHERTYPE_IP) {
		sr_print_ip_hdr(p);
		p = p + sizeof(struct  ip);
	}

}

void sr_print_arp_hdr(uint8_t * p) {
	struct sr_arphdr * arp_hdr  = (struct sr_arphdr *) p;
	unsigned short hw_addr_format = SWAP_UINT16(arp_hdr->ar_hrd);
	unsigned short pr_addr_format = SWAP_UINT16(arp_hdr->ar_pro);
	printf("\t\tARP hardware address format: %02x\n", hw_addr_format);
	printf("\t\tARP protocol address format: %02x\n", pr_addr_format);
	printf("\t\tARP hardware address length: %u\n", arp_hdr->ar_hln);
	printf("\t\tARP protocol address length: %u\n", arp_hdr->ar_pln);
	unsigned short opcode = SWAP_UINT16(arp_hdr->ar_op);
	printf("\t\tARP opcode: %02x\n", opcode);
    // ARP sender addresses
	printf("\t\tARP sender hardware address: ");
    print_hardware_address(arp_hdr->ar_sha, ETHER_ADDR_LEN);
	printf("\t\tARP sender IP address: ");
    print_ip_addr(arp_hdr->ar_sip);
    // ARP target addresses
	printf("\t\tARP target hardware address: ");
    print_hardware_address(arp_hdr->ar_tha, ETHER_ADDR_LEN);
	printf("\t\tARP target IP address: ");
    print_ip_addr(arp_hdr->ar_tip);
}

void sr_print_ip_hdr(uint8_t * p) {
	struct ip * ip_hdr = (struct ip *) p; 
	printf("\t\tIP Type of Service: %01x\n", ip_hdr->ip_tos);
	unsigned short len_of_ip_pkt = SWAP_UINT16(ip_hdr->ip_len);
	printf("\t\tIP Packet Total Length: %02x\n", len_of_ip_pkt);
	unsigned short ip_iden = SWAP_UINT16(ip_hdr->ip_id);
	printf("\t\tIP Packet ID: %02x\n", ip_iden);
	unsigned short frag_off = SWAP_UINT16(ip_hdr->ip_off);
	printf("\t\tIP Fragment Offset: %02x\n", frag_off);
	printf("\t\tIP TTL: %01x\n", ip_hdr->ip_ttl);
	printf("\t\tIP Protocol: %01x\n", ip_hdr->ip_p);
	unsigned short checksum = SWAP_UINT16(ip_hdr->ip_sum);
	printf("\t\tIP Checksum: %02x\n", checksum);
	printf("\t\tIP Source Address: %s\n", inet_ntoa(ip_hdr->ip_src));
	printf("\t\tIP Destination Address: %s\n", inet_ntoa(ip_hdr->ip_dst));
    if (ip_hdr->ip_p == IPPROTO_ICMP)
        sr_print_icmp_hdr(ip_hdr);
}

void sr_print_icmp_hdr(struct ip* ip_hdr){
    struct sr_icmp *icmp_hdr = (struct sr_icmp *) (ip_hdr + 1);
    printf("\t\t\tICMP Type: %01x\n", icmp_hdr->icmp_type);
    printf("\t\t\tICMP Code: %01x\n", icmp_hdr->icmp_code);
    unsigned short checksum = SWAP_UINT16(icmp_hdr->icmp_checksum);
    printf("\t\t\tICMP Checksum: %02x\n", checksum);
    // unsigned short identifier = SWAP_UINT16(icmp_hdr->icmp_id);
    // printf("\t\t\tICMP Identifier: %02x\n", identifier);
    // unsigned short seq_num = SWAP_UINT16(icmp_hdr->icmp_sn);
    // printf("\t\t\tICMP Sequence Number: %02x\n", seq_num);
}