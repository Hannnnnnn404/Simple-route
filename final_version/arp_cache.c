#include "arp_cache.h"



struct arp_cache *arp_check_mac_by_ip(struct sr_instance *sr, uint32_t ip){/*从arp表中查找对应ip的mac*/
    printf("arp_check_mac_by_ip is called!\n");
    // print_IP(ip);

    struct arp_cache *temp = malloc(sizeof(struct arp_cache));
    struct arp_cache *entry = sr->arp_cache;
    struct arp_cache *pre_entry = NULL;
    int flag= 0;
    while(entry){//存在ARP Tableb
       
        // printf("test4\n");
        // print_IP(entry->ip);
        // print_IP(ip);
        if(entry->ip == ip){// ARP表中某位置查询到
            // printf("test5\n");
            //every time before use saved result, check whether 10s has passed
            struct timeval *tv_end = malloc(sizeof(struct timeval));
            gettimeofday(tv_end, NULL);
            if(tv_end->tv_sec - entry->save_time > 10){//discard
                printf("The saved arp cache entry with ip:%s exists over 10s, discard\n");
                /*remove entry in ARP cache Table*/
                pre_entry = entry->prev;
                if (!pre_entry)/*头*/
                {  
                    printf("head\n");
                    sr->arp_cache = entry->next;
printf("head over1\n");
                    sr->arp_cache->prev = NULL;
                    
                    // arp_cache_hdr->prev = NULL;
                    // entry = entry->next;
                    // entry->prev = NULL;
                    // printf("head over2\n");
                    // arp_cache_hdr = entry;
                    printf("head over\n");
                }else if (!entry->next)/*尾*/
                {
                    printf("tail\n");
                    pre_entry->next = NULL;
                     printf("tail over\n");
                   
                }else /*中*/
                {
                    printf("middle\n");
                    entry = entry->next;
                    entry->prev = pre_entry;
                    pre_entry->next = entry;
                    printf("middle over\n");
                }
            }else{
                flag = 1;
                memcpy(temp->mac, entry->mac, sizeof(entry->mac));
                // print_hardware_address1(temp->mac, 6);
            }
             free(tv_end);
        }else{/*ARP表中没查询到，下一个entry*/
            printf("No find mac in ARP in the current iteration\n"); 
           
        }
        entry = entry->next;
    }
    
    temp->flag = flag;
    printf("I go out of check arp, mac is %u,%d\n", temp->mac,temp->flag);
    // print_hardware_address1(temp->mac,6);

   return temp;   
}



void update_arp_cache(struct sr_instance *sr,struct sr_arphdr* arp_hdr){/*将sender的mac顺便更新到本地arp cache*/
    struct arp_cache* entry = sr->arp_cache; /*arp_cache_hdr 永远指向arp_cache表头*/
    struct arp_cache* last_entry = NULL;
    printf("update cache\n");
    if(entry == NULL){//arp_cache_hdr = null
        entry = malloc(sizeof(struct arp_cache));
        entry->ip = arp_hdr->ar_sip;
        // print_IP(entry->ip);
        memcpy(entry->mac, arp_hdr->ar_sha, sizeof(entry->mac));
        //every time after saving the result, record time
        struct timeval *cur_time = malloc(sizeof(struct timeval));
        gettimeofday(cur_time, NULL); 
        //   printf("test1\n");
        entry->save_time = cur_time->tv_sec;
        entry->next = NULL;//next = NULL
        entry->prev = NULL;
        sr->arp_cache = entry;// head = entry更新表头
      
        printf("No entry in ARP caceh before, add header\n");
        // printf("test2\n");
        
    }else{
       
        while (entry)/*entry tranverse from hdr*/
        {
            // printf("test15\n");
            if(entry->ip == arp_hdr->ar_sip) /*ip already has an mac*/
            {
                // printf("test16\n");
                /*update original entry*/
                memcpy(entry->mac, arp_hdr->ar_sha, sizeof(entry->mac));
                //every time after saving the result, record time
                struct timeval *cur_time = malloc(sizeof(struct timeval));
                gettimeofday(cur_time, NULL); 
                entry->save_time = cur_time->tv_sec;
                printf("IP already in entry, update mac\n");
                return;
            }else/*no such entry*/
            {
                // printf("test17\n");
                if(entry->next == NULL)
                {
                    struct arp_cache *new_entry = malloc(sizeof(struct arp_cache));
                    new_entry->ip= arp_hdr->ar_sip;
                    memcpy(new_entry->mac, arp_hdr->ar_sha, sizeof(new_entry->mac));
                    new_entry->next = NULL;
                    new_entry->prev = entry;;
                    entry->next = new_entry;
                    //every time after saving the result, record time
                    struct timeval *cur_time1 = malloc(sizeof(struct timeval));
                    gettimeofday(cur_time1, NULL); 
                    new_entry->save_time = cur_time1->tv_sec;
                    printf("NO correspoding IP & MAC in ARP Cache, Add new entry\n");
                    // free(new_entry);
                    break;;
                }
                entry = entry->next;
            }
        }
         /*last entry, add new entry at final*/
       
    }
    // printf("check link\n");
    // struct arp_cache *entry1 = arp_cache_hdr;
    // while(entry1)
    // {
    //     print_IP(entry1->ip);
    //     print_hardware_address1(entry1->mac, 6);
    //     entry1 = entry1->next;
    // }
}

void update_cache_transmit(struct sr_instance *sr){
    struct arp_cache* entry = sr->arp_cache;
    while (entry)
    {
        struct timeval *cur_time1 = malloc(sizeof(struct timeval));
        gettimeofday(cur_time1, NULL); 
        entry->save_time = cur_time1->tv_sec;
        entry = entry->next;
    }
    
}

void print_hardware_address1(uint8_t *addr_ptr, int len){
for (int i = 0; i < len; i++) {
    printf("%01x", addr_ptr[i]);
    if (i != len - 1) 
        printf(":");
}
printf("\n");
}