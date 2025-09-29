#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>

#define ether_type_ip 0x0800
#define ether_type_arp 0x0806
#define arp_request 1
#define arp_reply 2

// Tree structure for IPs
typedef struct nod {
    struct route_table_entry *route_entry;
    struct nod *st, *dr;
} TNod, *TArb;

// Packet structure
typedef struct {
	uint32_t next_hop;
	int interface;
	size_t len;
	char *buf;
} packet;

// Singly linked list structure for packets
typedef struct cell {
    packet *info;
    struct cell *urm;
} *TList, TCell;

TArb route_table;
struct arp_table_entry **arp_table;
int arp_table_dim;
uint8_t broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
TList arp_list;

TList init_list() {
    TList list = calloc(1, sizeof(TCell));
    return list; 
}

TList aloc_cell (packet *info) {
    TList aux = calloc(1, sizeof(TCell));
    aux->info = info;
    aux->urm = NULL;
    return aux;
}

void insert_elem_beginning_list(TList *list, packet *elem) {
    TList aux = aloc_cell(elem);
    aux->urm = *list;
    *list = aux;
}

int remove_elem_from_list(TList *list, packet *elem) {
    TList ant, aux;
    
    for (ant = NULL, aux = *list; aux != NULL; ant = aux, aux = aux->urm)
        if (aux->info == elem)
            break;

    if (aux == NULL)
        return 0;

    if (ant)
        ant->urm = aux->urm;
    else 
        *list = aux->urm;

    return 1;
}

// Creating a packet and initializing the corresponding fields
packet *create_packet(uint32_t next_hop, int interface, size_t len, char *buf) {
    packet *pkt = calloc(1, sizeof(packet));
    pkt->next_hop = next_hop;
    pkt->len = len;
    pkt->buf = calloc(len, sizeof(char));
    memcpy(pkt->buf, buf, len);
    pkt->interface = interface;
    return pkt;
}

/* The following 4 functions obtain the header of a protocol of type:
 * ip, arp, icmp or ether
 */
struct iphdr *get_ip_header(char *buf) {
	struct iphdr *ip_header = (struct iphdr *)((struct ether_header *) buf + 1);
	return ip_header; 
}

struct arp_header *get_arp_header(char *buf) {
	struct arp_header *arp_header = (struct arp_header *)((struct ether_header *) buf + 1);
	return arp_header;
}

struct icmphdr *get_icmp_header(char *buf) {
	struct icmphdr *icmp_header = (struct icmphdr *) (((struct iphdr *) ((struct ether_header *)buf + 1)) + 1);
	return icmp_header;
}

struct ether_header *get_ether_header(char *buf) {
	struct ether_header *eth_header = (struct ether_header *) buf;
	return eth_header;
}

// Get the IP as a string (e.g. uint32_t ip = 1...1 1...1 1...1 0...0 => string = "255.255.255.0")
char* get_ip_string_from_ip(uint32_t ip) {
    // Form a group of bits for each 8 bits from the IP
    uint8_t group1_bites = (ip >> 24) & 0xFF;
    uint8_t group2_bites = (ip >> 16) & 0xFF;
    uint8_t group3_bites = (ip >> 8) & 0xFF;
    uint8_t group4_bites = ip & 0xFF;
    
    /* Allocate an ip_string of size 16 (1 char for each digit/dot 
     * + 1 char for the NULL character)
     */
    char* ip_string = calloc(16, sizeof(char));
    
    // Form an ip_string from the 4 groups of bits
    sprintf(ip_string, "%u.%u.%u.%u", group1_bites, group2_bites, group3_bites, group4_bites);

    return ip_string;
}

/* The inverse operation: get the IP starting from string (e.g. string = "255.255.255.0" 
 * => uint32_t ip = 1...1 1...1 1...1 0...0)
 */
uint32_t get_ip_from_ip_string(char* ip_string) {
    uint32_t ip = 0; 

    char* p = strtok(ip_string, ".");
    int no_byte = 1;
    
    while (p != NULL) {
        uint32_t byte = atoi(p) << (32 - 8 * no_byte);
        ip += byte;
        no_byte += 1;        
        p = strtok(NULL, ".");
    }

    return ip;
}

// Get the number of zeros from the end of the mask
int no_of_zeros_from_end(uint32_t mask) {
    int gasit_1 = 0, no_of_zeros = 0;

    for (int i = 0; i < 32 && gasit_1 == 0 ; i++) {
        uint32_t bit = (mask >> i) & 1;
        
        if (bit == 1)
            gasit_1 = 1;
        else 
            no_of_zeros++;
    }

    return no_of_zeros;
}

// Form the tree of IPs
void add_route_entry(TArb arb, uint32_t ip, uint32_t mask, struct route_table_entry *route_entry) {
    int no_of_zeros = no_of_zeros_from_end(mask);

    for (int i = 31; i >= no_of_zeros; i--) {
        uint32_t bit = (ip >> i) & 1;
        
        if (bit == 1) {
            if (!arb->st)
                arb->st = calloc(1, sizeof(TNod));
            arb = arb->st;
            continue;
        }

        if (!arb->dr)
            arb->dr = calloc(1, sizeof(TNod));
        arb = arb->dr;
    }

    arb->route_entry = route_entry;
}

struct route_table_entry *get_longest_prefix(TArb arb, uint32_t ip) {
    struct route_table_entry *longest_prefix = NULL;

    for (int i = 31; i >= 0; i--) {
		if (arb == NULL)
			break;

        uint32_t bit = (ip >> i) & 1;
        
        if (arb->route_entry != NULL)
            longest_prefix = arb->route_entry;
        
        if (bit == 1)
            arb = arb->st;
        else 
            arb = arb->dr;
    }
    
    return longest_prefix;
}

// Debugging function
void print_tree(TArb arb) {
    if (arb == NULL) return;
    
	if (arb->route_entry != NULL)
   		printf("%s\n", get_ip_string_from_ip(arb->route_entry->prefix));
    
    print_tree(arb->st);
    print_tree(arb->dr);
}

// Check if 2 MACs are equal by traversing each octet
int are_mac_equal(uint8_t *mac1, uint8_t *mac2) {
	for (int i = 0; i < 6; i++) {
		if (mac1[i] != mac2[i])
			return 0;
	}
	
	return 1;
}

// Get the entry from the ARP table corresponding to the IP
struct arp_table_entry *get_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table_dim; i++) {
		if (arp_table[i]->ip == ip) 
			return arp_table[i];
	}
	
	return NULL;
}

/* Check if there is an entry in the ARP table corresponding to the IP and otherwise, create it,
 * resizing the ARP table
 */
void add_in_arp_table(uint32_t ip, uint8_t *mac) {
	struct arp_table_entry *exists = get_arp_entry(ip);
	
	if (exists)
		return;

	struct arp_table_entry *arp_entry = calloc(1, sizeof(struct arp_table_entry));
	arp_entry->ip = ip;
	
	for (int i = 0; i < 6; i++)
		arp_entry->mac[i] = mac[i];
	
	arp_table = realloc(arp_table,(arp_table_dim + 1) * sizeof (struct arp_table_entry *));
	arp_table_dim += 1;
	arp_table[arp_table_dim - 1] = arp_entry;
}

// Check if the packet is addressed to a MAC
int is_addresed_to_me(uint8_t *mac_dest, uint8_t *mac_router) {
	int check = are_mac_equal(mac_dest, mac_router);
	
	if (check == 1)
		return 1;
	
	check = are_mac_equal(mac_dest, broadcast_mac);

	return check;
}

// Get the string associated with a MAC
char *get_mac_string(uint8_t *mac) {
	char *hex_string = calloc(18, sizeof(char));
	sprintf(hex_string, "%02x.%02x.%02x.%02x.%02x.%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return hex_string;
}

void handle_icmp(int interface, size_t len, char *buf, uint8_t type) {
	size_t dimension = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 64;
	char *pkt = calloc(dimension, sizeof(char));
	
	struct ether_header *eth_hdr_pkt = get_ether_header(pkt);
	struct ether_header *eth_hdr_buf = get_ether_header(buf);
	eth_hdr_pkt->ether_type = htons(ether_type_ip);
	
	for (int i = 0; i < 6; i++) {
		eth_hdr_pkt->ether_shost[i] = eth_hdr_buf->ether_dhost[i];
		eth_hdr_pkt->ether_dhost[i] = eth_hdr_buf->ether_shost[i];
	}
	
	struct iphdr *ip_hdr_pkt = get_ip_header(pkt);
	struct iphdr *ip_hdr_buf = get_ip_header(buf);

	memcpy(ip_hdr_pkt, ip_hdr_buf, sizeof(struct iphdr));

	ip_hdr_pkt->daddr = ip_hdr_buf->saddr;
	char *interface_ip_hdr_pkt = get_interface_ip(interface);
	uint32_t ip = get_ip_from_ip_string(interface_ip_hdr_pkt);
	ip_hdr_pkt->saddr = htonl(ip);
	ip_hdr_pkt->protocol = 1;
	ip_hdr_pkt->frag_off = 0;
	ip_hdr_pkt->ttl = 128;
	ip_hdr_pkt->id = htons(1);
	ip_hdr_pkt->tot_len = htonl(dimension - sizeof(struct ether_header));
	ip_hdr_pkt->check = 0;
	ip_hdr_pkt->check = htons(checksum((uint16_t *)ip_hdr_pkt, sizeof(struct iphdr)));

	struct icmphdr *icmp_hdr = get_icmp_header(pkt);
	icmp_hdr->type = type;
	icmp_hdr->code = 0;

	char *icmphdr_end = (char *)icmp_hdr + sizeof(struct icmphdr);
	memcpy(icmphdr_end, ip_hdr_buf, sizeof(struct iphdr) + 64);

	icmp_hdr->checksum = 0;
	size_t icmp_data_len = dimension - sizeof(struct ether_header) - sizeof(struct iphdr);
	icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, icmp_data_len));

	send_to_link(interface, pkt, dimension);
}

void handle_IPv4_packet(int interface, size_t len, char *buf) {
	uint8_t *mac = calloc(6, sizeof(uint8_t));
	get_interface_mac(interface, mac);

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	
	if (!is_addresed_to_me(eth_hdr->ether_dhost, mac))
		return;
	
	struct iphdr *ip_hdr = get_ip_header(buf);
	add_in_arp_table(ntohl(ip_hdr->saddr), eth_hdr->ether_shost);

	uint16_t check = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	uint16_t check_sum = checksum((uint16_t *) ip_hdr, sizeof(struct iphdr));
	
	if (check_sum != check)
		return;

	if (ip_hdr->ttl < 2) {
		handle_icmp(interface, len, buf, 11);
		return;
	}
	
	struct icmphdr *icmp_hdr = get_icmp_header(buf);
	
	if (icmp_hdr != NULL) {  
		// If it is an echo request
		if (icmp_hdr->type == 8) {
			char *interface_ip = get_interface_ip(interface);
			uint32_t ip = get_ip_from_ip_string(interface_ip);
			
			if (ntohl(ip_hdr->daddr) == ip) {
				uint8_t *aux = calloc(6, sizeof(uint8_t));
				
				for (int i = 0; i < 6; i++) {
					aux[i] = eth_hdr->ether_dhost[i];
					eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
					eth_hdr->ether_shost[i] = aux[i];
				}

				uint32_t temp;
				temp = ip_hdr->daddr;
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = temp;

				uint16_t check_ip = ip_hdr->check;
				ip_hdr->check = 0;
				ip_hdr->check = ~(~check_ip + ~((uint16_t)(ip_hdr->ttl + 1)) + (uint16_t)ip_hdr->ttl) - 1;

				icmp_hdr->type = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(ip_hdr)));
				send_to_link(interface, buf, len);
				return;
			}
		}
	}

	ip_hdr->ttl--;
	ip_hdr->check = ~(~htons(check) + ~((uint16_t)(ip_hdr->ttl + 1)) + (uint16_t)ip_hdr->ttl) - 1;

	struct route_table_entry *longest_prefix = get_longest_prefix(route_table, ntohl(ip_hdr->daddr));
	
	if (longest_prefix == NULL) {
		handle_icmp(interface, len, buf, 3);
		return;
	}
	
	uint8_t *out_interface_mac = calloc(6, sizeof(uint8_t));
	get_interface_mac(longest_prefix->interface, out_interface_mac);

	struct arp_table_entry *arp_entry = get_arp_entry(longest_prefix->next_hop);
	
	if (arp_entry == NULL) {
		packet *pkt = create_packet(longest_prefix->next_hop, longest_prefix->interface, len, buf);	
		insert_elem_beginning_list(&arp_list, pkt);
		
		// Create ARP request
		char *reply_pkt = calloc(sizeof(struct ether_header) + sizeof(struct arp_header), sizeof(char));
		struct ether_header *reply_eth = (struct ether_header *) reply_pkt;
		
		for (int i = 0; i < 6; i++) {
			reply_eth->ether_shost[i] = out_interface_mac[i];
			reply_eth->ether_dhost[i] = broadcast_mac[i];
		}
		
		reply_eth->ether_type = htons(ether_type_arp);

		struct arp_header *reply_arp = get_arp_header(reply_pkt);
		reply_arp->hlen = 6;
		reply_arp->plen = 4;
		reply_arp->htype = htons(1);
		reply_arp->ptype = htons(ether_type_ip);
		reply_arp->op = htons(arp_request);

		char *interface_ip = get_interface_ip(longest_prefix->interface);
		uint32_t ip = get_ip_from_ip_string(interface_ip);
		reply_arp->spa = htonl(ip);
		reply_arp->tpa = htonl(longest_prefix->next_hop);

		for (int i = 0; i < 6; i++) {
			reply_arp->sha[i] = out_interface_mac[i];
		}

		send_to_link(longest_prefix->interface, reply_pkt, sizeof(struct ether_header) + sizeof(struct arp_header));
		return;
	}

	for (int i = 0; i < 6; i++) {
		eth_hdr->ether_shost[i] = out_interface_mac[i];
		eth_hdr->ether_dhost[i] = arp_entry->mac[i];
	}

	send_to_link(longest_prefix->interface, buf, len);
}

void handle_arp_packet(int interface, size_t len, char *buf) {
	uint8_t *mac = calloc(6, sizeof(uint8_t));
	get_interface_mac(interface, mac);
	
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	
	if (!is_addresed_to_me(eth_hdr->ether_dhost, mac))
		return;

	struct arp_header *arp_hdr = get_arp_header(buf);
	
	if (ntohs(arp_hdr->op) == arp_reply) {
		add_in_arp_table(ntohl(arp_hdr->spa), arp_hdr->sha);
		TList aux = arp_list;
		
		while (aux != NULL && aux->info != NULL) {
			TList current = aux;
			aux = aux->urm;
			
			if (current->info->next_hop == ntohl(arp_hdr->spa)) {
				uint8_t *out_interface_mac = calloc(6, sizeof(uint8_t));
				get_interface_mac(current->info->interface, out_interface_mac);
				
				struct ether_header *eth_hdr_send = (struct ether_header *) current->info->buf;
				
				for (int i = 0; i < 6; i++) {
					eth_hdr_send->ether_shost[i] = out_interface_mac[i];
					eth_hdr_send->ether_dhost[i] = arp_hdr->sha[i];
				}
				
				send_to_link(current->info->interface, current->info->buf, current->info->len);
				remove_elem_from_list(&arp_list, current->info);
			}
		}
		
		return;
	}

	if (ntohs(arp_hdr->op) == arp_request) {
		char *interface_ip = get_interface_ip(interface);
		uint32_t ip = get_ip_from_ip_string(interface_ip);
		
		if (ip == ntohl(arp_hdr->tpa)) {
			// Create ARP reply packet and send it back
			char *reply_pkt = calloc(sizeof(struct ether_header) + sizeof(struct arp_header), sizeof(char));
			struct ether_header *reply_eth = (struct ether_header *) reply_pkt;
			
			for (int i = 0; i < 6; i++) {
				reply_eth->ether_shost[i] = mac[i];
				reply_eth->ether_dhost[i] = eth_hdr->ether_shost[i];
			}
			
			reply_eth->ether_type = htons(ether_type_arp);

			struct arp_header *reply_arp = get_arp_header(reply_pkt);
			reply_arp->hlen = 6;
			reply_arp->plen = 4;
			reply_arp->htype = htons(1);
			reply_arp->ptype = htons(ether_type_ip);
			reply_arp->op = htons(arp_reply);
			reply_arp->spa = arp_hdr->tpa;
			reply_arp->tpa = arp_hdr->spa;

			for (int i = 0; i < 6; i++) {
				reply_arp->sha[i] = mac[i];
				reply_arp->tha[i] = arp_hdr->sha[i];
			}

			send_to_link(interface, reply_pkt, sizeof(struct ether_header) + sizeof(struct arp_header));
		}	

		return;
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Static creation of the routing table
	struct route_table_entry *table_entry = calloc(1000000, sizeof(struct route_table_entry));
	int no_of_entries = read_rtable(argv[1], table_entry);
	route_table = calloc (1, sizeof(TNod));

	/* Creation of the ARP table, initially having a single entry
	 * its size will be resized by +1 each time a new entry is added
	 */
	arp_table = calloc(1, sizeof(struct arp_table_entry *));

	// Creating the tree with previously saved IPs
	for (int i = 0; i < no_of_entries; i++)
		add_route_entry(route_table, table_entry[i].prefix, table_entry[i].mask, &table_entry[i]);

	// Initialize packet list
	arp_list = init_list();

	init(argc - 2, argv + 2);
	
	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		// Handle a packet based on ether_type
		if (ntohs(eth_hdr->ether_type) == ether_type_ip) {
			handle_IPv4_packet(interface, len, buf);
		} else {
			if (ntohs(eth_hdr->ether_type) == ether_type_arp) {
				handle_arp_packet(interface, len, buf);
			}
		}
	}
}
