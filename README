I used a singly linked list to store packets that are waiting for an ARP reply.

For managing this list I used:
    - list initialization: init_list()
    - list cell allocation: aloc_cell
    - insert_elem_beginning_list: insert packet at the beginning of the packet list
    - remove_elem_from_list: remove packet from the list

For easy storage and searching of an IP, I created a tree as follows: I traverse all the bits of the IP 
until the 1 bits in the mask are exhausted.

I use a binary tree in which nodes corresponding to 1 bits are found on the left side and those 
corresponding to 0 bits are found on the right side. In the tree there can exist nodes without values 
(if the prefix formed by the bits up to that node does not represent a valid entry in the router's 
routing table).

get_longest_prefix(TArb arb, uint32_t ip)
    - searches for the IP in the tree
    - traverses each bit of the IP and checks which branch to advance on (left for 1 and right for 0)
    - at each step, stores a temporary prefix equal to the current entry in the tree

ICMP:
    - A new packet corresponding to the ICMP protocol is created.

    - For this, the ethernet header is obtained.
        * The destination and source are filled as follows: the destination of the initial packet 
          becomes the source of the new packet and its source becomes the destination of the new packet.
    
    - For this, the IP header is obtained.
        * The IPv4 header of the initial packet is copied. All necessary fields are updated.
    
    - For this, the ICMP header is obtained.
        * All necessary fields are calculated.
    
    Finally, the packet is sent on the same interface where the packet arrived.


IPv4:
    - The MAC corresponding to the interface where the packet arrived is obtained.
    
    - It is verified whether the packet is destined for the router.
    
    - The source IP of the packet is added to the ARP table.
    
    - The checksum is calculated based on the previously stored checksum and it is verified that the 
      transmitted message was not corrupted. Otherwise, the packet is dropped.
    
    - If the TTL is less than 2 => the packet is dropped and an ICMP TIME EXCEEDED packet is sent back.
    
    - It is verified whether the packet is an ECHO REQUEST addressed to the router; if yes, an ECHO 
      REPLY is sent back.
    
    - The IPv4 header is updated and the checksum is recalculated.
    
    - The longest prefix (the IP that matches best) is found, i.e., the next hop of the packet.
    
    - In case there is no entry in the ARP table for the next hop, the packet is added to a list and 
      an ARP REQUEST is generated in that network.
    
    Finally, the packet is sent to the next hop.


ARP:
    - The MAC corresponding to the interface where the packet arrived is obtained.
    
    - It is verified whether the packet is destined for the router.
    
    - ARP REQUEST:
        - An ARP reply packet is created and sent back.
        - All fields of this packet are filled and it is sent on the corresponding interface.
    
    - ARP REPLY:
        - The response is added to the ARP table.
        - All packets from the list that were waiting for this response are sent.
