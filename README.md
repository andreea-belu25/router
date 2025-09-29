## Implementation Details

### Packet Queue Management
- Used a singly linked list to store packets waiting for ARP replies
- List management functions:
  - `init_list()`: Initialize the list
  - `aloc_cell()`: Allocate a list cell
  - `insert_elem_beginning_list()`: Insert packet at the beginning of the packet list
  - `remove_elem_from_list()`: Remove packet from the list

### IP Routing Tree Structure
- Created a binary tree for efficient IP storage and searching
- Tree construction:
  - Traverse all bits of the IP until the 1 bits in the mask are exhausted
  - Nodes corresponding to 1 bits are placed on the left side
  - Nodes corresponding to 0 bits are placed on the right side
  - Tree may contain nodes without values (when prefix doesn't represent a valid routing table entry)

### get_longest_prefix(TArb arb, uint32_t ip)
- Searches for the IP in the tree
- Traverses each bit of the IP and determines which branch to follow (left for 1, right for 0)
- At each step, stores a temporary prefix equal to the current tree entry

### ICMP Handling
- Creates a new packet corresponding to the ICMP protocol
- Ethernet header processing:
  - Destination of initial packet becomes source of new packet
  - Source of initial packet becomes destination of new packet
- IP header processing:
  - Copies the IPv4 header of the initial packet
  - Updates all necessary fields
- ICMP header processing:
  - Calculates all necessary fields
- Sends the packet on the same interface where it arrived

### IPv4 Handling
- Obtains the MAC address corresponding to the arrival interface
- Verifies if the packet is destined for the router
- Adds the source IP of the packet to the ARP table
- Validates packet integrity:
  - Calculates checksum based on previously stored checksum
  - Verifies transmitted message was not corrupted
  - Drops packet if corrupted
- TTL handling:
  - If TTL < 2, drops packet and sends ICMP TIME EXCEEDED back
- ECHO REQUEST handling:
  - Verifies if packet is an ECHO REQUEST addressed to the router
  - If yes, sends ECHO REPLY back
- Updates the IPv4 header and recalculates the checksum
- Finds the longest prefix match (best matching IP) for the next hop
- ARP table lookup:
  - If no entry exists for the next hop, adds packet to waiting list
  - Generates an ARP REQUEST in the network
- Sends the packet to the next hop

### ARP Handling
- Obtains the MAC address corresponding to the arrival interface
- Verifies if the packet is destined for the router
- **ARP REQUEST:**
  - Creates an ARP reply packet
  - Fills all packet fields
  - Sends it on the corresponding interface
- **ARP REPLY:**
  - Adds the response to the ARP table
  - Sends all packets from the waiting list that were waiting for this response
