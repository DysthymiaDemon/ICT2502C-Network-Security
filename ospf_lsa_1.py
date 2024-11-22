from scapy.all import *
from scapy.contrib.ospf import *
import time

def send_hello_response():
    ospf_hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=10,
        router="192.168.10.1",
        prio=1,
        options=0x02,
        neighbors=["1.1.1.1"]
    )
    ospf_header_hello = OSPF_Hdr(
        version=2,
        type=1,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_hello = IP(
        src="192.168.10.99",
        dst="224.0.0.5"
    ) / ospf_header_hello / ospf_hello
    send(ospf_packet_hello, iface="eth0", verbose=1)

print("Starting periodic Hello packets...")
while True:
    send_hello_response()
    time.sleep(5)
