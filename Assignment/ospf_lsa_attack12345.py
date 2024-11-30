from scapy.all import *
from scapy.contrib.ospf import *
import time

state = "INIT"
source_ip = "192.168.10.99"

# Function to process received packets based on the ospf handshake state
def handle_packet(packet):
    
    global state
    global source_ip
    
    if packet.haslayer(OSPF_Hdr) and packet[IP].src != source_ip:
        ospf_layer = packet.getlayer(OSPF_Hdr)

        # If in "INIT" state, handle the hello packet
        if state == "INIT" and ospf_layer.type == 1:
            time.sleep(2)
            print("Received OSPF Hello packet")
            send_hello_response()
            state = "HELLO_SENT"
            print("HELLO_SENT")

        # If in "HELLO_SENT" state, handle the DBD packet
        elif state == "HELLO_SENT" and ospf_layer.type == 2:
            time.sleep(2)
            print("Received OSPF DBD packet")
            send_dbd_response(packet)
            state = "DBD_SENT"
            print("DBD_SENT")

        # If in "DBD_SENT" state, handle the LS Request packet
        elif state == "DBD_SENT" and ospf_layer.type == 3:
            time.sleep(2)
            print("Received OSPF LS Request packet")
            send_ls_update(packet)
            state = "UPDATE_SENT"
            print("UPDATE_SENT")

        # If in "UPDATE_SENT" state, handle the LS Update packet
        elif state == "DBD_SENT" or state == "UPDATE_SENT" and ospf_layer.type == 4:
            time.sleep(2)
            print("Received OSPF LS Update packet")
            send_ls_ack(packet)
            state = "ACK_SENT"
            print("ACK_SENT")
        
        # If in "ACK_SENT" state, handle the LS Ack packet
        elif state == "ACK_SENT" and ospf_layer.type == 5:
            time.sleep(2)
            print("Received OSPF LS Ack packet")
            state = "FULL"
            print("FULL")
            send_periodic_hellos()


# Function to send a response to an OSPF Hello packet
def send_hello_response():
    ospf_hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=10,
        router="224.0.0.5",
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


def send_dbd_response(received_packet):
    ospf_dbd = OSPF_DBDesc(
        mtu=1500,
        options=0x02,
        ddseq=received_packet[OSPF_DBDesc].ddseq + 1,  # Increment sequence number
        dbdescr=0x07
    )
    ospf_header_dbd = OSPF_Hdr(
        version=2,
        type=2,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_dbd = IP(
        src="192.168.10.99",
        dst="224.0.0.5"
    ) / ospf_header_dbd / ospf_dbd
    send(ospf_packet_dbd, iface="eth0", verbose=1)


def send_ls_request(received_packet):
    # Define OSPF LS Request Packet
    ospf_request = OSPF_LSReq(
        requests=[LSReq(type=1, lsid="1.1.1.1", adv_router="1.1.1.1")]
    )
    ospf_header_request = OSPF_Hdr(
        version=2,
        type=3,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_request = IP(
        src="192.168.10.99",
        dst="224.0.0.5"
    ) / ospf_header_request / ospf_request
    send(ospf_packet_request, iface="eth0", verbose=1)


def send_ls_update(received_packet):
    ospf_update = OSPF_LSUpd(
        lsu_number=1,
        lsaheaders=[OSPF_Router_LSA(id="3.3.3.3", adrouter="3.3.3.3", seq=0x80000001, options=0x02)]
    )
    ospf_header_update = OSPF_Hdr(
        version=2,
        type=4,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_update = IP(
        src="192.168.10.99",
        dst="224.0.0.5"
    ) / ospf_header_update / ospf_update
    send(ospf_packet_update, iface="eth0", verbose=1)


def send_ls_ack(received_packet):
    ospf_ack = OSPF_LSAck(
        lsaheaders=[OSPF_Router_LSA(id="1.1.1.1", adrouter="1.1.1.1", seq=0x80000001, options=0x02, linklist=[])]
    )
    ospf_header_ack = OSPF_Hdr(
        version=2,
        type=5,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_ack = IP(
        src="192.168.10.99",
        dst="224.0.0.5"
    ) / ospf_header_ack / ospf_ack
    send(ospf_packet_ack, iface="eth0", verbose=1)

def send_periodic_hellos():
    # Once FULL state is reached, send periodic Hello packets
    print("Starting periodic Hello packets...")
    while True:
        send_hello_response()
        time.sleep(10)    


# Start sniffing OSPF packets and handle them
while state != "FULL":
    print("Started sniffing packets...")
    sniff(filter="ip proto ospf and not src host 192.168.10.99", iface="eth0", prn=handle_packet)

