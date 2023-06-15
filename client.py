import socket
import struct
import time
import sys

# Author: Constantinovici

class Socks5_Client:
    def __init__(self, proxy_ip, proxy_port):
        self.proxy_ip = proxy_ip
        self.proxy_port = int(proxy_port)
        self.dest_ip = "127.0.0.1"
        self.dest_port = 9999
        print(f"Proxy was set to: {self.proxy_ip}:{self.proxy_port}")
        self.run()

	# Extract the reply type from subnegotiation response
    def extract_rep_reply_name(self, packet):
        int_packet = int.from_bytes(packet, "little")
        if int_packet > 9:
            print("Recived invalid REP In subnegotiation.")
            sys.exit(0)

        rep_types = {
                "0": "Succeeded",
                "1": "General SOCKS server failure",
                "2": "Connection not allowed by ruleset",
                "3": "Network unreachable",
                "4": "Host unreachable",
                "5": "Connection refused", 
                "6": "TTL expired",
                "7": "Command not supported",
                "8": "Address type not supported",
                "9": "To X'FF' unassigned"
        }
        return rep_types[str(int_packet)] 

    def connect(self):
        try:
            self.self_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.self_socket.connect((self.proxy_ip, self.proxy_port))
        except Exception as e:
            print(f"Can't create socket: {e}")
            sys.exit(0)

	# Create the socks5 handshake
    def socks5_handshake(self):
        
        # Send
        self.self_socket.send(b"\x05\x01\x00")
        buffer = self.self_socket.recv(2)
        
        if buffer[0] != 0x05:
            print("Server returned an invalid version of socks in handshake.")
            sys.exit(0)
        
        if buffer[1] != 0x00:
            print("Server returned an invalid Auth method in handshake.")
            sys.exit(0)

        print("Handshake made successfully.")
    
    def socks5_subnegotiation(self):

		# +-----+-----+-------+------+----------+-----------+
        # | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT  |
        # +-----+-----+-------+------+----------+-----------+
        # |  1  |  1  | X'00' |  1   | Variable |    2      |
        # +-----+-----+-------+------+----------+-----------+

        buffer = b''
        buffer += b'\x05' # Socks5 version
        buffer += b'\x03' # UDP Associate
        buffer += b'\x00' # Reserved
        buffer += b'\x01' # Address Type is IPV4
        buffer += socket.inet_aton(self.dest_ip)
        buffer += struct.pack(">H", self.dest_port)
        print("send", buffer)
        self.self_socket.send(buffer)

        recv_buffer = self.self_socket.recv(20)
        print("recv", recv_buffer)

        # +-----+-----+-------+------+----------+----------+
        # | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +-----+-----+-------+------+----------+----------+
        # |  1  |  1  | X'00' |  1   | Variable |    2     |
        # +-----+-----+-------+------+----------+----------+

		# REP responses
		# X'00' succeeded
		# X'01' general SOCKS server failure
        # X'02' connection not allowed by ruleset
        # X'03' Network unreachable
        # X'04' Host unreachable
        # X'05' Connection refused
        # X'06' TTL expired
        # X'07' Command not supported
        # X'08' Address type not supported
        # X'09' to X'FF' unassigned

        ver = recv_buffer[0]
        if ver != 0x05:
            print("Recived invalid socks VER recived in subnegotiation.")
            sys.exit(0)
        
        rep = recv_buffer[1]
        if rep != 0x00:
            rep_string = self.extract_rep_reply_name(recv_buffer[1:2])
            print(f"Recived invalid REP in subnegotiation: {rep_string}")
            sys.exit(0) 

        rsv = recv_buffer[2]
        if rsv != 0x00:
            print("Recived invalid RSV in subnegotiation.")
            sys.exit(0)

        atype = recv_buffer[3]
        if atype != 0x01:
            print("Recived invalid ATYPE in subnegotiation. I have to deal only with IPV4")
            sys.exit(0)

        
        self.internal_ip_bytes = recv_buffer[4:8]
        self.internal_port_bytes = recv_buffer[8:10]
        
		# Convert bytes ip to dotted ip
        # proxy_intern_address = socket.inet_ntoa(self.internal_ip_bytes)

        # Convert bytes into network decimal 
        # intern_network_order_port = int.from_bytes(self.internal_port_bytes)

        # Convert the network-order decimal to host order decimal
        # proxy_intern_port = socket.ntohs(intern_network_order_port)

        # print("recv->buff", list(recv_buffer))
        # print(proxy_intern_address)
        # print(proxy_intern_port)
        # print(f"Internal IP:{proxy_intern_address}: PORT:{proxy_intern_port}")
        # print("Subnegociation successfully.")

    def socks5_udp_procedure(self):
        buffer = b''
        buffer += b"\x00\x00" # RSV
        buffer += b'\x00' # FRAG
        buffer += b'\x01' # ATYPE (0x00 = IPV4)
        buffer += self.internal_ip_bytes
        buffer += self.internal_port_bytes
        buffer += b"cool"
        self.self_socket.send(buffer)
        
    def run(self):
        self.connect()
        self.socks5_handshake()
        self.socks5_subnegotiation()
        
        while 1:
            self.socks5_udp_procedure()
            time.sleep(5)
    

if __name__ == '__main__':

    if len(sys.argv) != 3:
        print("python client.py <proxy_ip> <proxy_port>")
        sys.exit(3)

    client = Socks5_Client(sys.argv[1], sys.argv[2])

