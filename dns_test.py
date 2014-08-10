#encoding=utf8
import struct
import socket
import argparse

#                                   1  1  1  1  1  1
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                      ID                       |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                    QDCOUNT                    |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                    ANCOUNT                    |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                    NSCOUNT                    |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                    ARCOUNT                    |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

def pack_dns_header(_id, QR, Opcode, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT):
    QR = QR << 15
    Opcode = Opcode << 11
    AA = AA << 10
    TC = TC << 9
    RD = RD << 8
    RA = RA << 7
    Z = Z << 4
    header_id = struct.pack(">h", 1)
    header_operator = struct.pack(">h", QR | Opcode | AA | TC | RD | RA | Z | RCODE)
    QDCOUNT = struct.pack(">h", QDCOUNT)
    ANCOUNT = struct.pack(">h", ANCOUNT)
    NSCOUNT = struct.pack(">h", NSCOUNT)
    ARCOUNT = struct.pack(">h", ARCOUNT)
    return header_id + header_operator + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

header = pack_dns_header(_id=1, QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0,
        QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0)

#   question section format
#                                   1  1  1  1  1  1
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                                               |
#   /                     QNAME                     /
#   /                                               /
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     QTYPE                     |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     QCLASS                    |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

def pack_QNAME(domain):
    labels = domain.split(".") 
    result = ""
    for label in labels:
        l = len(label)
        t = struct.pack(">B%ds" %l, l, label)
        result += t
    result += struct.pack(">B", 0)
    return result

def pack_question_section(domain_name, QTYPE, QCLASS):
    QNAME = pack_QNAME(domain_name)
    QTYPE = struct.pack(">H", QTYPE) #ask for ipv4 address
    QCLASS = struct.pack(">H", QCLASS) #ask for internet address
    return QNAME + QTYPE + QCLASS


#from scapy.all import *
#c = DNS(id=1,qr=0,opcode=0,tc=0,rd=1,qdcount=1,ancount=0,nscount=0,arcount=0)
#c.qd=DNSQR(qname="www.ejoy.com",qtype=1,qclass=1)
#a = IP(dst="8.8.8.8")
#b = UDP(dport=53)
#resp = sr1(a/b/c)
#print resp[DNS].show()
#print len(resp[DNS])

def unpack_dns_header(rawstr):
    _id = struct.unpack(">h", rawstr[0:2])[0]
    header_operator = struct.unpack(">h", rawstr[2:4])[0]
    QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack(">hhhh", rawstr[4:(4+2*4)])
    return {
            "id" : _id, 
            "QDCOUNT" : QDCOUNT,
            "ANCOUNT" : ANCOUNT,
        }

#                                   1  1  1  1  1  1
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                                               |
#   /                                               /
#   /                      NAME                     /
#   |                                               |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                      TYPE                     |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     CLASS                     |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                      TTL                      |
#   |                                               |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                   RDLENGTH                    |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#   /                     RDATA                     /
#   /                                               /
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

def unpack_name(rawstring, offset):
    labels = []
    i = offset
    while True:
        label_length = struct.unpack(">B", rawstring[i])[0]
        if label_length >= 192: #this is pointer
            label_length = struct.unpack(">H", rawstring[i:i+2])[0]
            pointer_offset = label_length & 0x3fff
            labels, _ = unpack_name(rawstring, pointer_offset)
            return labels, i + 2
        else:
            i = i + 1
        label = struct.unpack("%ds" %label_length, rawstring[i:i+label_length])[0]
        labels.append(label)
        i = i + label_length
        if rawstring[i] == chr(0):
            break
    i += 1
    return labels, i

def unpack_question_record(rawstring, offset):
    labels, i = unpack_name(rawstring, offset)
    QTYPE, QCLASS = struct.unpack(">hh", rawstring[i:i+4])
    i += 4
    return labels, QTYPE, QCLASS, i

def unpack_resource_record(rawstring, count, offset):
    result = []
    for i in xrange(count):
        rr, offset = unpack_single_resource_record(rawstring, offset)
        result.append(rr)
    return result, offset

def unpack_single_resource_record(rawstring, offset):
    labels, i = unpack_name(rawstring, offset)
    TYPE, CLASS, TTL, RDLENGTH = struct.unpack(">hhIh", rawstring[i:i+(2+2+4+2)])
    i += 2 + 2 + 4 + 2
    RDATA = struct.unpack(">%ds" %RDLENGTH, rawstring[i:i+RDLENGTH])[0]
    return {
            "labels":labels,
            "type":TYPE,
            "class":CLASS,
            "ttl":TTL,
            "rdlength":RDLENGTH,
            "rdata":RDATA,
        }, i + RDLENGTH

def ipstr_to_4tuple(ipstr):
    result = ""
    for i in xrange(3):
        result += str(ord(ipstr[i])) + "."
    result += str(ord(ipstr[3]))
    return result

def domain_name_to_ip(domain_name, use_tcp):
    HOST, PORT = "114.114.114.114", 53
    payload = pack_question_section(domain_name, 1, 1)
    package = header + payload
    if use_tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        package_size = struct.pack(">h", len(package))
        sock.sendall(package_size + package)
        received = sock.recv(1024)
        received_size = struct.unpack(">h", received[0:2])[0]
        received = received[2:2+received_size]
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(package, (HOST, PORT))
        received = sock.recv(1024)
    header_info = unpack_dns_header(received)
    answer_count = header_info["ANCOUNT"]
    labels, qtype, qclass, offset = unpack_question_record(received, HEADER_LEN)
    resource_records, offset = unpack_resource_record(received, answer_count, offset)
    ips = []
    for rr in resource_records:
        if rr["type"] == 1 and rr["class"] == 1:
            ips.append(ipstr_to_4tuple(rr["rdata"]))
    return ips

HEADER_LEN = 12
if __name__ == "__main__":
    parser = argparse.ArgumentParser("This is a simple domain name to ip address tool")
    parser.add_argument("domain_names", nargs = "+")
    parser.add_argument('--tcp', action='store_true', default=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    for arg in args.domain_names:
        print arg, "==>", domain_name_to_ip(arg, args.tcp) 
