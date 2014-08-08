#encoding=utf8
import struct
import socket

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

payload = pack_question_section("www.ejoy.com", 1, 1)
package = header + payload

from scapy.all import *
c = DNS(id=1,qr=0,opcode=0,tc=0,rd=1,qdcount=1,ancount=0,nscount=0,arcount=0)
c.qd=DNSQR(qname="www.ejoy.com",qtype=1,qclass=1)
a = IP(dst="8.8.8.8")
b = UDP(dport=53)
resp = sr1(a/b/c)
print resp[DNS].show()
print len(resp[DNS])

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

def unpack_question_record(rawstring):
    labels = []
    i = 0
    while True:
        label_length = struct.unpack(">B", rawstring[i])[0]
        # TODO if label_length > 192 then this is a offset
        i = i + 1
        label = struct.unpack("%ds" %label_length, rawstring[i:i+label_length])[0]
        labels.append(label)
        i = i + label_length
        if rawstring[i] == chr(0):
            break
    i += 1
    QTYPE, QCLASS = struct.unpack(">hh", rawstring[i:i+4])
    i += 4
    return labels, QTYPE, QCLASS, i

def unpack_resource_record(rawstring, count):
    labels = []
    i = 0
    while True:
        label_length = struct.unpack(">B", rawstring[i])[0]
        # TODO if label_length > 192 then this is a offset
        if label_length > 192:
            jump_point = i
        else:
            i = i + 1
            label = struct.unpack("%ds" %label_length, rawstring[i:i+label_length])[0]
            labels.append(label)
            print label
            i = i + label_length
            if rawstring[i] == chr(0):
                break
    i += 1
    TYPE, CLASS, TTL, RDLENGTH = struct.unpack(">hhIh", rawstring[i:i+(2+2+4+2)])
    print "type", TYPE
    print "class", CLASS
    print "ttl", TTL
    print "rdlength", RDLENGTH
    i += 2 + 2 + 4 + 2
    RDATA = struct.unpack(">%ds" %RDLENGTH, rawstring[i:i+RDLENGTH]) 
    return labels

HEADER_LEN = 12
if __name__ == "__main__":
    HOST, PORT = "8.8.8.8", 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(package, (HOST, PORT))
    received = sock.recv(1024)
    print "received: ", len(received)
    header_info = unpack_dns_header(received)
    answer_count = header_info["ANCOUNT"]
    answer_part = received[HEADER_LEN:]
    print "answer_count", answer_count
    labels, qtype, qclass, remain = unpack_question_record(answer_part)
    resource_record_part = answer_part[remain:]
    unpack_resource_record(resource_record_part, answer_count)
