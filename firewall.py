#!/usr/bin/env python
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.
import socket
import struct

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        # TODO: Load the firewall rules (from rule_filename) here.
        EOL = ''
        EMPTY_LIST = []
        COMMENT = '%'
        self.rules = []
        self.HTTPConnection = {}

        rules_file = open(config['rule'])
        current_line = rules_file.readline()
        while current_line != EOL:
            pl = current_line.split()
            if pl != EMPTY_LIST and pl[0] != COMMENT and pl[0] != EOL:
                if pl[1].lower() == 'dns' or pl[1].lower() == 'http':
                    self.rules.append(Rule(pl[0].lower(), pl[1].lower(), pl[2].lower(), None))
                else:
                    self.rules.append(Rule(pl[0].lower(), pl[1].lower(), pl[2].lower(), pl[3].lower()))
            current_line = rules_file.readline()

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        self.geoipdb = []
        geoipdb_file = open('geoipdb.txt')
        current_line = geoipdb_file.readline()
        while current_line != EOL:
            pl = current_line.split()
            self.geoipdb.append(GeoIP(pl[0].split("."), pl[1].split("."), pl[2]))
            current_line = geoipdb_file.readline()

        # TODO: Also do some initialization if needed.
        self.protocols = {'icmp': 1, 'tcp':6, 'udp':17}
        self.any = 'any'
        self.src_addr = None
        self.dst_addr = None
        self.src_port = None
        self.dst_port = None

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        iph_len = (struct.unpack('!B', pkt[0:1])[0] & 0xf) * 4 # Set the offset to the size of the IPV4 header

        if iph_len >= 20:
            protocol = struct.unpack('!B', pkt[9:10])[0] # Get the transport protocol type
            ext_ip = socket.inet_ntoa(pkt[12:16]) if pkt_dir == PKT_DIR_INCOMING else socket.inet_ntoa(pkt[16:20])

            # Handle ICMP packets
            if protocol == self.protocols['icmp']:
                icmp_type = struct.unpack('!B', pkt[iph_len:iph_len+1])[0]
                self.handle_general(ext_ip, 'icmp', icmp_type, pkt, pkt_dir)
            #Handle UDP and TCP packets
            elif protocol == self.protocols['tcp'] or protocol == self.protocols['udp']:
                if pkt_dir == PKT_DIR_INCOMING:
                    port = struct.unpack('!H', pkt[iph_len:iph_len+2])[0]
                elif pkt_dir == PKT_DIR_OUTGOING:
                    port = struct.unpack('!H', pkt[iph_len+2:iph_len+4])[0]
                # Handle UDP packets
                if protocol == self.protocols['udp']:
                    dns = None
                    qtype = None
                    if port == 53 and pkt_dir == PKT_DIR_OUTGOING:
                        #deals with udp
                        curr_pos = iph_len+8
                        #why is this curr_pos+4 and curr_pos+6?
                        #shouldn't it be curr_pos+12 and curr_pos+14?
                        qdcount = struct.unpack('!H', pkt[curr_pos+4:curr_pos+6])[0]

                        # Parse the QNAME
                        # Only consider packets w/ single question entry
                        if qdcount == 1:
                            qname = ""
                            curr_pos += 12 # Size of the DNS header 
                            qname_len = struct.unpack('!B', pkt[curr_pos:curr_pos+1])[0]
                            curr_pos += 1

                            #not quite sure what this does
                            while qname_len != 0:
                                qname += struct.unpack('!%ds' % qname_len, pkt[curr_pos:curr_pos+qname_len])[0] + "."
                                curr_pos += qname_len
                                qname_len = struct.unpack('!B', pkt[curr_pos:curr_pos+1])[0]
                                curr_pos += 1

                            # Cutoff the last '.' if length of QNAME > 0
                            if len(qname) > 0:
                                qname = qname[:len(qname)-1]

                            # Parse the QTYPE
                            qtype = struct.unpack('!H', pkt[curr_pos:curr_pos+2])[0]
                            curr_pos += 2
                            # Parse the QCLASS
                            qclass = struct.unpack('!H', pkt[curr_pos:curr_pos+2])[0]
                            # Set dns only if all conditions are met
                            if (qtype == 1 or qtype == 28) and qclass == 1:
                                dns = qname.lower()

                    # Should just pass dns packets where QCount != 1
                    self.handle_general(ext_ip, 'udp', port, pkt, pkt_dir, dns, qtype)
                # Handle TCP packets
                else:
                    iph_len = (struct.unpack('!B', pkt[0:1])[0] & 0xf) * 4
                    self.src_addr = struct.unpack('!L', pkt[12:16])[0]
                    self.dst_addr = struct.unpack('!L', pkt[16:20])[0]
                    self.src_port = struct.unpack('!H', pkt[iph_len:iph_len+2])[0]
                    self.dst_port = struct.unpack('!H', pkt[iph_len+2:iph_len+4])[0]

                    hostname = self.gethostname(ext_ip)
                    self.handle_general(ext_ip, 'tcp', port, pkt, pkt_dir, hostname)
            #Blindly pass all non-IPv4 packets
            else:
                self.send(pkt_dir, pkt)

    def handle_general(self, ext_ip, protocol, port_type, packet, pkt_dir, dns_hostname=None, qtype=None):
        verdict = 'pass'
        for rule in reversed(self.rules):
            rule_protocol = rule.field2
            rule_ip_dns_hostname = rule.field3
            rule_port_type = rule.field4

            if protocol == rule_protocol and self.ip_match(ext_ip, rule_ip_dns_hostname) and self.port_type_match(port_type, rule_port_type):
                verdict = rule.verdict
                break

            if rule_protocol == 'dns' and protocol == 'udp' and dns_hostname != None and self.match_domain(dns_hostname, rule_ip_dns_hostname):
                verdict = rule.verdict
                break

            if rule_protocol == 'http' and protocol == 'tcp' and dns_hostname != None and self.match_domain(dns_hostname, rule_ip_dns_hostname):
                verdict = rule.verdict
                break

        #send tcp packet w/ RST flag = 1
        if verdict == "deny" and protocol == "tcp":
            # check if it is a tcp syn packet
            iph_len = (struct.unpack('!B', packet[0:1])[0] & 0xf) * 4
            syn = struct.unpack('!B', packet[iph_len+13:iph_len+14])[0] & 0x2
            if syn:
                self.deny_tcp(pkt_dir, packet)

        #send DNS request to 169.229.49.130. Drop if qtype==28
        if verdict == "deny" and protocol == "udp": 
            if qtype != 28:
                self.deny_dns(pkt_dir, packet)

        if verdict == "log" and protocol == "tcp":

            log = self.getlog(dns_hostname)
            if log != None:
                self.writelog(log)
                self.remove_connection()
            self.send(pkt_dir, packet)

        if verdict == 'pass':
            if protocol == 'tcp':
                self.getcontents(pkt_dir, packet)
            else:
                self.send(pkt_dir, packet)

    def deny_dns(self, pkt_dir, packet):
        iph_len = (struct.unpack('!B', packet[0:1])[0] & 0xf) * 4
        lst = list(packet)
        # Change IP Header

        #flip src/dst addr
        src = lst[12:16]
        lst[12:16] = lst[16:20]
        lst[16:20] = src     

        # Change UDP Header

        #flip src/dst port
        src = lst[iph_len:iph_len+2]
        lst[iph_len:iph_len+2] = lst[iph_len+2:iph_len+4]
        lst[iph_len+2:iph_len+4] = src

        #set udp checksum to 0
        lst[iph_len+6:iph_len+8] = struct.pack('!H', 0)

        # size of UDP header
        curr_pos = iph_len + 8

        #change DNS header

        #leave ID as is
        # set QR = 1, opcode = 0, set AA as is, set TC = 0, set RD as is
        check1 = struct.unpack('!B', packet[curr_pos+2:curr_pos+3])[0] & 0x5
        lst[curr_pos+2:curr_pos+3] = struct.pack('!B', 128 + check1)
        #set RCode = 0
        check2 = struct.unpack('!B', packet[curr_pos+3:curr_pos+4])[0] & 0xF0
        lst[curr_pos+3:curr_pos+4] = struct.pack('!B', check2)
        #set qdcount = 1
        lst[curr_pos+4:curr_pos+6] = struct.pack('!H', 1)
        #set anscount = 1
        lst[curr_pos+6:curr_pos+8] = struct.pack('!H', 1)
        #set nscount = 0
        lst[curr_pos+8:curr_pos+10] = struct.pack('!H', 0)
        #set arcount = 0
        lst[curr_pos+10:curr_pos+12] = struct.pack('!H', 0)

        # size of DNS header
        curr_pos += 12

        start = curr_pos #save initial curr_pos
        qname_len = struct.unpack('!B', packet[curr_pos:curr_pos+1])[0]
        curr_pos += 1

        #not quite sure what this does
        while qname_len != 0:
            curr_pos += qname_len
            qname_len = struct.unpack('!B', packet[curr_pos:curr_pos+1])[0]
            curr_pos += 1

        #get final position of curr_pos
        final = curr_pos

        #get size of QNAME
        name_size = final - start

        #size of qtype and qclass
        curr_pos += 4

        #set Answer name = Question name
        lst[curr_pos:curr_pos+name_size] = lst[start:final]

        curr_pos += name_size

        #set qtype to 1
        lst[curr_pos:curr_pos+2] = struct.pack('!H', 1)
        #set class to 1
        lst[curr_pos+2:curr_pos+4] = struct.pack('!H', 1)
        #set ttl to 1
        lst[curr_pos+4:curr_pos+8] = struct.pack('!L', 1)
        #set RDlength to 4
        lst[curr_pos+8:curr_pos+10] = struct.pack('!H', 4)
        #set rdata to IP addr
        IP = "169.229.49.130"
        lst[curr_pos+10:curr_pos+14] = socket.inet_aton(IP)

        data = curr_pos + 14

        #set UDP length
        lst[iph_len+4:iph_len+6] = struct.pack('!H', data - iph_len)

        #set IP length
        lst[2:4] = struct.pack('!H', data)

        # construct the new packet to get IP checksum
        p = ''.join(lst)
        pkt = str(p)
        lst[10:12] = struct.pack('!H', self.IPv4_checksum(pkt))

        #change direction of lst
        if pkt_dir == PKT_DIR_OUTGOING:
            pkt_dir = PKT_DIR_INCOMING
        else:
            pkt_dir = PKT_DIR_OUTGOING

        p = ''.join(lst)
        pkt = str(p)

        self.send(pkt_dir, pkt)

    def deny_tcp(self, pkt_dir, packet):
        iph_len = (struct.unpack('!B', packet[0:1])[0] & 0xf) * 4
        lst = list(packet)

        #payload should be 0
        tcp_len = (struct.unpack('!B', packet[iph_len+12:iph_len+13])[0] >> 4) * 4
        length = struct.unpack('!H', packet[2:4])[0]
        payload = length - iph_len - tcp_len

        #lets get rid of TCP options
        while len(lst) > 40:
            lst.pop()

        #Change IP Header

        #set version to IPv4 and header len to 5
        lst[0:1] = struct.pack('!B', 69)
        #set TOS to 0
        lst[1:2] = struct.pack('!B', 0)
        #set total len to 40 B (2 headers & no data)
        lst[2:4] = struct.pack('!H', 40)
        #set ID/flags/offset to 0
        lst[4:8] = struct.pack('!L', 0)
        
        #flip src/dst addr
        src = lst[12:16]
        lst[12:16] = lst[16:20]
        lst[16:20] = src

        p = ''.join(lst)
        pkt = str(p)
        #set IPv4 checksum
        lst[10:12] = struct.pack('!H', self.IPv4_checksum(pkt))

        #Change TCP Header

        #flip src/dst port
        src = lst[iph_len:iph_len+2]
        lst[iph_len:iph_len+2] = lst[iph_len+2:iph_len+4]
        lst[iph_len+2:iph_len+4] = src
        # update ack to seq + 1 and set seq = 0
        seq = struct.unpack('!L', packet[iph_len+4:iph_len+8])[0]
        lst[iph_len+4:iph_len+8] = struct.pack('!L', 0)
        ack = seq + 1
        lst[iph_len+8:iph_len+12] = struct.pack('!L', ack)

        #set offset to 5 and reserved to 0
        lst[iph_len+12:iph_len+13] = struct.pack('!B', 80)
        #set RST and ACK flag in TCP header
        lst[iph_len+13:iph_len+14] = struct.pack('!B', 0x14)
        #set window to 0
        lst[iph_len+14:iph_len+16] = struct.pack('!H', 0)
        #set urgent ptr to 0
        lst[iph_len+18:iph_len+20] = struct.pack('!H', 0)

        #empty payload

        p = ''.join(lst)
        pkt = str(p)

        #set TCP checksum
        lst[iph_len+16:iph_len+18] = struct.pack('!H', self.TCP_checksum(pkt))

        #change direction of packet
        if pkt_dir == PKT_DIR_OUTGOING:
            pkt_dir = PKT_DIR_INCOMING
        else:
            pkt_dir = PKT_DIR_OUTGOING

        p = ''.join(lst)
        pkt = str(p)

        self.send(pkt_dir, pkt)

    #Get IPv4 checksum
    def IPv4_checksum(self, packet):
        iph_len = (struct.unpack('!B', packet[0:1])[0] & 0xf) * 4
        total = 0 

        i=0
        while (i<iph_len-1):
            if i == 10:
                word = 0
            else:
                word = struct.unpack('!H', packet[i:i+2])[0]
            total += word
            i+=2

        # if packet header has odd length
        if iph_len%2==1:
            word = struct.unpack('!B', packet[i:i+1])[0]
            word << 8 #pad 1B worth of 0s
            total += word

        total = (total & 0xffff) + (total >> 16)
        total += (total >> 16)
        total = ~total & 0xffff

        return total

    def TCP_checksum(self, packet):
        iph_len = (struct.unpack('!B', packet[0:1])[0] & 0xf) * 4
        tcp_len = (struct.unpack('!B', packet[iph_len+12:iph_len+13])[0] >> 4) * 4
        total = 26

        i=12
        while (i<iph_len+tcp_len-1):
            if i == 16+iph_len:
                word = 0
            else:
                word = struct.unpack('!H', packet[i:i+2])[0]
            total += word
            i+=2 

        #if packet header has odd length
        if tcp_len%2==1:
            word = struct.unpack('!B', packet[i:i+1])[0]
            word << 8 #pad 1B worth of 0s
            total += word

        # fold as part of checksum alg

        total = (total & 0xffff) + (total >> 16)
        total += (total >> 16)
        total = ~total & 0xffff

        return total

    #why does domain == None?
    def match_domain(self, domain, rule):
        if rule[0] == '*':
            if len(rule) == 1:
                return True
            elif rule[1] == '.' and '*' not in rule[1:] and domain != None:
                return rule[1:] in domain
        return domain == rule

    def ip_match(self, pkt_ip, rule_ip):
        if rule_ip == self.any:
            return True
        if len(rule_ip) == 2: # The rule uses a country code
            pkt_country = self.find_country_code(pkt_ip.split("."), 0, len(self.geoipdb)-1)
            return pkt_country == rule_ip
        else:
            rule_ip = rule_ip.split("/")
            if pkt_ip == rule_ip[0]: # Return true if the whole IP address matches
                return True
            elif len(rule_ip) == 2: # The rule has a subnet mask
                ip = pkt_ip.split(".")
                mask_ip = rule_ip[0].split(".")
                mask = int(rule_ip[1])
                cur = 0
                while mask > 0:
                    if mask < 8:
                        sub = 0xff << (8 - mask)
                        return int(ip[cur]) & sub == int(mask_ip[cur]) & sub
                    elif ip[cur] != mask_ip[cur]:
                        return False
                    mask -= 8
                    cur += 1
                return True
            return False

    def find_country_code(self, ip, start, end):
        # Return None if no country code can be found for given IP
        if end < start:
            return None
        else:
            cur = self.geoipdb[(start+end)/2]
            comp_start = self.compare_ip(ip, cur.start)
            comp_end = self.compare_ip(ip, cur.end)
            if comp_start != -1 and comp_end != 1:
                return cur.country_code.lower()
            elif comp_start == -1:
                return self.find_country_code(ip, start, (start+end)/2 - 1)
            else:
                return self.find_country_code(ip, (start+end)/2 + 1, end) 

    # Takes two IP addresses in list form
    # Returns -1 if ip1 < ip2, 0 if ip1 = ip2, and 1 if ip1 > ip2
    def compare_ip(self, ip1, ip2):
        if len(ip1) == 0 or len(ip2) == 0:
            return 0
        elif int(ip1[0]) < int(ip2[0]):
            return -1
        elif int(ip1[0]) > int(ip2[0]):
            return 1
        else:
            return self.compare_ip(ip1[1:], ip2[1:])

    def port_type_match(self, pkt_port_type, rule_port_type):
        if rule_port_type == self.any:
            return True
        port_type = rule_port_type.split("-")
        if len(port_type) == 1: # Only single port or ICMP type
            return int(pkt_port_type) == int(port_type[0])
        else: # Range of ports
            start = port_type[0]
            end = port_type[1]
            return (int(pkt_port_type) >= int(start)) and (int(pkt_port_type) <= int(end))

    def send(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    def gethostname(self, ext_ip):
        src_addr = self.src_addr
        dst_addr = self.dst_addr
        src_port = self.src_port
        dst_port = self.dst_port

        #hostname will only be in HTTP Request. that is when dst_port == 80
        hostname = None
        if (src_addr, dst_addr, src_port, dst_port) in self.HTTPConnection and dst_port == 80:
            if self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].complete:
                data = self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].data.split('\r\n')
                for line in data:
                    if line[:4].lower() == 'host':
                        hostname = line.split()[1]
                if hostname == None:
                    hostname = ext_ip
        return hostname

    # Need to reassemble TCP segments into byte streams based on TCP seq #
    def getcontents(self, pkt_dir, packet):
        iph_len = (struct.unpack('!B', packet[0:1])[0] & 0xf) * 4
        tcp_len = (struct.unpack('!B', packet[iph_len+12:iph_len+13])[0] >> 4) * 4

        #get total_len of packet
        total_len = len(packet)

        #get total data_len of packet
        header_len = iph_len + tcp_len
        start = header_len
        payload = total_len - header_len

        src_addr = self.src_addr
        dst_addr = self.dst_addr
        src_port = self.src_port
        dst_port = self.dst_port

        #sequence number of packet
        seq = struct.unpack('!L', packet[iph_len+4:iph_len+8])[0]

        get_data = False
        send_packet = False
        syn = struct.unpack('!B', packet[iph_len+13:iph_len+14])[0] & 0x2
        fin = struct.unpack('!B', packet[iph_len+13:iph_len+14])[0] & 0x1
        next = seq+payload+1 if syn or fin else seq+payload

        if (src_addr, dst_addr, src_port, dst_port) not in self.HTTPConnection:
            self.HTTPConnection[src_addr, dst_addr, src_port, dst_port] = HTTPLog(next)
            get_data = True
            send_packet = True

        elif self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].nextseq >= seq:
            if self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].nextseq == seq:
                self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].nextseq = next
                get_data = True
            send_packet = True

        if get_data and not self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].complete:
            data = packet[start:]
            if '\r\n\r\n' not in data:
                self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].data += str(data)
            else:
                for byte in data:
                    self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].data += byte
                    data_len = len(self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].data)
                    if self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].data[data_len-4:] == '\r\n\r\n':
                        self.HTTPConnection[src_addr, dst_addr, src_port, dst_port].complete = True
                        break

        if send_packet:
            self.send(pkt_dir, packet)

    # get contents to log
    def getlog(self, hostname):
        src_addr = self.src_addr
        dst_addr = self.dst_addr
        src_port = self.src_port
        dst_port = self.dst_port

        log = None

        host_name = hostname
        method = None
        path = None
        version = None
        status_code = None
        object_size = None

        request = None
        response = None
        if dst_port == 80:
            request = (src_addr, dst_addr, src_port, dst_port)
            response = (dst_addr, src_addr, dst_port, src_port)
        elif src_port == 80:
            request = (dst_addr, src_addr, dst_port, src_port)
            response = (src_addr, dst_addr, src_port, dst_port)

        if request != None and response != None:
            if request in self.HTTPConnection:
                if self.HTTPConnection[request].complete:
                    data = self.HTTPConnection[request].data.split('\r\n')
                    first_line = data[0].split()
                    method = first_line[0]
                    path = first_line[1]
                    version = first_line[2]
            if response in self.HTTPConnection:
                if self.HTTPConnection[response].complete:
                    data = self.HTTPConnection[response].data.split('\r\n')
                    # status_code = data[0].split()[1]
                    for line in data:
                        if line[:4].lower() == 'http':
                            status_code = line.split()[1]
                        if line[:14].lower() == 'content-length':
                            object_size = line.split()[1]
                            break
                    if object_size == None:
                        object_size = -1

        if hostname != None and method != None and path != None and version != None and status_code != None and object_size != None:
            log = [str(hostname), str(method), str(path), str(version), str(status_code), str(object_size)]
        return log

    # write contents to log
    def writelog(self, log):
        f = open("http.log", "a")
        s = " ".join(log)
        f.write(s + "\n")
        f.flush()

    def remove_connection(self):
        src_addr = self.src_addr
        dst_addr = self.dst_addr
        src_port = self.src_port
        dst_port = self.dst_port

        first = (src_addr, dst_addr, src_port, dst_port)
        second = (dst_addr, src_addr, dst_port, src_port)

        del self.HTTPConnection[first]
        del self.HTTPConnection[second]

class Rule:
    def __init__(self, verdict, field2, field3, field4):
        self.verdict = verdict
        self.field2 = field2 # Protocol
        self.field3 = field3 # External IP for non DNS, domain name for DNS
        self.field4 = field4 # External port or ICMP type for non DNS

    def toString(self):
        return "(%s, %s, %s, %s)" % (self.verdict, self.field2, self.field3, self.field4)

class GeoIP:
    def __init__(self, start, end, country_code):
        self.start = start
        self.end = end
        self.country_code = country_code

    def toString(self):
        return "(%s, %s, %s)" % (self.start, self.end, self.country_code)

class HTTPLog:
    def __init__(self, nextseq):
        self.nextseq = nextseq
        self.data = ""
        self.complete = False