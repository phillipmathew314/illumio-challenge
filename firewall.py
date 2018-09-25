import csv
import ipaddress

class Firewall:
    def __init__(self, filename):
        self.rules = self.store_rules(filename)

    def store_rules(self, filename):
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            #initialize the rules dictionary
            rules_dict = { 'inboundtcp': {'ports': set(), 'ips': set()}, 'outboundtcp': {'ports': set(), 'ips': set()}, 'inboundudp': {'ports': set(), 'ips': set()}, 'outboundudp': {'ports': set(), 'ips': set() }}

            for row in reader:
                key_string = row[0] + row[1]
                if '-' in row[2]:
                    r = row[2].split('-')
                    for i in range(int(r[0]), int(r[1])+1):
                        rules_dict[key_string]['ports'].add(i)
                else:
                    rules_dict[key_string]['ports'].add(int(row[2]))

                if '-' in row[3]:
                    r = row[3].split('-')
                    beg = int(ipaddress.ip_address(r[0]))
                    end = int(ipaddress.ip_address(r[1])) + 1
                    for i in range(beg, end):
                        rules_dict[key_string]['ips'].add(i)
                else:
                    rules_dict[key_string]['ips'].add(int(ipaddress.ip_address(row[3])))

            return rules_dict

    def accept_packet(self, direction, protocol, port, ip_address):
        key_string = direction + protocol
        return port in self.rules[key_string]['ports'] and int(ipaddress.ip_address(ip_address)) in self.rules[key_string]['ips']

f = Firewall("firewall_rules.csv")
print(f.accept_packet("inbound", "tcp", 80, "192.168.1.2"))         #True
print(f.accept_packet("inbound", "tcp", 80, "192.168.1.1"))         #False
print(f.accept_packet("inbound", "tcp", 90, "192.168.1.2"))         #False
print(f.accept_packet("inbound", "udp", 53, "192.168.2.5"))         #True
print(f.accept_packet("inbound", "udp", 53, "192.168.1.200"))       #True
print(f.accept_packet("outbound", "tcp", 10000, "192.168.10.11"))   #True
print(f.accept_packet("outbound", "tcp", 20001, "192.168.10.11"))   #False
print(f.accept_packet("outbound", "udp", 1500, "52.12.48.92"))      #True
