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
                    for i in range(int(r[0]), int(r[1])):
                        rules_dict[key_string]['ports'].add(i)
                else:
                    rules_dict[key_string]['ports'].add(int(row[2]))

                if '-' in row[3]:
                    r = row[3].split('-')
                else:
                    rules_dict[key_string]['ips'].add(row[3])

            return rules_dict

    def accept_packet(self, direction, protocol, port, ip_address):
        key_string = direction + protocol
        return port in self.rules[key_string]['ports'] and ip_address in self.rules[key_string]['ips']

#f = Firewall("firewall_rules.csv")
#print(f.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
