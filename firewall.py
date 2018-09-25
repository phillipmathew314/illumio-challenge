import csv

class Firewall:
    def __init__(self, filename):
        self.rules = self.store_rules(filename)

    def store_rules(self, filename):
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            rules_set = set()
            for row in reader:
                row_string = row[0] + row[1]
                if '-' in row[2]:
                    range = row[2].split('-')
                    row_string += range[0]
                else:
                    row_string += row[2]

                if '-' in row[3]:
                    range = row[2].split('-')
                    row_string += range[0]
                else:
                    row_string += row[3]

                rules_set.add(row_string)
                return rules_set

    def accept_packet(self, direction, protocol, port, ip_address):
        packet_string = direction + protocol + str(port) + ip_address
        return packet_string in self.rules

f = Firewall("firewall_rules.csv")
print(f.rules)
print(f.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
