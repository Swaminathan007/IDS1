import scapy.all as scapy
interfaces = scapy.get_if_list()
interfaces_with_ip = {}

for i in interfaces:
    interfaces_with_ip[i] = scapy.get_if_addr(i)

print(interfaces_with_ip) 