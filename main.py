import os
import scapy.all as scapy

# Firewall Rules
rules = []

def add_rule(action, ip, port, protocol):
    rules.append({
        'action': action,
        'ip': ip,
        'port': port,
        'protocol': protocol
    })
    print(f"Rule added: {action} {protocol} {ip}:{port}")

def check_packet(packet):
    # Check if the packet matches any rule
    for rule in rules:
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            if packet.haslayer(scapy.TCP):
                port_src = packet[scapy.TCP].sport
                port_dst = packet[scapy.TCP].dport
                protocol = 'TCP'
            elif packet.haslayer(scapy.UDP):
                port_src = packet[scapy.UDP].sport
                port_dst = packet[scapy.UDP].dport
                protocol = 'UDP'
            else:
                continue
            
            if (rule['protocol'] == protocol and
                (rule['ip'] == ip_src or rule['ip'] == ip_dst) and
                (rule['port'] == port_src or rule['port'] == port_dst)):
                if rule['action'] == 'BLOCK':
                    print(f"Blocked packet: {protocol} {ip_src}:{port_src} -> {ip_dst}:{port_dst}")
                    return False
                elif rule['action'] == 'ALLOW':
                    print(f"Allowed packet: {protocol} {ip_src}:{port_src} -> {ip_dst}:{port_dst}")
                    return True
    print("Packet dropped (no matching rule):")
    return False

def packet_callback(packet):
    if check_packet(packet):
        print("Packet passed through the firewall.")
    else:
        print("Packet blocked by the firewall.")

def start_sniffing():
    print("Starting packet sniffing...")
    scapy.sniff(prn=packet_callback, filter="ip", store=0)

if __name__ == "__main__":
    # Example rules
    add_rule('ALLOW', '192.168.1.10', 80, 'TCP')
    add_rule('BLOCK', '192.168.1.20', 53, 'UDP')
    
    # Start sniffing packets
    start_sniffing()