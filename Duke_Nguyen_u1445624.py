"""
SDN coded by Duke Nguyen (u1445624)
Programming Assignment 2: SDN
CS 4480 - Spring 2025
"""


from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

# Virtual IP that clients will ping
VIRTUAL_IP = IPAddr("10.0.0.10")

# Real server IPs and MACs (h5 and h6)
SERVERS = [
    {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
    {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
]

# Track the current server index for round-robin
server_index = 0

class SDNLoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Load balancer initialized on %s", connection)

    def _handle_PacketIn(self, event):
        global server_index

        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Handle ARP Requests to virtual IP
        if packet.type == pkt.ethernet.ARP_TYPE:
            arp_packet = packet.payload

            if arp_packet.opcode == pkt.arp.REQUEST and arp_packet.protodst == VIRTUAL_IP:
                log.info("Received ARP request for virtual IP from %s", arp_packet.protosrc)

                # Pick server using round-robin
                server = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)

                # Send ARP reply
                arp_reply = pkt.arp()
                arp_reply.opcode = pkt.arp.REPLY
                arp_reply.hwsrc = server["mac"]
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = arp_packet.protosrc

                eth = pkt.ethernet()
                eth.type = pkt.ethernet.ARP_TYPE
                eth.src = server["mac"]
                eth.dst = arp_packet.hwsrc
                eth.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)

                log.info("Replied to ARP with server MAC %s", server["mac"])

                # Push flow rules for ICMP forwarding
                self.install_forwarding_rules(event.port, arp_packet.protosrc, server)

    def install_forwarding_rules(self, client_port, client_ip, server):
        # Server port discovery (simple assumption: MAC-to-port mapping)
        server_port = self.mac_to_port(server["mac"])

        # Client to Server Rule
        fm1 = of.ofp_flow_mod()
        fm1.match.in_port = client_port
        fm1.match.dl_type = 0x0800  # IP
        fm1.match.nw_dst = VIRTUAL_IP
        fm1.actions.append(of.ofp_action_nw_addr.set_dst(server["ip"]))
        fm1.actions.append(of.ofp_action_dl_addr.set_dst(server["mac"]))
        fm1.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(fm1)

        # Server to Client Rule
        fm2 = of.ofp_flow_mod()
        fm2.match.in_port = server_port
        fm2.match.dl_type = 0x0800  # IP
        fm2.match.nw_src = server["ip"]
        fm2.match.nw_dst = client_ip
        fm2.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        fm2.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(fm2)

        log.info("Installed flow rules: %s ↔ %s", client_ip, server["ip"])

    def mac_to_port(self, mac):
        # Assumes static mapping:
        # h1-h6 ports are 1-6
        return int(str(mac)[-1])

def launch():
    def start_switch(event):
        log.info("Controlling %s", event.connection)
        SDNLoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
