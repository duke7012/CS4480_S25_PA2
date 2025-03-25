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

# Server IPs and MACs (h5 and h6)
SERVERS = [
    {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
    {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
]

server_index = 0  # Round-robin tracker

class SDNLoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Load balancer initialized on switch %s", connection)

        self.client_mac_cache = {}           # IPAddr -> MAC
        self.client_server_map = {}          # (client_ip, virtual_ip) -> server dict

    def _handle_PacketIn(self, event):
        global server_index

        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if packet.type == pkt.ethernet.ARP_TYPE:
            arp = packet.payload
            src_ip = arp.protosrc
            dst_ip = arp.protodst
            src_mac = arp.hwsrc

            log.info("ARP REQUEST: who-has %s tell %s", dst_ip, src_ip)

            if src_ip in [s["ip"] for s in SERVERS]:
                return  # Ignore ARPs from backend servers

            self.client_mac_cache[src_ip] = src_mac
            log.info("Cached client MAC: %s → %s", src_ip, src_mac)

            key = (src_ip, dst_ip)
            if key not in self.client_server_map:
                server = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)
                self.client_server_map[key] = server
                log.info("Assigned server %s to client %s for VIP %s", server["ip"], src_ip, dst_ip)
            else:
                server = self.client_server_map[key]

            # ARP reply from virtual IP to client
            arp_reply = pkt.arp()
            arp_reply.opcode = pkt.arp.REPLY
            arp_reply.hwsrc = server["mac"]
            arp_reply.hwdst = src_mac
            arp_reply.protosrc = dst_ip
            arp_reply.protodst = src_ip

            eth = pkt.ethernet()
            eth.type = pkt.ethernet.ARP_TYPE
            eth.src = server["mac"]
            eth.dst = src_mac
            eth.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)

            log.info("Sent ARP reply for virtual IP %s to client %s", dst_ip, src_ip)
            self.install_forwarding_rules(event.port, src_ip, server, event, dst_ip)

        # Server ARP request for client IP
        elif packet.type == pkt.ethernet.ARP_TYPE:
            arp = packet.payload
            src_ip = arp.protosrc
            dst_ip = arp.protodst
            src_mac = arp.hwsrc

            if dst_ip in self.client_mac_cache:
                reply_mac = self.client_mac_cache[dst_ip]
                log.info("Replying to ARP from server for known client IP %s with MAC %s", dst_ip, reply_mac)

                arp_reply = pkt.arp()
                arp_reply.opcode = pkt.arp.REPLY
                arp_reply.hwsrc = reply_mac
                arp_reply.hwdst = src_mac
                arp_reply.protosrc = dst_ip
                arp_reply.protodst = src_ip

                eth = pkt.ethernet()
                eth.type = pkt.ethernet.ARP_TYPE
                eth.src = reply_mac
                eth.dst = src_mac
                eth.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)

                log.info("Sent ARP reply to server %s for client %s", src_ip, dst_ip)

        elif packet.type == pkt.ethernet.IP_TYPE:
            ip_packet = packet.payload
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip

            if src_ip in [s["ip"] for s in SERVERS]:
                log.info("Ignoring IP packet from server IP %s", src_ip)
                return

            key = (src_ip, dst_ip)
            server = self.client_server_map.get(key)
            if not server:
                log.warning("No server mapping for client %s and virtual IP %s", src_ip, dst_ip)
                return

            if src_ip not in self.client_mac_cache:
                self.client_mac_cache[src_ip] = packet.src

            self.install_forwarding_rules(event.port, src_ip, server, event, dst_ip)

            # Rewrite and forward the first packet
            ip_packet.dstip = server["ip"]
            packet.dst = server["mac"]

            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=self.mac_to_port_map[server["mac"]]))
            self.connection.send(msg)
            log.info("Forwarded packet to server %s for client %s via VIP %s", server["ip"], src_ip, dst_ip)

    def install_forwarding_rules(self, client_port, client_ip, server, event, virtual_ip):
        server_port = self.mac_to_port_map[server["mac"]]

        # Client → Server
        fm1 = of.ofp_flow_mod()
        fm1.match.in_port = client_port
        fm1.match.dl_type = 0x0800
        fm1.match.nw_dst = virtual_ip
        fm1.actions.append(of.ofp_action_nw_addr.set_dst(server["ip"]))
        fm1.actions.append(of.ofp_action_dl_addr.set_dst(server["mac"]))
        fm1.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(fm1)

        # Server → Client
        fm2 = of.ofp_flow_mod()
        fm2.match.in_port = server_port
        fm2.match.dl_type = 0x0800
        fm2.match.nw_src = server["ip"]
        fm2.match.nw_dst = client_ip
        fm2.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))
        fm2.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(fm2)

        log.info("Installed flows for %s ↔ %s via virtual IP %s", client_ip, server["ip"], virtual_ip)

    def mac_to_port(self, mac):
        return self.mac_to_port_map.get(mac, 1)

def launch():
    def start_switch(event):
        log.info("Controller now managing switch: %s", event.connection)
        SDNLoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
