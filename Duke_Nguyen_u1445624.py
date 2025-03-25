"""
SDN coded by Duke Nguyen (u1445624)
Programming Assignment 2: SDN
CS 4480 - Spring 2025
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt

log = core.getLogger("")

SERVERS = [
    {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
    {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
]

server_index = 0

class SDNLoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Load balancer initialized on switch %s", connection)

        self.client_mac_cache = {}                     # IPAddr -> MAC
        self.client_server_map = {}                    # (client_ip, VIP) -> server
        self.mac_to_port_map = {}                      # MAC -> port
        self.reverse_flows_installed = set()           # (server_ip, client_ip, vip)

    def _handle_PacketIn(self, event):
        global server_index

        packet = event.parsed
        if not packet.parsed:
            log.warning("Incomplete packet received")
            return

        self.mac_to_port_map[packet.src] = event.port

        if packet.type == pkt.ethernet.ARP_TYPE:
            arp = packet.payload
            src_ip = arp.protosrc
            dst_ip = arp.protodst
            src_mac = arp.hwsrc

            if src_ip in [s["ip"] for s in SERVERS]:
                if dst_ip in self.client_mac_cache:
                    reply_mac = self.client_mac_cache[dst_ip]
                    self.send_arp_reply(reply_mac, src_mac, dst_ip, src_ip, event.port)
                    log.info("Replied to ARP from server %s for client %s", src_ip, dst_ip)
                return

            self.client_mac_cache[src_ip] = src_mac
            key = (src_ip, dst_ip)
            if key not in self.client_server_map:
                server = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)
                self.client_server_map[key] = server
                log.info("Assigned server %s to client %s for VIP %s", server["ip"], src_ip, dst_ip)
            else:
                server = self.client_server_map[key]

            self.send_arp_reply(server["mac"], src_mac, dst_ip, src_ip, event.port)
            log.info("Sent ARP reply: VIP %s → client %s via server %s", dst_ip, src_ip, server["ip"])
            self.install_forwarding_rules(event.port, src_ip, server, dst_ip)

        elif packet.type == pkt.ethernet.IP_TYPE:
            ip_packet = packet.payload
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip

            # Server → Client
            if src_ip in [s["ip"] for s in SERVERS]:
                client_ip = dst_ip
                vip_match = None
                for (s_ip, c_ip, vip) in self.reverse_flows_installed:
                    if s_ip == src_ip and c_ip == client_ip:
                        vip_match = vip
                        break

                if vip_match is None:
                    log.warning("No VIP found for server %s → client %s", src_ip, client_ip)
                    return

                ip_packet.srcip = vip_match
                msg = of.ofp_packet_out()
                msg.data = packet.pack()
                msg.actions.append(of.ofp_action_output(port=self.mac_to_port(packet.dst)))
                self.connection.send(msg)

                log.info("Rewrote packet: server %s → client %s using VIP %s", src_ip, client_ip, vip_match)
                return

            # Client → VIP
            key = (src_ip, dst_ip)
            server = self.client_server_map.get(key)
            if not server:
                log.warning("No server assigned for client %s → VIP %s", src_ip, dst_ip)
                return

            self.client_mac_cache[src_ip] = packet.src
            self.install_forwarding_rules(event.port, src_ip, server, dst_ip)

            ip_packet.dstip = server["ip"]
            packet.dst = server["mac"]

            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=self.mac_to_port(server["mac"])))
            self.connection.send(msg)

            log.info("Forwarded client %s → server %s via VIP %s", src_ip, server["ip"], dst_ip)

    def install_forwarding_rules(self, client_port, client_ip, server, vip):
        server_port = self.mac_to_port(server["mac"])
        triple = (server["ip"], client_ip, vip)

        # Client → Server
        fm1 = of.ofp_flow_mod()
        fm1.match.in_port = client_port
        fm1.match.dl_type = 0x0800
        fm1.match.nw_dst = vip
        fm1.actions.append(of.ofp_action_nw_addr.set_dst(server["ip"]))
        fm1.actions.append(of.ofp_action_dl_addr.set_dst(server["mac"]))
        fm1.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(fm1)

        # Server → Client (record only, handled in controller)
        if triple not in self.reverse_flows_installed:
            self.reverse_flows_installed.add(triple)
            log.info("Tracking reverse path: %s → %s via VIP %s", server["ip"], client_ip, vip)

        log.info("Installed flow rules: %s ↔ %s via VIP %s", client_ip, server["ip"], vip)

    def send_arp_reply(self, src_mac, dst_mac, src_ip, dst_ip, out_port):
        arp_reply = pkt.arp()
        arp_reply.opcode = pkt.arp.REPLY
        arp_reply.hwsrc = src_mac
        arp_reply.hwdst = dst_mac
        arp_reply.protosrc = src_ip
        arp_reply.protodst = dst_ip

        eth = pkt.ethernet()
        eth.type = pkt.ethernet.ARP_TYPE
        eth.src = src_mac
        eth.dst = dst_mac
        eth.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def mac_to_port(self, mac):
        return self.mac_to_port_map.get(mac, 1)

def launch():
    def start_switch(event):
        log.info("Controller now managing switch: %s", event.connection)
        SDNLoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
