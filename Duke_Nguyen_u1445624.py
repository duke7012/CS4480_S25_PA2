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

# Server IPs and MACs (h5 and h6)
SERVERS = [
    {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
    {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
]

# Track the current server index for round-robin
server_index = 0

class SDNLoadBalancer(object):
    def __init__(self, connection):
        self.client_mac_cache = {}  # IPAddr → EthAddr
        self.client_server_map = {}  # Maps IPAddr (client) → server dict

        self.connection = connection
        connection.addListeners(self)
        log.info("Load balancer initialized on switch %s", connection)

        self.mac_to_port_map = {
            EthAddr("00:00:00:00:00:01"): 1,
            EthAddr("00:00:00:00:00:02"): 2,
            EthAddr("00:00:00:00:00:03"): 3,
            EthAddr("00:00:00:00:00:04"): 4,
            EthAddr("00:00:00:00:00:05"): 5,
            EthAddr("00:00:00:00:00:06"): 6,
        }

    def _handle_PacketIn(self, event):
        global server_index

        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Handle ARP packets only
        if packet.type == pkt.ethernet.ARP_TYPE:
            arp_packet = packet.payload
            src_ip = arp_packet.protosrc
            dst_ip = arp_packet.protodst
            src_mac = arp_packet.hwsrc

            log.info("ARP REQUEST: who-has %s tell %s", dst_ip, src_ip)

            if arp_packet.opcode == pkt.arp.REQUEST:

                # Case 1: ARP for virtual IP (from client)
                if dst_ip == VIRTUAL_IP:
                    log.info("ARP is for virtual IP. Triggering load balancer selection.")

                    if src_ip not in [server["ip"] for server in SERVERS]:
                        self.client_mac_cache[src_ip] = src_mac
                        log.info("Cached client MAC: %s → %s", src_ip, src_mac)

                    if src_ip not in self.client_server_map:
                        server = SERVERS[server_index]
                        server_index = (server_index + 1) % len(SERVERS)
                        self.client_server_map[src_ip] = server
                        log.info("Assigned server %s to client %s", server["ip"], src_ip)
                    else:
                        server = self.client_server_map[src_ip]
                        log.info("Client %s already assigned to server %s", src_ip, server["ip"])


                    log.info("Selected server: %s (%s)", server["ip"], server["mac"])

                    # Craft ARP reply
                    arp_reply = pkt.arp()
                    arp_reply.opcode = pkt.arp.REPLY
                    arp_reply.hwsrc = server["mac"]
                    arp_reply.hwdst = src_mac
                    arp_reply.protosrc = VIRTUAL_IP
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

                    log.info("Sent ARP reply for virtual IP to %s", src_ip)
                    log.info("Installing forwarding rules for %s <-> %s", src_ip, server["ip"])

                    self.install_forwarding_rules(event.port, src_ip, server, event)

                # Case 2: Server ARPing for client IP
                elif dst_ip in self.client_mac_cache:
                    reply_mac = self.client_mac_cache[dst_ip]
                    log.info("Server is ARPing for client IP %s. Using cached MAC %s.", dst_ip, reply_mac)

                    # Craft ARP reply
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

                    log.info("Replied to server ARP with cached client MAC.")
        # Handle IP packets (ICMP only) directed to the virtual IP
        elif packet.type == pkt.ethernet.IP_TYPE:
            ip_packet = packet.payload

            if ip_packet.dstip == VIRTUAL_IP:
                src_ip = ip_packet.srcip
                src_mac = packet.src
                dst_mac = packet.dst

                log.info("Intercepted ICMP packet to virtual IP from %s", src_ip)

                # If this client hasn't been mapped to a server yet (i.e., no flow installed),
                # perform round-robin selection and cache the MAC
                if src_ip not in self.client_mac_cache:
                    self.client_mac_cache[src_ip] = src_mac
                    log.info("Cached client MAC (from ICMP): %s → %s", src_ip, src_mac)

                server = self.client_server_map.get(src_ip)
                if not server:
                    log.warning("No server mapping found for client %s during ICMP handling", src_ip)
                    return


                log.info("Selected server for direct ICMP redirect: %s (%s)", server["ip"], server["mac"])

                self.install_forwarding_rules(event.port, src_ip, server, event)

                # Rewrite IP and MAC headers and resend the packet manually
                eth = packet
                ip = ip_packet

                ip.dstip = server["ip"]
                eth.dst = server["mac"]

                msg = of.ofp_packet_out()
                msg.data = eth.pack()
                msg.actions.append(of.ofp_action_output(port=self.mac_to_port_map[server["mac"]]))
                self.connection.send(msg)

                log.info("Rewrote and sent first ICMP packet to server %s", server["ip"])


    def install_forwarding_rules(self, client_port, client_ip, server, event):
        server_port = self.mac_to_port_map[server["mac"]]

        # Client to Server
        fm1 = of.ofp_flow_mod()
        fm1.match.in_port = client_port
        fm1.match.dl_type = 0x0800  # IP
        fm1.match.nw_dst = VIRTUAL_IP
        fm1.actions.append(of.ofp_action_nw_addr.set_dst(server["ip"]))
        fm1.actions.append(of.ofp_action_dl_addr.set_dst(server["mac"]))
        fm1.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(fm1)
        log.info("Flow (Client → Server): port %s → %s on port %s", client_port, server["ip"], server_port)

        # Server to Client
        fm2 = of.ofp_flow_mod()
        fm2.match.in_port = server_port
        fm2.match.dl_type = 0x0800  # IP
        fm2.match.nw_src = server["ip"]
        fm2.match.nw_dst = client_ip
        fm2.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        fm2.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(fm2)
        log.info("Flow (Server → Client): port %s → %s on port %s", server_port, client_ip, client_port)


    def mac_to_port(self, mac):
        return int(str(mac)[-1])

def launch():
    def start_switch(event):
        log.info("Controller now managing switch: %s", event.connection)
        SDNLoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
