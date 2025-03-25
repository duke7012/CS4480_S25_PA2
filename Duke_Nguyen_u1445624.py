"""
SDN Load Balancer Controller
Author: Duke Nguyen (u1445624)
Course: CS 4480 - Spring 2025

This POX controller implements a simple Software-Defined Network (SDN) load balancer.
Clients send ICMP (ping) requests to a virtual IP address. The controller intercepts
ARP requests for the virtual IP, assigns backend servers (round-robin), and rewrites
packet headers to transparently redirect traffic to the selected server.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

# List of real backend servers with static IP/MAC
SERVERS = [
    {"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05")},
    {"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06")},
]

server_index = 0  # Used for round-robin server selection

class SDNLoadBalancer(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Load balancer initialized on switch %s", connection)

        self.client_mac_cache = {}        # Maps client IP → MAC
        self.client_server_map = {}       # Maps (client IP, VIP) → server
        self.mac_to_port_map = {}         # Tracks MAC → port mappings

    def _handle_PacketIn(self, event):
        """
        Handles all incoming packets from the switch. Intercepts ARP requests
        and IP traffic from clients:
        - Responds to ARP requests to virtual IPs with spoofed replies using backend server MACs.
        - Caches client MACs for future replies.
        - Assigns backend servers using round-robin.
        - Installs bidirectional flow rules for efficient packet handling.
        - Rewrites destination IP/MAC of packets to transparently redirect traffic.

        Args:
            event: The OpenFlow event containing the incoming packet.
        """
        global server_index

        packet = event.parsed
        if not packet.parsed:
            log.warning("Incomplete packet received")
            return

        # Update MAC-to-port mapping
        self.mac_to_port_map[packet.src] = event.port

        # Handle ARP traffic
        if packet.type == pkt.ethernet.ARP_TYPE:
            arp = packet.payload
            src_ip = arp.protosrc
            dst_ip = arp.protodst
            src_mac = arp.hwsrc

            log.info("ARP request from: %s to: %s", src_ip, dst_ip)

            # If a server ARPs for a client (i.e., reverse direction)
            if src_ip in [s["ip"] for s in SERVERS]:
                if dst_ip in self.client_mac_cache:
                    reply_mac = self.client_mac_cache[dst_ip]
                    self.send_arp_reply(reply_mac, src_mac, dst_ip, src_ip, event.port)
                    log.info("Replied to ARP from server %s for client %s", src_ip, dst_ip)
                return

            # If client ARPs for a real server (not a virtual IP), ignore
            if dst_ip in [s["ip"] for s in SERVERS]:
                return

            # Cache client MAC for future replies
            self.client_mac_cache[src_ip] = src_mac
            key = (src_ip, dst_ip)  # (client, VIP)

            # Assign a backend server for this client/VIP pair
            if key not in self.client_server_map:
                server = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)
                self.client_server_map[key] = server
                log.info("Assigned server %s to client %s for VIP %s", server["ip"], src_ip, dst_ip)
            else:
                server = self.client_server_map[key]

            # Send spoofed ARP reply with the selected server's MAC
            self.send_arp_reply(server["mac"], src_mac, dst_ip, src_ip, event.port)
            log.info("Sent ARP reply: VIP %s → client %s via server %s", dst_ip, src_ip, server["ip"])

            # Install bidirectional IP flow rules
            self.install_forwarding_rules(event.port, src_ip, server, dst_ip)

        # Handle IP traffic (ICMP ping requests)
        elif packet.type == pkt.ethernet.IP_TYPE:
            ip_packet = packet.payload
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip
            log.info("ICMP request from: %s to %s", src_ip, dst_ip)

            key = (src_ip, dst_ip)
            server = self.client_server_map.get(key)
            if not server:
                log.warning("No server assigned for client %s → VIP %s", src_ip, dst_ip)
                return

            # Rewrite destination IP and MAC to forward to real server
            ip_packet.dstip = server["ip"]
            packet.dst = server["mac"]

            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=self.mac_to_port(server["mac"])))
            self.connection.send(msg)

            log.info("Forwarded client %s → server %s via VIP %s", src_ip, server["ip"], dst_ip)


    def install_forwarding_rules(self, client_port, client_ip, server, virtual_ip):
        """
        Installs flow rules in the switch for traffic between a client and its
        assigned server through the virtual IP.

        - Rewrites destination IP and MAC for packets from client → VIP.
        - Rewrites source IP for packets from server → client.

        Args:
            client_port: Switch port the client is connected to.
            client_ip: IP address of the client host.
            server: Dict containing IP and MAC of the assigned backend server.
            virtual_ip: The VIP the client is targeting.
        """
        server_port = self.mac_to_port(server["mac"])

        # Flow: Client → VIP
        fm1 = of.ofp_flow_mod()
        fm1.match.in_port = client_port
        fm1.match.dl_type = pkt.ethernet.IP_TYPE
        fm1.match.nw_dst = virtual_ip
        fm1.actions.append(of.ofp_action_nw_addr.set_dst(server["ip"]))
        fm1.actions.append(of.ofp_action_dl_addr.set_dst(server["mac"]))
        fm1.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(fm1)

        # Flow: Server → Client
        fm2 = of.ofp_flow_mod()
        fm2.match.in_port = server_port
        fm2.match.dl_type = pkt.ethernet.IP_TYPE
        fm2.match.nw_src = server["ip"]
        fm2.match.nw_dst = client_ip
        fm2.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))
        fm2.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(fm2)

        log.info("Installed flow rules: %s ↔ %s via VIP %s", client_ip, server["ip"], virtual_ip)

    def send_arp_reply(self, src_mac, dst_mac, src_ip, dst_ip, out_port):
        """
        Constructs and sends an ARP reply packet directly to a host.

        Args:
            src_mac: The MAC address to respond with.
            dst_mac: The destination MAC (requester).
            src_ip: The source IP to place in the ARP reply.
            dst_ip: The destination IP (who made the request).
            out_port: The switch port to send the reply out on.
        """
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
        """
        Looks up the switch port associated with a given MAC address.
        Defaults to port 1 if the MAC has not been seen yet.

        Args:
            mac: The MAC address to resolve.

        Returns:
            int: The switch port number.
        """
        return self.mac_to_port_map.get(mac, 1)

def launch():
    """
    Entry point for the POX controller. Called when POX starts this module.
    Registers the controller to listen for new switch connections and assigns
    SDNLoadBalancer to manage them.
    """
    def start_switch(event):
        log.info("Controller now managing switch: %s", event.connection)
        SDNLoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
