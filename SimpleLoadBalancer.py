from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
import time
import random

# Create logger
log = core.getLogger()

class SimpleLoadBalancer(object):

    def __init__(self, service_ip, server_ips = []):
        ''' Class initializer. '''
        core.openflow.addListeners(self)
        self.service_ip = service_ip
        self.server_ips = server_ips

        # Dict for servers, with IPs as keys and (mac,port) as values
        self.servers_ip_to_macport = {}
        # Dict for known servers, with IPs as keys and (mac,port) as values
        self.clients_ip_to_macport = {}

    def send_proxied_arp_request(self, connection, ip):
        ''' Send ARP request from the load balancer. '''
        arp_query = arp()
        arp_query.opcode = arp_query.REQUEST
        arp_query.hwtype = arp_query.HW_TYPE_ETHERNET
        arp_query.prototype = arp_query.PROTO_TYPE_IP
        arp_query.hwlen = 6
        arp_query.protodst = ip
        arp_query.protosrc = self.service_ip

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = ETHER_BROADCAST
        ether.src = self.lb_mac
        ether.set_payload(arp_query)
        
        log.debug("Sending ARP query")

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        connection.send(msg)

    def _handle_ConnectionUp(self, event):
        ''' Prepare the controller upon switch connection.'''
        # Fake load balancer MAC
        self.lb_mac = EthAddr("A0:00:00:00:00:01")
        self.connection = event.connection
        # ARP queries for server MAC
        for i in self.server_ips:
            self.send_proxied_arp_request(self.connection, i)

    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        ''' Send ARP reply from the load balancer. '''
        arp_query = arp()
        arp_query.hwsrc = requested_mac
        arp_query.hwdst = packet.src
        arp_query.opcode = arp_query.REPLY
        arp_query.prototype = arp_query.PROTO_TYPE_IP
        arp_query.protosrc = packet.payload.protodst#self.service_ip
        arp_query.protodst = packet.payload.protosrc

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = packet.src
        ether.src = self.lb_mac
        ether.set_payload(arp_query)
        
        log.debug("Sending ARP reply to " + str(arp_query.hwdst))

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        connection.send(msg)

    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        ''' Create a table flow entry from clients to servers. '''
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x800
        fm.match.nw_dst = self.service_ip
        fm.match.nw_src = client_ip
        fm.buffer_id = buffer_id
        fm.idle_timeout = 10
        (server_mac, server_port) = self.servers_ip_to_macport[server_ip]
        fm.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        fm.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        fm.actions.append(of.ofp_action_output(port = outport))
        connection.send(fm)
        log.debug("Install flow, server %s, client %s" % (str(server_ip), str(client_ip)))

    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        ''' Create a table flow entry from servers to clients. '''
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x800
        fm.match.nw_dst = client_ip
        fm.match.nw_src = server_ip
        fm.buffer_id = buffer_id
        fm.idle_timeout = 10
        fm.actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
        fm.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        (client_mac, client_port) = self.clients_ip_to_macport[client_ip]
        fm.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
        fm.actions.append(of.ofp_action_output(port = outport))
        connection.send(fm)
        log.debug("Install flow, server %s, client %s" % (str(server_ip), str(client_ip)))

    def resend_packet(self, connection, packet_in, outport):
        ''' Resend a packet to a specific port. '''
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port = outport)
        msg.actions.append(action)
        connection.send(msg)

    def _handle_PacketIn(self, event):
        ''' Deal with packets for which there is no match in the flow table. '''
        packet = event.parsed
        connection = event.connection
        inport = event.port
        
        if packet.type == packet.ARP_TYPE:
            srcip = packet.payload.protosrc
            dstip = packet.payload.protodst
            # Check for reply ARP 
            if packet.payload.opcode == arp.REPLY:
                if srcip in self.server_ips:
                    # Update servers table
                    self.servers_ip_to_macport[srcip] = (packet.src, inport)            
                    log.debug("ARP reply from server %s" % srcip)
                    log.debug("Current servers MAC table " + str(self.servers_ip_to_macport))
            # Check for request ARP
            if packet.payload.opcode == arp.REQUEST:
                # Keep the client information
                if srcip not in self.server_ips:
                    self.clients_ip_to_macport[srcip] = (packet.src, inport)
                    self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
                    log.debug("Clients updated, clients are " + str(self.clients_ip_to_macport))
                if srcip in self.server_ips:
                    if packet.payload.protodst in self.clients_ip_to_macport:
                        self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
                        log.debug("Reply server request, server " + str(srcip))
        
        elif packet.type == packet.IP_TYPE:
            srcip = packet.payload.srcip
            dstip = packet.payload.dstip
            if srcip in self.clients_ip_to_macport and dstip == self.service_ip:
                rand_server = list(self.servers_ip_to_macport.keys())[random.randint(0,3)]
                (server_mac, server_port) = self.servers_ip_to_macport[rand_server]
                self.install_flow_rule_client_to_server(self.connection, server_port, srcip, rand_server)
                (client_mac, client_port) = self.clients_ip_to_macport[srcip]
                self.install_flow_rule_server_to_client(self.connection, client_port, rand_server, srcip)
                # Resend the in_packet 
                packet.payload.dstip = rand_server
                packet.dst = server_mac
                self.resend_packet(self.connection, packet, server_port)
        else:
            log.info("Unknown Packet type: %s" % packet.type)
        return

def launch(ip, servers):
    ''' Launch the controller. '''
    log.info("Loading Simple Load Balancer module")
    server_ips = servers.replace(",", " ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(SimpleLoadBalancer, service_ip, server_ips)


