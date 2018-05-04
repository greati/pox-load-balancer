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
        # Fake load balancer MAC
        self.lb_mac = EthAddr("A0:00:00:00:00:01")
        self.connection = event.connection
        # ARP queries for server MAC
        for i in self.server_ips:
            self.send_proxied_arp_request(self.connection, i)

    def update_lb_mapping(self, client_ip):
        ''' Update load balancing mappiing. '''
        pass
        #TODO

    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
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
        pass
        #TODO

    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        pass
        #TODO

    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        
        if packet.type == packet.ARP_TYPE:
            # The source IP
            srcip = packet.payload.protosrc
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
            pass
            #TODO
        else:
            log.info("Unknown Packet type: %s" % packet.type)
        return

def launch(ip, servers):
    log.info("Loading Simple Load Balancer module")
    server_ips = servers.replace(",", " ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(SimpleLoadBalancer, service_ip, server_ips)


