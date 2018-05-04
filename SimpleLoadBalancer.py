import pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
import time
import random

# Create logger
log = core.getLogger()

class SimpleLoadBalancer(object):

    def __init__(self, service_ip, server_ips = []):
        ''' Class initializer. '''
        core.openflow.addListeners(self)
        #TODO

    def _handle_ConnectionUp(self, event):
        ''' New switch connection handler. '''
        # Fake load balancer MAC
        self.lb_mac = EthAddr("A0:00:00:00:00:01")
        self.connection = connection
        #TODO

    def update_lb_mapping(self, client_ip):
        ''' Update load balancing mappiing. '''
        #TODO

    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        #TODO

    def send_proxied_arp_request(self, connection, ip):
        #TODO

    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        #TODO

    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER)
        #TODO

    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        
        if packet.type == packet.ARP_TYPE:
            #TODO
        elif packet.type == packet.IP_TYPE:
            #TODO
        else:
            log.info("Unknown Packet type: %s" % packet.type)
        return

def launch(ip, servers):
    log.info("Loading Simple Load Balancer module")
    server_ips = servers.replace(",", " ").split()
    server_ips = [IpAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(SimpleLoadBalancer, service_ip, server_ips)


