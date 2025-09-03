# mitm6
![License: GPLv2](https://img.shields.io/pypi/l/mitm6.svg)

This is a fork of mitm6 which adds a number of features. The original version can be found at https://github.com/dirkjanm/mitm6

mitm6 is a pentesting tool that exploits the default configuration of Windows and all modern operating systems to take over the default DNS server and route. 

Modern operating systems are designed to use IPv6 as their primary networking protocol, and will use it in preference to any legacy protocols such as IPv4, IPX/SPX or NetBEUI that may be present.

Operators of legacy networks typically ignore IPv6 entirely. That is to say they don't implement it, don't factor it into their security monitoring and don't implement mitigations against IPv6-specific attacks.

This version of mitm6 sends out router advertisements via SLAAC, which is the primary method of auto configuring IPv6, and the default on virtually every device. It also supports DHCPv6 which as an optional protocol which can be used alongside SLAAC and provides additional features such as prefix delegation.

Mitm6 is designed to work together with [ntlmrelayx from impacket](https://github.com/CoreSecurity/impacket) for WPAD spoofing and credential relaying. It can also be used with tools such as Responder if the poisoning options are disabled and only the credential collection services are running.

## Dependencies and installation
mitm6 is compatible with Python 3.x. Support for Python 2.7 was available in the original version and hasn't been explicitly removed, but has not been tested as this version of Python is no longer supported.

mitm6 uses the following packages:
- Scapy
- Twisted
- netifaces

If the above packages are not provided by your system package manager, it is recommended to create a virtualenv before installing them with pip.

## Usage
After installation, mitm6 will be available as a command line program called `mitm6`. Since it uses raw packet capture with Scapy, it should be run as root. 
It is also possible to run the script directly from a checked out git repository, eg: python3 mitm6.py

For this version of mitm6 it is strongly recommended to bind a non link-local address to the host first, preferably a globally unique address within the 2000::/3 prefix. The reason for this is RFC6724 address selection which assigns the highest preference to globally unique addresses (GUAs).

It is possible to use the documentation prefix for this, for example:
ip addr add 2001:db8:666:666::1/64 dev eth0

However it is preferable to use a /64 of your own address space for this, as some devices may recognise the well known documentation prefix.

## Changes

This fork has a bunch of changes from the original version.

### Full SLAAC support

The previous mitm6 version implemented a minimal SLAAC response, just enough to instruct clients to activate DHCPv6.
Unlike legacy DHCP, DHCPv6 does not work on its own - it works as an optional extension of SLAAC. Standards following clients will only activate their DHCPv6 client once they receive a router advertisement with the Managed flag set.
Many devices do not support DHCPv6. Android has no support at all, Linux has no support in the kernel although some desktop-focused distros include userland support, embedded devices generally only support SLAAC as it's the core standard.

### Uses GUA addresses by default

As per RFC6724, different address classes have different preference. By default hosts will favour the GUA IPv6 space under 2000::/3. Link-local address space under fe80::/10 and ULA space receive a lower priority.

Using higher priority address space is more likely to override legacy traffic and thus be successful. ULA space in particular has a lower priority than legacy traffic in a dual stack setup, so would be unlikely to work.

### PREF64 support

Many modern operating systems support the PREF64 flag sent via RA. This causes these hosts to disable legacy IP, and use IPv6 exclusively for all traffic, with NAT64 used for accessing legacy resources.

This is currently supported by all Apple operating systems and some Linux distributions using NetworkManager. Microsoft have promised forthcoming support in Windows 11.

This should cause ALL traffic to be relayed through your mitm6 host. Use carefully as this may cause a DoS if your host is unable to forward the traffic anywhere.

### Prefix Delegation support

The primary use of DHCPv6 is actually prefix delegation. ISPs use it not to assign a single IP to your router, but to give your router a routable prefix that it can use for devices behind without having to resort to horrible kludges like NAT.

You can do the same with mitm6 - delegate a prefix to clients. If the client is a router of some kind it should then start announcing your routed prefix to the devices behind it. Virtualization stacks can also work the same way whereby the hypervisor receives a prefix delegation, and then makes it available to the virtual machines. Apple TV, Matter hubs, Thread routers and certain newer Android devices can also request a PD.

## Usage with ntlmrelayx
mitm6 is designed to be used with ntlmrelayx. You should run the tools next to each other, in this scenario mitm6 will spoof the DNS, causing victims to connect to ntlmrelayx for HTTP and SMB connections. For this you have to make sure to run ntlmrelayx with the `-6` option, which will make it listen on both IPv4 and IPv6. To obtain credentials for WPAD, specify the WPAD hostname to spoof with `-wh HOSTNAME` (any non-existing hostname in the local domain will work since mitm6 is the DNS server). Optionally you can also use the `-wa N` parameter with a number of attempts to prompt for authentication for the WPAD file itself in case you suspect victims do not have the MS16-077 patch applied.

## Usage with krbrelayx
You can also use mitm6 to relay Kerberos authentication, especially via DNS. To do this, use the `--relay` parameter and specify a host that you want to relay to. This host will be impersonated, and mitm6 will try to convince your victims to send authenticated dynamic updates using Kerberos authentication to krbrelayx. More info about this attack is available on the following blog: <https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/>

## Fixing / Mitigation

The correct way to fix this kind of attack is to implement IPv6 properly on your network, ensuring that network security devices like firewalls, IDS, IPS, NAC etc are fully IPv6-aware and properly monitoring your v6 deployment. You should then also implement IPv6-specific security measures such as RA Guard, MLD snooping and possibly SEND.

