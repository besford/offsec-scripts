from scapy.all import ARP, Ether, srp, send, sniff
from typing import NamedTuple, Union, Optional, Tuple
from argparse import ArgumentParser, ArgumentError

class Options(NamedTuple):
    interface: str
    verbose: bool

acks = []

def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-i', '--interface', dest='interface', help='Interface to sniff ARP packets on.')
        parser.add_argument('-s', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.interface:
            error('Interface must be specified')
        if not options.verbose:
            options.verbose = False
        return Options(options.interface, options.verbose)
    except ArgumentError as e:
        error('An error occurred while parsing input arguments.')
        return

def get_mac(ip: str) -> None:
    '''
    Determines the corresponding MAC address for a given IP address
    '''
    assert isinstance(ip, str)
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast / arp_req
    resp_list = srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    return resp_list[0][1].hwsrc

def proc_arp_packets(packet) -> None:
    '''
    Evaluates a given ARP packet for discrepancies in its source MAC address fields
    '''
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            real_mac = get_mac(packet[ARP].psrc)
            resp_mac = packet[ARP].hwsrc
            if real_mac != resp_mac:
                print(f'[+] ARP discrepancy detected: \n\t Expected: {real_mac} \tCurrent: {resp_mac}')
        except IndexError:
            pass

def sniff_arp(interface: str):
    '''
    Sniffs packets sent through a given network interface. Detected arp packets are further
    processed to determine discrepancies.
    '''
    sniff(iface=interface, store=False, prn=proc_arp_packets)

def error(msg: str) -> None:
    '''
    Prints an error message to standard output before exiting
    '''
    print(f'[-] {msg} Exiting...')
    exit()

def main(*args, **kwargs) -> None:
    global config
    config = get_args()
    try:
        sniff_arp(config.interface)
    except (KeyboardInterrupt, InterruptedError):
        print('\n[+] Detected interrupt. Exiting...')


if __name__ == "__main__":
    main()