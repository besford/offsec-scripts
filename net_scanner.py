from scapy.all import ARP, Ether, srp
from argparse import ArgumentParser, ArgumentError
from typing import NamedTuple, Optional, List

class Options(NamedTuple):
    target: str
    verbose: bool

class Client(NamedTuple):
    ip: str
    mac: str

def get_args() -> 'Options':
    parser = ArgumentParser()
    try:
        parser.add_argument('-t', '--target', dest='target', help='IP range for target device(s) or network.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.target: 
            error('Invalid arguments. You must provide a valid IP range or device IP. See help for more info.')
        if not options.verbose:
            options.verbose = False
        return Options(options.target, options.verbose)
    except ArgumentError as e:
        error('An error occurred while parsing input arguments.')
        return

def scan(ip_range: str, time: int) -> List['Client']:
    '''
    Scans a desired ip range for a specified time in seconds using ARP requests. Returns a list of Client objects representing each host discovered during the scan.
    '''
    assert isinstance(ip_range, str)
    clients = []
    arp_req = ARP(pdst=ip_range)
    broadcast_frame = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast_frame / arp_req
    responses = srp(arp_req_broadcast, timeout=time, verbose=False)[0]
    for resp in responses:
        clients.append(Client(ip=resp[1].psrc, mac=resp[1].hwsrc))
    return clients

def print_results(results: List['Client']) -> None:
    print('IP''s \t\t\t MAC''s')
    print('-----------------------------')
    for client in results:
        print(f'{client.ip} \t\t {client.mac}')

def error(msg: str) -> None:
    '''
    Prints an error message to standard output before exiting
    '''
    print(f'[-] {msg} Exiting...')
    exit()

def main(*args, **kwargs) -> None:
    config = get_args()
    print('[+] Scanning target IP range...')
    results = scan(ip_range=config.target, time=5)
    print_results(results)

if __name__ == "__main__": main()