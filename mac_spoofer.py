from subprocess import call, check_output, check_call, CalledProcessError
from argparse import ArgumentParser, ArgumentError
from re import search
from typing import NamedTuple, Optional

class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    interface: str
    mac: str
    verbose: bool

def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options.
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-i', '--interface', dest='interface', help='The name of the desired network interface')
        parser.add_argument('-m', '--mac', dest='mac_addr', help='The new MAC address to be assigned to the network interface')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.interface or not options.mac_addr: 
            error('Invalid arguments. You must provide both a valid interface and MAC address.')
        if not options.verbose:
            options.verbose = False
        return Options(options.interface, options.mac_addr, options.verbose)
    except ArgumentError as e:
        error('An argument occurred while parsing input arguments.')
        return

def change_mac(interface: str, new_mac: str) -> None:
    '''
    Changes the MAC address of the desired network interface device to new_mac.
    '''
    try:
        check_call(['ifconfig', interface, 'down'])
        check_call(['ifconfig', interface, 'hw', 'ether', new_mac])
        check_call(['ifconfig', interface, 'up'])
    except (CalledProcessError, OSError) as e:
        error('An exception ocurred while modifying MAC address.')

def get_mac(interface: str) -> Optional[str]:
    '''
    Returns a MAC address string for the desired network interface name.
    '''
    try:
        ifconfig_str = check_output(['ifconfig', interface])
    except (CalledProcessError, OSError) as e:
        error('An exception ocurred while reading network interface information.')
    mac = search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', str(ifconfig_str))
    return mac.group(0)


def error(msg: str) -> None:
    '''
    Prints an error message to standard output before exiting
    '''
    print(f'[-] {msg} Exiting...')
    exit()

def main(*args, **kwargs) -> None:
    config = get_args()
    current_mac = get_mac(config.interface)
    print(f'[+] Current MAC address of {config.interface} is {current_mac}')
    print(f'[+] Attempting to change MAC address to {config.mac}')
    change_mac(config.interface, config.mac)
    new_mac = get_mac(config.interface)

    if current_mac == new_mac:
        error(f'Failed to change MAC address of {config.interface}.')
    
    print(f'[+] MAC address of {config.interface} successfuly changed to {new_mac}')

if __name__ == "__main__": main()