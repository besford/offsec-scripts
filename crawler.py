from requests import get, ConnectionError
from urllib.parse import urljoin
from re import findall
from time import sleep
from argparse import ArgumentParser, ArgumentError
from typing import NamedTuple, Optional, List
from dataclasses import dataclass


class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    target: str
    discover_dirs: bool
    discover_subdoms: bool
    discover_doms: bool
    verbose: bool


@dataclass
class Index:
    found_dirs: set
    found_doms: set
    found_subdoms: set

    def append_dir(self, directory: str) -> None:
        self.found_dirs.add(directory)

    def append_dom(self, domain: str) -> None:
        self.found_doms.add(domain)

    def append_subdom(self, subdomain: str) -> None:
        self.found_subdoms.add(subdomain)

    def is_indexed(self, url: str) -> bool:
        return (url in self.found_dirs) or (url in self.found_doms) or (url in self.found_subdoms)


class Crawler(object):
    '''
    Provides functionality for systemically indexing directories, domains, and subdomains on a target url.
    '''
    def __init__(self, target: str):
        self.target = target
        self.index = Index()

    def __request(self, url: str) -> str:
        try:
            req = get(f'http://{url}')
            return req
        except ConnectionError:
            pass

    def __extract_hrefs(self, url: str) -> List[str]:
        resp = get(url)
        hrefs = findall(r'(?:href=")(.*?)"', resp.content.decode(errors='ignore'))
        return hrefs

    def __index_dir(self, directory: str) -> None:
        self.index.append_dir(directory)

    def __index_dom(self, domain: str) -> None:
        self.index.append_dom(domain)

    def __index_subdom(self, subdomain: str) -> None:
        self.index.append_subdom(subdomain)
    
    def __in_index(self, url: str) -> None:
        return self.index.is_indexed(url)

    def discover_urls(self, url: str = '') -> None:
        hrefs = self.__extract_hrefs(url)
        global config
        for link in hrefs:
            #sleep(1)
            link = urljoin(url, link)
            if '#' in link:
                link = link.split('#')[0]
            #print('10.0.2.17' in link and link not in self.found_doms)
            if config.target.split('//')[-1] in link and link not self.__in_index(link):
                self.__index_dom(link)
                print(f'[+] urls >> {link}')
                self.discover_urls(link)

    def discover_subdoms(self, url: str = '') -> None:
        with open(file='subdomains.txt', mode='r') as subdoms:
            for line in subdoms:
                subdom = line.strip()
                test_url = f'{subdom}.{url}'
                resp = self.__request(test_url)
                if resp:
                    print(f'[+] Subdomain found >> {test_url}')
                    self.__index_subdom(subdom)

    def discover_dirs(self, url: str = '') -> None:
        with open(file='dirs.txt', mode='r') as dirs:
            for line in dirs:
                cur_dir = line.strip()
                test_url = f'{url}/{cur_dir}'
                resp = self.__request(test_url)
                if resp:
                    print(f'[+] Directory found >> {test_url}')
                    self.__index_dir(cur_dir)

    def print_summary(self):
        pass


def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options.
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-t', '--target', dest='target', help='Target domain to discover domains, subdomains, and directories for.')
        parser.add_argument('-s', '--subdoms', action='store_true', help='Enable discovery of subdomains on target.')
        parser.add_argument('-d', '--dirs', action='store_true', help='Enable discovery of directories on target.')
        parser.add_argument('-u', '--doms', action='store_true', help='Enable discovery of domains on target.')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.target: 
            error('Invalid arguments. You must provide a valid target url. See help for more info.')
        if not options.verbose:
            options.verbose = False
        if not options.dirs:
            options.dirs = False
        if not options.subdoms:
            options.subdoms = False
        if not options.doms:
            options.doms = False
        return Options(options.target, options.dirs, options.subdoms, options.doms, options.verbose)
    except ArgumentError as e:
        error('An error occurred while parsing input arguments.')
        return


def error(msg: str) -> None:
    '''
    Prints an error message to standard output before exiting
    '''
    print(f'[-] {msg} Exiting...')
    exit()


def main(*args, **kwargs) -> None:
    global config
    config = get_args()
    crawler = Crawler('')
    if config.discover_doms:
        print(f'[+] Discovering domains on {config.target}...')
        crawler.discover_urls(config.target)
    if config.discover_subdoms:
        print(f'[+] Discovering subdoms on {config.target}...')
        crawler.discover_subdoms(config.target)
    if config.discover_dirs:
        print(f'[+] Discovering directories on {config.target}...')
        crawler.discover_dirs(config.target)
    print('[+] Finished all tasks.')

if __name__ == "__main__": main()