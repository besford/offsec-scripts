from argparse import ArgumentError, ArgumentParser
from re import findall, search
from typing import Any, Callable, List, NamedTuple, Set, Type, TypeVar, cast
from urllib.parse import urljoin
from time import time_ns
from bs4 import BeautifulSoup
from requests import Session


ERRORS = {
    # MySQL and Postgres
    "you have an error in your sql syntax;",
    "warning: mysql",
    # SQL Server
    "unclosed quotation mark after the character string",
    # Oracle
    "quoted string not properly terminated",
}


class Options(NamedTuple):
    '''
    Tuple for storing configuration constants.
    '''
    target_url: str
    xss_payload: str
    sqli_payload: str
    cmd_payload: str
    verbose: bool


class Scanner(object):
    '''
    Provides functionality for scanning a target url for various classes of common web vulnerabilities. 
    '''
    target_url: str
    target_links: Set[str]
    blacklisted_links: Set[str]
    cmd_payload: str
    xss_payload: str
    sqli_payload: str

    def __init__(self, url: str = '', ignore_links: List[str] = [''], xss_payload: str = '', sqli_payload: str = '', cmd_payload: str = '') -> None:
        self.session = Session()
        self.target_url = url
        self.target_links = set()
        self.blacklisted_links = set(ignore_links)
        self.num_vulns = 0
        if xss_payload == '': 
            self.xss_payload = "<sCript>alert('hi!!!')</scriPt>"
        else:
            self.xss_payload = xss_payload

        if cmd_payload == '':
            self.cmd_payload = 'echo \'vulnerable\''
        else:
            self.cmd_payload = cmd_payload

        if sqli_payload == '':
            #self.sqli_payload = "'AND sleep(30)#"
            self.sqli_payload = "(select(0)from(select(sleep(60)))v)/*\'+(select(0)from(select(sleep(60)))v)+\'\"+(select(0)from(select(sleep(60)))v)+\"*/"
        else:
            self.sqli_payload = sqli_payload

    def __extract_forms(self, url: str = '') -> 'ResultSet':
        '''
        Extracts all web forms present in a target url. Returns a ResultSet containing any 
        form strings found in the url.
        '''
        resp = self.session.get(url)
        parsed_html = BeautifulSoup(resp.content, features='lxml')
        return parsed_html.findAll('form')

    def __extract_hrefs(self, url: str = '') -> List[str]:
        '''
        Extracts all href address strings present in a target url. Returns a list of strings representing
        the collection of addresses found.
        '''
        resp = self.session.get(url)
        return findall('(?:href=")(.*?)"', resp.content.decode(errors='ignore'))

    def crawl(self, url: str = '') -> None:
        '''
        Explores all 
        '''
        if url == '': url = self.target_url
        hrefs = self.__extract_hrefs(url)
        for link in hrefs:
            link = urljoin(url, link)
            if '#' in link: 
                link = link.split('#')[0]
            if self.target_url in link and link not in self.target_links and link not in self.blacklisted_links:
                print(link)
                self.target_links.add(link)
                self.crawl(link)
    
    def login(self, url: str = '', login_data: dict = dict()):
        '''
        Performs a login request on the provided url.
        '''
        resp = self.session.post(url, data=login_data)
        return resp

    def submit_form(self, form: str = '', value: str = '', url: str = ''):
        '''
        Performs the process of submitting a web form using provided input data.
        '''
        action = form.get('action')
        method = form.get('method')
        post_url = urljoin(url, action)
        inputs = form.findAll('input')
        post_data = {}
        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type')
            input_value = input_field.get('value')
            if input_type == 'text': input_value = value
            post_data[input_name] = input_value
        if method == 'post': return self.session.post(url=post_url, data=post_data)
        return self.session.get(url=post_url, params=post_data)

    def is_cmd_in_url(self, url: str = '') -> bool:
        raise NotImplementedError('Todo')

    def is_cmd_in_form(self, url: str = '') -> bool:
        raise NotImplementedError('Todo')

    def is_xss_in_url(self, url: str = '') -> bool:
        '''
        Determines whether or not a given url contains a potential cross-site scripting vulnerability.
        '''
        url = url.replace('=', '='+self.xss_payload)
        resp = self.session.get(url)
        return self.xss_payload.encode() in resp.content

    def is_xss_in_form(self, form: str, url: str) -> bool:
        '''
        Determines whether or not a given web form contains a potential cross-site scripting vulnerability.
        '''
        resp = self.submit_form(form, self.xss_payload.encode(), url)
        return self.xss_payload.encode() in resp.content

    def is_code_injectable(self, url: str) -> bool:
        raise NotImplementedError('Todo')

    def is_sqli_in_url(self, url: str) -> bool:
        '''
        Determines whether or not a given url contains a potential SQL injection vulnerability.
        '''
        url = url.replace('=', '='+self.sqli_payload[0])
        start = time_ns()
        resp = self.session.get(url=url)
        end = time_ns()
        resp_delay = end - start
        #print(resp_delay)
        for error in ERRORS:
            if error in resp.content.decode().lower(): return True
        if resp_delay >= 30000000: return True
        return False

    def is_sqli_in_form(self, form: str, url: str) -> bool:
        '''
        Determines whether or not a given we form contains a potential SQL injection vulnerability.
        '''
        start = time_ns()
        resp = self.submit_form(form, self.sqli_payload.encode(), url)
        end = time_ns()
        resp_delay = end - start
        for error in ERRORS:
            if error in resp.content.decode().lower(): return True
        if resp_delay >= 30000000: return True
        return False

    def run(self):
        '''
        Initiates the process of vulnerability discovery over a list of discovered target urls. Each url is tested directly for supported 
        class of vulnerability; any forms found at the target url are extracted and also tested.
        '''
        for link in self.target_links:
            forms = self.__extract_forms(link)
            for form in forms:
                print(f'Testing form in {link}')
                if self.is_xss_in_form(form, link):
                    print(''.center(80, '-'))
                    print(f'[+] Potential XSS vulnerability found in {link} for form: \n{form}')
                    self.num_vulns += 1
                    print(''.center(80, '-'))
                if self.is_sqli_in_form(form, link):
                    print(f'[+] Potential SQL Injection vulnerability found in {link} for form: \n{form}')
                    self.num_vulns += 1
            if '=' in link:
                print(f'Testing {link}')
                if self.is_xss_in_url(link):
                    print(''.center(80, '-'))
                    print(f'[+] Potential XSS vulnerability found in {link}')
                    self.num_vulns += 1
                    print(''.center(80, '-'))
                if self.is_sqli_in_url(link):
                    print(f'[+] Potential SQL Injection vulnerability found in {link}')
                    self.num_vulns += 1


def get_args() -> 'Options':
    '''
    Parses command arguments for initialization of config options.
    '''
    parser = ArgumentParser()
    try:
        parser.add_argument('-u', '--url', dest='url', help='Target domain to discover domains, subdomains, and directories for.')
        parser.add_argument('-s', '--script', dest='script', help='Test script to use against target url')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for debugging purposes.')
        options = parser.parse_args()
        if not options.url: 
            error('Invalid arguments. You must provide a valid target url. See help for more info.')
        if not options.verbose:
            options.verbose = False
        if not options.script:
            options.script = ''
        if not options.ignore_links:
            options.ignore_links = ['']
        return Options(options.url, options.script, options.verbose)
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
    target_dom = 'http://10.0.2.5/dvwa/'
    login_url = 'http://10.0.2.5/dvwa/login.php'
    ignore_list = ['http://10.0.2.5/dvwa/logout.php']
    print(f'[+] Starting vulnerability scanner on {target_dom}')
    vuln_scanner = Scanner(url=target_dom, ignore_links=ignore_list)
    login_data = {
        "username":"admin",
        "password":"",
        "Login":"submit"
    }

    print(f'[+] Logging into {target_dom} as {login_data["username"]}...')
    login_resp = vuln_scanner.login(login_url, login_data)
    if login_resp.status_code == 200:
        print(f'[+] Successfully logged in as {login_data["username"]}')
    else:
        error(f'Unable to login to {target_dom}')

    print(f'[+] Discovering links...')
    print(''.center(80, '-'))
    vuln_scanner.crawl()

    print(f'\n[+] Testing for vulnerabilities...')
    print(''.center(80, '-'))
    vuln_scanner.run()
    if vuln_scanner.num_vulns > 0:
        print(f'[+] Scan completed. A total of {vuln_scanner.num_vulns} vulnerabilities were found.')
    else:
        error('Scan completed. No vulnerabilities were detected.')


if __name__ == "__main__":
    main()
