#!/user/bin/env python3
# -*- coding: utf-8 -*-
from set.config import ua,domain,port,cmd,threads,cookie,ssl,rhost,rport,lhost,lport,proxy,file,timeout # 引入配置文件
from cve.BATCH_WORK.bigip.CVE_2023_46747 import Cve_2023_46747
from cve.BATCH_WORK.joomla.CVE_2023_23752 import Cve_2023_23752
from cve.BATCH_WORK.joomla.CVE_2017_8917 import Cve_2017_8917
from cve.BATCH_WORK.zimbra.CVE_2022_27925Poc2 import Cve_2022_27925Poc2
from cve.BATCH_WORK.laravel.CVE_2021_3129 import Cve_2021_3129
from cve.BATCH_WORK.joomla.JoomlaGetshell import JoomlaGetshellScan
from cve.BATCH_WORK.bigip.CVE_2023_46747Poc2 import Cve_2023_46747Poc2
from cve.BATCH_WORK.bigip.CVE_2022_1388 import Cve_2022_1388
from cve.BATCH_WORK.spring.springDump import SpringDumnp
from cve.BATCH_WORK.spring.springEnv import SpringEnv
from cve.BATCH_WORK.spring.CVE_2022_22965 import Cve_2022_22965
from cve.BATCH_WORK.wordpress.CVE_2022_21661 import Cve_2022_21661
from cve.BATCH_WORK.jboss.JbossVuls import JbossVulsScan
from cve.BATCH_WORK.cmseasy.CmsEasySql import CmsEasySqlScan
from cve.BATCH_WORK.doccms.DoccmsSql import DocSqlScan
from cve.BATCH_WORK.thinkphp.ThinkphpSql import ThinkSqlScan
from cve.BATCH_WORK.thinkphp.ThinkLog import LogScan
from cve.BATCH_WORK.thinkphp.ThinkphpDB import ThinkDBScan
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE import ThinkRCEScan
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE1 import ThinkRCEScan1
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE2 import ThinkRCEScan2
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE3 import ThinkRCEScan3
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE4 import ThinkRCEScan4
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE5 import ThinkRCEScan5
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE6 import ThinkRCEScan6
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE7 import ThinkRCEScan7
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE8 import ThinkRCEScan8
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE9 import ThinkRCEScan9
from cve.BATCH_WORK.thinkphp.ThinkphpAllRCE10 import ThinkRCEScan10
from cve.BATCH_WORK.jeecg_boot.JeecgBootSql import JeecgSql
from cve.BATCH_WORK.pbootcms.PBootSql import PBSqlScan
from cve.BATCH_WORK.apache.ApacheSkywalkingSQL import SkywalkingSqlScan
from cve.BATCH_WORK.apache.CVE_2018_2894 import Cve_2018_2894
from cve.BATCH_WORK.apache.ApachePut import ApachePutScan
from cve.BATCH_WORK.wso2.CVE_2022_29464 import Cve_2022_29464
from cve.BATCH_WORK.jquery.JqueryDirRead import JqueryDirReadScan
from cve.BATCH_WORK.jshERPboot.JshErpBoot import JshErpBootScan
from cve.BATCH_WORK.fastadmin.FadminAdminInfoVul import FastadminInfoScan
from cve.BATCH_WORK.openfire.CVE_2023_32315 import Cve_2023_32315
from cve.BATCH_WORK.webinfo.DomainScan import ScanDomain
from cve.BATCH_WORK.phpmyadmin.PhpMyAdmin import PMASetupScan
url_file = "batch/url.txt"


# 批量检测
batch_modules = [
{"name": "BigIP", "description": "[b bright_red]CVE-2023-46747[/b bright_red]Big-IP CVE-2023-46747-Rce", "params": {"dir": url_file,"header":ua,"proxy":proxy,"ssl":ssl,"timeout": timeout},'poc': Cve_2023_46747},
{"name": "Joomla", "description": "[b bright_red]CVE-2023-23752[/b bright_red]CVE-2023-23752身份验证绕过，导致Joomla上的信息泄露", "params": {"dir": url_file,"ssl":ssl,"proxy":proxy,"timeout":timeout},'poc': Cve_2023_23752},
{"name": "Joomla", "description": "[b bright_red]CVE-2017-8917[/b bright_red]Joomla-3.7.0-SQL注入漏洞", "params": {"dir": url_file,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout},'poc': Cve_2017_8917},
{"name": "Zimbra", "description": "Zimbra[b bright_red]CVE-2022-27925[/b bright_red]漏洞扫描利用点2", "params": {"dir": url_file, "ssl": ssl, "header": ua, "proxy": proxy}, 'poc': Cve_2022_27925Poc2},
{"name": "Laravel", "description": "[b bright_red]CVE-2021-3129[/b bright_red]Laravel一键GetShell", "params": {"dir": url_file,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout},'poc': Cve_2021_3129},
{"name": "Joomla", "description": "Joomla[b bright_red]一键GetShell[/b bright_red]", "params": {"dir": url_file,"header":ua,"ssl":ssl,"proxy":proxy,"timeout":timeout},'poc': JoomlaGetshellScan},
{"name": "BigIP", "description": "[b bright_red]CVE-2023-46747[/b bright_red]Big-IP CVE-2023-46747-Rce-Poc2", "params": {"dir": url_file,"proxy":proxy,"ssl":ssl,"header":ua,"timeout":timeout,"cmd":cmd},'poc': Cve_2023_46747Poc2},
{"name": "Spring", "description": "Spring[b bright_red]Dump[/b bright_red]漏洞", "params": {"dir": url_file,"proxy":proxy,"timeout":timeout,"ssl":ssl},'poc': SpringDumnp},
{"name": "Spring", "description": "Spring[b bright_red]CVE-2022-22965[/b bright_red]GET-Shell漏洞", "params": {"dir": url_file,"proxy":proxy,"timeout":timeout,"ssl":ssl,"header":ua},'poc': Cve_2022_22965},
{"name": "Spring", "description": "Spring[b bright_red]ENV[/b bright_red]敏感信息泄漏漏洞", "params": {"dir": url_file,"proxy":proxy,"timeout":timeout,"ssl":ssl,"header":ua,"flag":False,"*Tips*": "flag为True时增加校验信息是否加密,加密会不输出"},'poc': SpringEnv},
{"name": "WordPress", "description": "WordPress[b bright_red]CVE-2022-21661[/b bright_red]SQL注入漏洞", "params": {"dir": url_file,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout},'poc': Cve_2022_21661},
{"name": "JBoss", "description": "扫描历史各类[b bright_red]Jboss[/b bright_red]漏洞", "params": {"dir": url_file, "ssl": ssl, "head": ua,"proxy":proxy,"timeout":timeout},'poc': JbossVulsScan},
{"name": "BigIP", "description": "[b bright_red]CVE-2022-1388[/b bright_red]Big-IP CVE-2022-1388-Rce", "params": {"dir": url_file,"header":ua,"ssl":ssl,"proxy":proxy,"timeout":timeout},'poc': Cve_2022_1388},
{"name": "CmsEasy", "description": "[b bright_red]CmsEasy[/b bright_red] SQL注入","params": {"dir": url_file, "ssl": ssl, "timeout": timeout, "proxy": proxy}, 'poc': CmsEasySqlScan},
{"name": "DocCms", "description": "[b bright_red]DocCms[/b bright_red] SQL注入","params": {"dir": url_file, "ssl": ssl, "header": ua, "proxy": proxy, "timeout": timeout}, 'poc': DocSqlScan},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x SQL全版本注入检测","params": {"dir": url_file, "ssl": ssl, "header": ua, "proxy": proxy, "timeout": timeout}, 'poc': ThinkSqlScan},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 日志文件搜索","params": {"dir": url_file,"header": ua,"proxy": proxy, "ssl": ssl,"timeout": timeout}, 'poc': LogScan},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 5.0.x配置文件泄漏","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkDBScan},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE([b bright_yellow]耗时较长[/b bright_yellow])","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-1","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan1},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-2","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan2},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-3","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan3},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-4","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan4},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-5","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan5},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-6","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan6},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-7","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan7},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-8","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan8},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-9","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan9},
{"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x系列全版本RCE-分支-写入Shell脚本","params": {"dir": url_file,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan10},


{"name": "JeecgBoot", "description": "[b bright_red]JeecgBoot[/b bright_red] SQL注入", "params": {"dir": url_file,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': JeecgSql},
{"name": "PBootCms", "description": "[b bright_red]PBootCms[/b bright_red] SQL注入", "params": {"dir": url_file,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': PBSqlScan},
{"name": "Apache", "description": "[b bright_red]Apache Skywalking[/b bright_red]<=8.3 SQL注入", "params": {"dir": url_file,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': SkywalkingSqlScan},
{"name": "Apache", "description": "Apache Tomcat[b bright_red]CVE-2018-2894[/b bright_red]put文件上传", "params": {"dir": url_file,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout},'poc': Cve_2018_2894},
{"name": "Apache", "description": "Apache[b bright_red]PUT[/b bright_red]文件上传", "params": {"dir": url_file,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': ApachePutScan},

{"name": "WSO2", "description": "WSO2[b bright_red]CVE-2022-29464[/b bright_red]文件上传", "params": {"dir": url_file,"shell":"shhhelll.jsp","ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': Cve_2022_29464},
{"name": "JQuery", "description": "JQuery[b bright_red]1.7.2[/b bright_red]任意文件下载", "params": {"dir": url_file,"file":file,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout},'poc': JqueryDirReadScan},
{"name": "JshERPBoot", "description": "[b bright_red]JshERPBoot[/b bright_red]敏感信息泄漏","params": {"dir": url_file, "ssl": ssl, "header": ua, "proxy": proxy, "timeout": timeout}, 'poc': JshErpBootScan},
{"name": "FastAdmin", "description": "[b bright_red]FastAdmin[/b bright_red]敏感信息泄漏","params": {"dir": url_file, "ssl": ssl, "header": ua, "proxy": proxy, "timeout": timeout}, 'poc': FastadminInfoScan},
{"name": "Openfire", "description": "Openfire[b bright_red]CVE-2023-32315[/b bright_red]日志信息泄漏/添加用户", "params": {"dir": url_file,"header":ua,"proxy":proxy},'poc': Cve_2023_32315},
{"name": "SubDoamin", "description": "SubDomain批量枚举[b bright_red]子域名[/b bright_red]信息", "params": {"dir": url_file,"header":ua,"ssl": ssl,"proxy":proxy,"timeout": timeout,"threads":threads},'poc': ScanDomain},
{"name": "PHPMyAdmin", "description": "PHPMyAdmin批量扫描暴露的[b bright_red]/setup/index.php[/b bright_red]路径信息", "params": {"dir": url_file,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout},'poc': PMASetupScan},

]
