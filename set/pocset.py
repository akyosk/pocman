#! /usr/bin/python3
# -*- coding: utf-8 -*-
from set.config import ua,ip,domain,url,port,cmd,threads,cookie,ssl,rhost,rport,lhost,lport,proxy,file,timeout,censys_api,shodan_api # 引入配置文件
from cve.WebInfoScan.DomainScan import DomainScanInfo
from cve.WebInfoScan.DomainScan2 import ScanDomain
from cve.WebInfoScan.Crt import CERTScan
from cve.WebInfoScan.DomainPassword import PwdsDomain
from cve.WebInfoScan.HistoryIp import HistoryIpScan
from cve.WebInfoScan.JsFinder import JsFinderScan
from cve.WebInfoScan.WebAll import JsFinderScan2
from cve.WebInfoScan.DirScan import Dirsearch
from cve.WebInfoScan.PortScan import ScanProt
from cve.WebInfoScan.DoaminPortScan import DoaminScanProt
from cve.WebInfoScan.ZhongJianJian import ZhongJianJianScan
from cve.WebInfoScan.SecurityCheck import SecurityCheckScan
from cve.WebInfoScan.JScanner import JscannerMaster
from cve.WebInfoScan.FindSomeThings.main.console import Find_Some_Thing
from cve.WebInfoScan.Jjjjjjjjjjjjjs import Jssssss
from cve.WebInfoScan.dirpro_main.dirpro import Dirpro
from cve.WebInfoScan.Shodan import ShodanWork
from cve.WebInfoScan.DomainAllScan import DomainAll
from cve.WebInfoScan.CensysIp import CensysInfo
from cve.WebInfoScan.CensysDomain import CensysDomainInfo
from cve.WebInfoScan.GitHack_master.GitHack import GitHackScan

from cve.Wordpress.WpRest import WpRestScan
from cve.Wordpress.CVE_2022_21661 import Cve_2022_21661

from cve.BigIP.CVE_2023_46747 import Cve_2023_46747
from cve.BigIP.CVE_2023_46747Poc2 import Cve_2023_46747Poc2
from cve.BigIP.CVE_2022_1388 import Cve_2022_1388

from cve.CmsEasy.CmsEasySql import CmsEasySqlScan


from cve.Joomla.CVE_2023_23752 import Cve_2023_23752
from cve.Joomla.CVE_2017_8917 import Cve_2017_8917
from cve.Joomla.CVE_2017_8917Poc2 import Cve_2017_8917Poc2
from cve.Joomla.JoomlaGetshell import JoomlaGetshellScan

from cve.Nacos.QVD_2023_6271 import Qvd_2023_6271
from cve.Jquery.CVE_2018_9206 import Cve_2018_9206
from cve.Jquery.JqueryDirRead import JqueryDirReadScan
from cve.Log.Logs import LogScan
from cve.ThinkPHP.thinkphp_scan_master.thinkphp_scan import ThinkphpScanMaster
from cve.ThinkPHP.ThinkPHPV6 import ThinkPhpV6
from cve.ThinkPHP.ThinkphpSql import ThinkSqlScan
from cve.ThinkPHP.ThinkphpDB import ThinkDBScan
from cve.ThinkPHP.ThinkphpAllRCE import ThinkRCEScan
from cve.JBoss.JbossVuls import JbossVulsScan
from cve.FastAdmin.FastAdminDirUpload import FastAdminDirUploadScan
from cve.Ftp.FtpSmile import FtpScan
from cve.Lanling.LanlingDebugRce import LanlingDebugRceScan
from cve.Lanling.LanlingDirRead import LanlingDirReadScan
from cve.Lanling.LanlingSsrfGetshell import LanlingSsrfGetshellScan
from cve.Lanling.LanlingSsrfJndi import LanlingSsrfJndiScan
from cve.NodeJs.CVE_2021_21315Nc import Cve_2021_21315Nc
from cve.NodeJs.CVE_2021_21315 import Cve_2021_21315
from cve.Plesk.CVE_2023_24044 import Cve_2023_24044
from cve.Redis.CVE_2022_0543 import Cve_2022_0543
from cve.Redis.Redisunanthour import RedisunanthourScan
from cve.Vue.VueJsScan import VueJsScaner
from cve.Spring.SpringBoot import SpringBootScan
from cve.Spring.SBSCAN_master.sbscan import SBScan
from cve.RocketMQ.CVE_2023_33246 import Cve_2023_33246
from cve.RocketMQ.RocketUser import RocketUserScan
from cve.Grafana.GrafanaMetrics import GrafanaMetricsScan
from cve.Grafana.CVE_2022_32276 import Cve_2022_32276
from cve.Grafana.CVE_2022_32275 import Cve_2022_32275
from cve.Grafana.CVE_2021_43798_2 import Cve_2021_43798_2
from cve.Grafana.CVE_2021_43798 import Cve_2021_43798
from cve.Grafana.CVE_2021_39226 import Cve_2021_39226
from cve.Grafana.CVE_2020_11110 import Cve_2020_11110
from cve.Shiro.ShiroScan_master.shiro_rce import ShiroScan
from cve.FunAdmin.CVE_2023_24775 import Cve_2023_24775
from cve.Zimbra.CVE_2022_27925 import Cve_2022_27925
from cve.Zimbra.CVE_2022_27925Poc2 import Cve_2022_27925Poc2
from cve.Zabbix.CVE_2022_23131 import Cve_2022_23131
from cve.Swagger.Swagger_Hack import Swagger_Hack_Scan
from cve.NetScaler.CVE_2023_4966 import Cve_2023_4966
from cve.Juniper.CVE_2023_36845 import Cve_2023_36845
from cve.Jeecg.CVE_2023_33510 import Cve_2023_33510
from cve.Apache.CVE_2021_41773 import Cve_2021_41773
from cve.Apache.CVE_2018_2894 import Cve_2018_2894
from cve.Apache.ApacheSkywalkingSQL import SkywalkingSqlScan
from cve.Apache.ApachePut import ApachePutScan
from cve.Struts.Struts2scan_main.Struts2scan import Struts2Scaner

from cve.Fanwei.weaver_exp_master.Weaver_Master import WeaverScan
from cve.Fanwei.Weaver_pocs import Weaver_Poc_Scan
from cve.Laravel.CVE_2021_3129 import Cve_2021_3129
from cve.Nginx.NginxRCE1 import NginxRceScan1
from cve.Doccms.DoccmsSql import DocSqlScan
from cve.JeecgBoot.JeecgBootSql import JeecgSql
from cve.PbootCMS.PBootSql import PBSqlScan
from cve.Wso2.CVE_2022_29464 import Cve_2022_29464
from cve.JshERPboot.JshErpBoot import JshErpBootScan
from cve.Openfire.CVE_2023_32315 import Cve_2023_32315


modules = [
    {"name": "Web-Domain", "description": "通过domain枚举子域名([b bright_red]短时间[/b bright_red])", "params": {"domain": domain,"ssl": ssl,},'poc': DomainScanInfo},
    {"name": "Web-Domain", "description": "通过domain枚举子域名([b bright_red]长时间[/b bright_red])", "params": {"domain": domain,"threads": threads,"header": ua,"ssl": ssl,"proxy": proxy},'poc': ScanDomain},
    {"name": "Web-Dir", "description": "通过url枚举[b bright_red]web路径[/b bright_red]", "params": {"url": url,"threads": threads,"header": ua,"ssl": ssl,"proxy": proxy},'poc': Dirsearch},
    {"name": "Web-Cert", "description": "通过domain扫描[b bright_red]cert/dns/ip/domain[/b bright_red]信息", "params": {"domain": domain},'poc': CERTScan},
    {"name": "Domain-Password", "description": "通过domain名称随机生成[b bright_red]爆破字典[/b bright_red]", "params": {"domain": domain,"counts": 50000},'poc': PwdsDomain},
    {"name": "Web-INFO", "description": "通过securitytrails扫描domain的[b bright_red]ip/dns/domain[/b bright_red]信息", "params": {"domain": domain},'poc': HistoryIpScan},
    {"name": "Web-JS", "description": "通过[b bright_red]jsfinder[/b bright_red]扫描目标网站源码敏感信息", "params": {"url": url,"cookie": cookie, "depth": False,"threads":threads,"proxy": proxy,"ssl": ssl},'poc': JsFinderScan},
    {"name": "Web-JS", "description": "通过[b bright_red]jsfinder[/b bright_red]扫描目标网站源码敏感信息,对传参对数据进行SQL/XSS/目录穿越检测", "params": {"url": url,"cookie": cookie, "depth": False,"threads":threads,"proxy": proxy,"ssl": ssl},'poc': JsFinderScan2},
    {"name": "Web-JS", "description": "[b bright_red]JSscanner[/b bright_red]工具移植,递归式网站目录扫描", "params": {"url": url,"header":ua,"wait":3,"height": 0,"proxy":proxy,"level":0, "timeout":0,"ssl":ssl,"*Tips1*": "wait为请求超时等待时间｜height为查找深度","*Tips2*":"level为最大递减数，默认0为全递减｜timeout为请求间隔延时"},'poc': JscannerMaster},
    {"name": "Web-IP", "description": "通过ip扫描目标网站[b bright_red]端口[/b bright_red]信息", "params": {"ip": ip,"nums": 10000,"threads": threads},'poc': ScanProt},
    {"name": "Web-Port", "description": "通过url扫描目标网站[b bright_red]端口[/b bright_red]信息", "params": {"url": url,"nums": 10000,"header":ua,"ssl": ssl,"proxy": proxy,"timeout":timeout,"threads": threads},'poc': DoaminScanProt},
    {"name": "Web-Dir", "description": "扫描目标网站[b bright_red]中间件[/b bright_red]路径信息", "params": {"url": url,"threads": threads,"ssl": ssl,"header": ua,"proxy": proxy},'poc': ZhongJianJianScan},
    {"name": "Web-Dir", "description": "通过ip扫描目标网站[b bright_red]未授权[/b bright_red]漏洞", "params": {"ip": ip,"ssl": ssl,"header": ua,"proxy": proxy},'poc': SecurityCheckScan},
    {"name": "Web-SomeThing", "description": "[b bright_red]FindSomeThing[/b bright_red]工具移植", "params": {"url": url},'poc': Find_Some_Thing},
    {"name": "Web-JS", "description": "[b bright_red]Jjjjjjjjjjjjjs[/b bright_red]工具移植,爬网站JS文件,自动fuzz api接口,指定api接口", "params": {"url": url,"cookie":cookie,"header":ua,"api": None,"thread":threads,"proxy":proxy},'poc': Jssssss},
    {"name": "Web-Dir", "description": "[b bright_red]Dirpro[/b bright_red]工具移植,目录扫描器,自动使用随机的User-Agent", "params": {"url": url,"thread":threads,"proxy":proxy},'poc': Dirpro},
    {"name": "Web", "description": "通过[b bright_red]Shodan[/b bright_red]搜索引擎批量搜索/导出域名信息", "params": {"query": "hostname:baidu.com","header": ua,"cookie":shodan_api,"thread":threads,"output":False},'poc': ShodanWork},
    {"name": "Web", "description": "通过[b bright_red]Censys[/b bright_red]搜索域名相关的IP信息", "params": {"domain": domain,"cookie":censys_api},'poc': CensysDomainInfo},
    {"name": "Web", "description": "通过[b bright_red]Censys[/b bright_red]搜索IP及端口信息", "params": {"domain": domain,"cookie":censys_api},'poc': CensysInfo},
    {"name": "Web", "description": "GitHack工具移植,通过网站泄漏的[b bright_red]Git[/b bright_red]文件信息下载网站源码信息", "params": {"url": url},'poc': GitHackScan},
    {"name": "Web", "description": "通过多方平台收集[b bright_red]Domain/IP[/b bright_red]信息([b red]强烈推荐[/b red])", "params": {"domain": domain,"output":False},'poc': DomainAll},

    {"name": "WordPress", "description": "[b bright_red]WpRest[/b bright_red]工具移植,检测Wordpress网站信息", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy},'poc': WpRestScan},
    {"name": "WordPress", "description": "WordPress[b bright_red]CVE-2022-21661[/b bright_red]SQL注入漏洞", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout},'poc': Cve_2022_21661},

    {"name": "Nacos", "description": "扫描目标网站[b bright_red]QVD-2023-6271[/b bright_red]及一系列nacos漏洞", "params": {"url": url},'poc': Qvd_2023_6271},
    {"name": "JQuery", "description": "扫描jquery的[b bright_red]CVE-2018-9206[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,},'poc': Cve_2018_9206},
    {"name": "JQuery", "description": "扫描jquery[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"file":file,"header":ua,"proxy":proxy,"ssl": ssl,},'poc': JqueryDirReadScan},
    {"name": "Log", "description": "扫描网站[b bright_red]日志文件[/b bright_red]", "params": {"url": url,"threads":threads,"header":ua,"proxy":proxy,"ssl": ssl,},'poc': LogScan},
    {"name": "ThinkPHP", "description": "thinkphp2x3x5x的漏洞检测[b bright_red]ThinkPHP-Scan[/b bright_red]工具移植", "params": {"url": url},'poc': ThinkphpScanMaster},
    {"name": "ThinkPHP", "description": "受影响版本Thinkphp[b bright_red]6.0.1~6.0.13[/b bright_red]lang", "params": {"url": url, "head": ua,"proxy":proxy,"ssl": ssl},'poc': ThinkPhpV6},
    {"name": "ThinkPHP", "description": "Thinkphp[b bright_red]3.x/5.x[/b bright_red]全版本SQL注入检测", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': ThinkSqlScan},
    {"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 5.0.x配置文件泄漏","params": {"url": url,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkDBScan},
    {"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x全版本RCE扫描","params": {"url": url,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan},

    {"name": "JBoss", "description": "扫描历史各类[b bright_red]Jboss[/b bright_red]漏洞", "params": {"url": url, "threads":threads, "ssl": ssl, "head": ua,"proxy":proxy},'poc': JbossVulsScan},
    {"name": "FastAdmin", "description": "FastAdmin后台[b bright_red]文件上传[/b bright_red]漏洞", "params": {"url": url, "head": ua, "cookie":cookie, "ssl": ssl,"proxy":proxy},'poc': FastAdminDirUploadScan},
    {"name": "FTP", "description": "通过IP检测FTP[b bright_red]笑脸[/b bright_red]漏洞", "params": {"ip": ip},'poc': FtpScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]debug.jsp代码执行[/b bright_red]漏洞", "params": {"url": url,"cmd":cmd,"ssl":ssl,"header":ua,"proxy":proxy},'poc': LanlingDebugRceScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"file":file,"ssl":ssl,"header":ua,"proxy":proxy},'poc': LanlingDirReadScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]SSRF-GETSHELL[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': LanlingSsrfGetshellScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]SSRF-JNDI[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': LanlingSsrfJndiScan},
    {"name": "Node-JS", "description": "Node-JS[b bright_red]CVE-2021-21315[/b bright_red]监听端口转发漏洞", "params": {"url": url,"proxy":proxy,"header":ua,"lhost":lhost,"lport":lport,"ssl":ssl},'poc': Cve_2021_21315Nc},
    {"name": "Node-JS", "description": "Node-JS[b bright_red]CVE-2021-21315[/b bright_red]检测并利用", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy},'poc': Cve_2021_21315},
    {"name": "Plesk", "description": "Plesk[b bright_red]CVE-2023-24044[/b bright_red]重定向漏洞", "params": {"url": url,"cdx":"baidu.com","ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2023_24044},
    {"name": "Redis", "description": "检测Redis[b bright_red]CVE-2022-0543/未授权[/b bright_red]漏洞", "params": {"ip": ip,"port":6379,"threads": threads},'poc': Cve_2022_0543},
    {"name": "Redis", "description": "检测Redis[b bright_red]未授权[/b bright_red]漏洞", "params": {"ip": ip,"port":6379},'poc': RedisunanthourScan},
    {"name": "Vue", "description": "检测Vue[b bright_red]接口文件[/b bright_red]是否存在敏感信息泄露", "params": {"url": url,"header":ua,"threads": threads,"proxy":proxy,"ssl":ssl,"cookie":cookie},'poc': VueJsScaner},
    {"name": "Spring", "description": "[b bright_red]SpringBootScan[/b bright_red]工具移植扫描Spring敏感信息泄露", "params": {"url": url,"proxy":proxy},'poc': SpringBootScan},
    {"name": "Spring", "description": "[b bright_red]SBScan[/b bright_red]工具移植扫描Spring敏感信息泄露及漏洞利用", "params": {"url": url,"proxy":proxy,"dnslog": None,"threads":threads,"webscan":False,"*Tips*":"webscan为True只对存在spring指纹的网站开始扫描"},'poc': SBScan},
    {"name": "RocketMQ", "description": "RocketMQ[b bright_red]CVE-2023-33246[/b bright_red]漏洞检测", "params": {"ip": ip,"port":port},'poc': Cve_2023_33246},
    {"name": "RocketMQ", "description": "RocketMQ[b bright_red]默认用户[/b bright_red]检测", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': RocketUserScan},
    {"name": "Grafana", "description": "Grafana[b bright_red]Grafana指标集群[/b bright_red]检测", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': GrafanaMetricsScan},
    {"name": "Struts", "description": "[b bright_red]Struts2Scan[/b bright_red]工具移植", "params": {"url": url,"proxy":proxy},'poc': Struts2Scaner},
    {"name": "Shiro", "description": "[b bright_red]ShiroScan-master[/b bright_red]工具移植,Shiro<=1.2.4反序列化", "params": {"url": url,"cmd":cmd},'poc': ShiroScan},
    {"name": "Grafana", "description": "Grafana[b bright_red]Metrics[/b bright_red]文件扫描", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': GrafanaMetricsScan},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2022-32276[/b bright_red]数据库快照泄漏漏洞扫描", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2022_32276},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2022-32275[/b bright_red]任意文件读取漏洞扫描", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2022_32275},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2021-43798[/b bright_red]任意文件读取漏洞扫描,利用点2", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2021_43798_2},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2021-43798[/b bright_red]任意文件读取", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"threads":threads},'poc': Cve_2021_43798},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2021-39226[/b bright_red]数据库快照泄露", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2021_39226},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2020-11110[/b bright_red]XSS漏洞检测", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"poc":"<script>alert(1)</script>"},'poc': Cve_2020_11110},
    {"name": "Swagger", "description": "[b bright_red]Swagger-Hack[/b bright_red]工具移植", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Swagger_Hack_Scan},
    {"name": "FunAdmin", "description": "FunAdmin[b bright_red]CVE-2023-24775[/b bright_red]漏洞扫描", "params": {"url": url,"ssl":ssl,"proxy":proxy},'poc': Cve_2023_24775},
    {"name": "Zimbra", "description": "Zimbra[b bright_red]CVE-2022-27925[/b bright_red]漏洞扫描", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy},'poc': Cve_2022_27925},
    {"name": "Zimbra", "description": "Zimbra[b bright_red]CVE-2022-27925[/b bright_red]漏洞扫描利用点2", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2022_27925Poc2},
    {"name": "Zabbix", "description": "Zabbix[b bright_red]CVE-2022-23131[/b bright_red]漏洞扫描", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy},'poc': Cve_2022_23131},
    {"name": "NetScaler", "description": "NetScaler ADC&NetScaler Gateway[b bright_red]CVE-2023-4966[/b bright_red]敏感信息泄露漏洞扫描", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2023_4966},
    {"name": "Juniper", "description": "[b bright_red]CVE-2023-36845[/b bright_red]Juniper Networks Junos OS EX远程命令执行漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2023_36845},
    {"name": "Jeecg", "description": "[b bright_red]CVE-2023-33510[/b bright_red]Jeecg P3 Biz Chat 任意文件读取漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2023_33510},
    {"name": "Apache", "description": "[b bright_red]CVE-2021-41773 / CVE-2021-42013[/b bright_red]Apache HTTP Server 2.4.50远程代码执行漏洞", "params": {"url": url,"header":ua, "ssl":ssl},'poc': Cve_2021_41773},
    {"name": "Apache", "description": "[b bright_red]Apache Skywalking[/b bright_red]<=8.3 SQL注入", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': SkywalkingSqlScan},
    {"name": "Apache", "description": "Apache Tomcat[b bright_red]CVE-2018-2894[/b bright_red]文件上传", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout},'poc': Cve_2018_2894},
    {"name": "Apache", "description": "Apache[b bright_red]PUT[/b bright_red]文件上传", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': ApachePutScan},

    {"name": "Fanwei", "description": "[b bright_red]Weaver-Exp-Scan[/b bright_red]泛微检测工具移植", "params": {"url": url},'poc': WeaverScan},
    {"name": "Fanwei", "description": "[b bright_red]2023-Weaver-Pocs[/b bright_red]泛微检测工具移植", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Weaver_Poc_Scan},
    {"name": "BigIP", "description": "[b bright_red]CVE-2023-46747[/b bright_red]Big-IP CVE-2023-46747-Rce", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,},'poc': Cve_2023_46747},
    {"name": "BigIP", "description": "[b bright_red]CVE-2023-46747[/b bright_red]Big-IP CVE-2023-46747-Rce-Poc2", "params": {"url": url,"proxy":proxy,"ssl":ssl,"header":ua,"timeout":timeout,"cmd":cmd},'poc': Cve_2023_46747Poc2},
    {"name": "BigIP", "description": "[b bright_red]CVE-2022-1388[/b bright_red]Big-IP CVE-2022-1388-Rce", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"timeout":timeout},'poc': Cve_2022_1388},

    {"name": "Joomla", "description": "[b bright_red]CVE-2023-23752[/b bright_red]CVE-2023-23752身份验证绕过，导致Joomla上的信息泄露", "params": {"url": url,"ssl":ssl,"proxy":proxy,"timeout":timeout},'poc': Cve_2023_23752},
    {"name": "Joomla", "description": "[b bright_red]CVE-2017-8917[/b bright_red]Joomla-3.7.0-SQL注入漏洞", "params": {"url": url,"header":ua,"proxy":proxy},'poc': Cve_2017_8917},
    {"name": "Joomla", "description": "[b bright_red]CVE-2017-8917[/b bright_red]Joomla-3.7.0-SQL注入漏洞利用点2(推荐)", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout},'poc': Cve_2017_8917Poc2},
    {"name": "Joomla", "description": "Joomla[b bright_red]一键GetShell[/b bright_red]", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"timeout":timeout},'poc': JoomlaGetshellScan},
    {"name": "Laravel", "description": "[b bright_red]CVE-2021-3129[/b bright_red]Laravel一键GetShell", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl},'poc': Cve_2021_3129},
    {"name": "Nginx", "description": "[b bright_red]NginxWebUI[/b bright_red]命令执行", "params": {"url": url,"cmd":cmd,"ssl":ssl,"header":ua,"proxy":proxy},'poc': NginxRceScan1},
    {"name": "CmsEasy", "description": "[b bright_red]CmsEasy[/b bright_red] SQL注入", "params": {"url": url,"ssl":ssl,"timeout":timeout,"proxy":proxy},'poc': CmsEasySqlScan},
    {"name": "DocCms", "description": "[b bright_red]DocCms[/b bright_red] SQL注入", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': DocSqlScan},
    {"name": "JeecgBoot", "description": "[b bright_red]JeecgBoot[/b bright_red] SQL注入", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': JeecgSql},
    {"name": "PBootCms", "description": "[b bright_red]PBootCms[/b bright_red] SQL注入", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': PBSqlScan},
    {"name": "WSO2", "description": "WSO2[b bright_red]CVE-2022-29464[/b bright_red]put文件上传", "params": {"url": url,"shell":"shhhelll.jsp","ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': Cve_2022_29464},
    {"name": "JshERPBoot", "description": "[b bright_red]JshERPBoot[/b bright_red]敏感信息泄漏", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': JshErpBootScan},
    {"name": "Openfire", "description": "Openfire[b bright_red]CVE-2023-32315[/b bright_red]日志信息泄漏/添加用户", "params": {"url": url,"header":ua,"proxy":proxy},'poc': Cve_2023_32315},
]
