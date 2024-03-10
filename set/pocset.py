#! /usr/bin/python3
# -*- coding: utf-8 -*-
from set.config import ua,ip,domain,url,port,cmd,threads,cookie,ssl,rhost,rport,lhost,lport,proxy,file,timeout,censys_api,shodan_api,ceye_dns,ceye_api # 引入配置文件
from cve.VulsScan.Vuls import VulsScanAll
from cve.VulsScan.POC_bomber.POC_bomber_Run import POC_bomber_Scan
from cve.VulsScan.vulmap.Vulmap_Run import Vulmap_Scan
from cve.VulsScan.vulcat.Vulcat_Run import Vulcat_Scan
from cve.VulsScan.VulnX.VulnX_Run import VulnX_Scan
from cve.VulsScan.XSSCon.XSSCon_Run import XSSCon_Scan
from cve.VulsScan.sqlmap.SqlMap_Run import SqlMap_Run_Scan
from cve.VulsScan.GHR.GHR_Run import GHR_Scan
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
from cve.WebInfoScan.jjjjjjjjjjjjjs.jjjjjjjjjjjjjs_Run import jjjjjjjjjjjjjs_Scan
from cve.WebInfoScan.dirpro.Dirpro_Run import Dirpro_Scan
from cve.WebInfoScan.Shodan import ShodanWork
from cve.WebInfoScan.DomainAllScan import DomainAll
from cve.WebInfoScan.CensysIp import CensysInfo
from cve.WebInfoScan.CensysDomain import CensysDomainInfo
from cve.WebInfoScan.GitHack_master.GitHack import GitHackScan
from cve.WebInfoScan.knock.knockRun import Knock
from cve.WebInfoScan.FofaCrocs import Fofacrocs
from cve.WebInfoScan.CloakQuest3r.CloakQuest3r_Run import CloakQuest3r_Run_Scan
from cve.WebInfoScan.Packer_Fuzzer.Packer_Fuzzer_Run import Packer_Fuzzer_Run_Scan
from cve.WebInfoScan.SiteScan.SiteScan_Main import SiteScan_Run
from cve.WebInfoScan.okadminfinder3.okadminfinder_Run import okadminfinder_Run_Scan
from cve.WebInfoScan.SploitScan import SploitScan_Run
from cve.WebInfoScan.CloudFail.CloudFail_Run import CloudFail_Run_Scan


from cve.Wordpress.WpRest import WpRestScan
from cve.Wordpress.CVE_2022_21661 import Cve_2022_21661
from cve.Wordpress.CVE_2023_23488 import Cve_2023_23488
from cve.Wordpress.CVE_2023_4278 import Cve_2023_4278
from cve.Wordpress.CVE_2023_6553_main.CVE_2023_6553 import Cve_2023_6553
from cve.Wordpress.Wordpress4_6_Rce import Wordpress4_6_Rce_Scan
from cve.Wordpress.WPvSCAN.WPvSCAN_Run import WPvSCAN_Scan
from cve.Wordpress.CVE_2023_0329 import Cve_2023_0329
from cve.Wordpress.CVE_2023_2744 import Cve_2023_2744
from cve.Wordpress.Wordpress_Lfi import Wordpress_Lfi_Scan
from cve.Wordpress.WordpressReg import WordpressRegScan
from cve.Wordpress.Wordpress_Listingo_File_Upload import Wordpress_Listingo_File_Upload_Scan
from cve.Wordpress.CVE_2024_25600 import Cve_2024_25600
from cve.Wordpress.CVE_2024_1061 import Cve_2024_1061
from cve.Wordpress.CVE_2024_1208 import Cve_2024_1208
from cve.Wordpress.CVE_2020_25213 import Cve_2020_25213
from cve.Wordpress.CVE_2022_1119 import Cve_2022_1119
from cve.Wordpress.CVE_2023_1730 import Cve_2023_1730
from cve.Wordpress.CVE_2022_2633 import Cve_2022_2633
from cve.Wordpress.CVE_2020_11738 import Cve_2020_11738

from cve.BigIP.CVE_2023_46747 import Cve_2023_46747
from cve.BigIP.CVE_2023_46747Poc2 import Cve_2023_46747Poc2
from cve.BigIP.CVE_2022_1388 import Cve_2022_1388

from cve.CmsEasy.CmsEasySql import CmsEasySqlScan


from cve.Joomla.CVE_2023_23752 import Cve_2023_23752
from cve.Joomla.CVE_2017_8917 import Cve_2017_8917
from cve.Joomla.CVE_2017_8917Poc2 import Cve_2017_8917Poc2
from cve.Joomla.JoomlaGetshell import JoomlaGetshellScan
from cve.Joomla.CVE_2023_23752_2 import Cve_2023_23752_2

from cve.Nacos.QVD_2023_6271 import Qvd_2023_6271
from cve.Nacos.HKEcho_Nacos_main.NacosRun import NacosR
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
from cve.Lanling.Lanling_Sql import Lanling_Sql_Scan
from cve.Lanling.Lanling_Info import Lanling_Info_Scan
from cve.Lanling.Lanling_getLoginSessionId_login_bypass import Lanling_getLoginSessionId_login_bypass_Scan
from cve.NodeJs.CVE_2021_21315Nc import Cve_2021_21315Nc
from cve.NodeJs.CVE_2021_21315 import Cve_2021_21315
from cve.NodeJs.CVE_2017_14849 import Cve_2017_14849
from cve.Plesk.CVE_2023_24044 import Cve_2023_24044
from cve.Redis.CVE_2022_0543 import Cve_2022_0543
from cve.Redis.Redisunanthour import RedisunanthourScan
from cve.Redis.Redis_Rce.Redis_Run import Redis_Scan_Run
from cve.Vue.VueJsScan import VueJsScaner
from cve.Spring.SpringBoot import SpringBootScan
from cve.Spring.JeeSpringCloudUploadFile import JeeSpringCloudUploadFileScan
from cve.Spring.SBSCAN_master.sbscan import SBScan
from cve.Spring.CVE_2022_22947 import Cve_2022_22947
from cve.Spring.CVE_2022_22965 import Cve_2022_22965
from cve.Spring.CVE_2022_22965_Poc2 import Cve_2022_22965_Poc2
from cve.Spring.CVE_2022_22963 import Cve_2022_22963
from cve.Spring.SpringDump import SpringDumpScan
from cve.Spring.SpringBlade_Sql import SpringBlade_Sql_Scan
from cve.Spring.DVB_2024_6364 import Dvb_2024_6364
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
from cve.Shiro.Shiro_Check import Shiro_Check_Run
from cve.Shiro.Shiro_File_Dump import Shiro_File_Dump_Scan
from cve.Shiro.Shiro_Exploit import Shiro_Exp_Scan
from cve.FunAdmin.CVE_2023_24775 import Cve_2023_24775
from cve.Zimbra.CVE_2022_27925 import Cve_2022_27925
from cve.Zimbra.CVE_2022_27925Poc2 import Cve_2022_27925Poc2
from cve.Zabbix.CVE_2022_23131 import Cve_2022_23131
from cve.Zabbix.CVE_2016_10134 import Cve_2016_10134
from cve.Swagger.Swagger_Hack import Swagger_Hack_Scan
from cve.NetScaler.CVE_2023_4966 import Cve_2023_4966
from cve.Juniper.CVE_2023_36845 import Cve_2023_36845
from cve.Juniper.Junper_J_Web import Junper_J_WebRce
from cve.Juniper.CVE_2023_36844 import Cve_2023_36844
from cve.Jeecg.CVE_2023_33510 import Cve_2023_33510
from cve.Apache.CVE_2021_41773 import Cve_2021_41773
from cve.Apache.CVE_2021_41773_2 import Cve_2021_41773_2
from cve.Apache.CVE_2018_2894 import Cve_2018_2894
from cve.Apache.ApacheSkywalkingSQL import SkywalkingSqlScan
from cve.Apache.ApachePut import ApachePutScan
from cve.Apache.CVE_2016_3088 import Cve_2016_3088
from cve.Apache.Struts.CVE_2023_50164 import Cve_2023_50164
from cve.Apache.weblogicScanner_master.weblogicRun import weblogicRunScan
from cve.Apache.CVE_2020_13945 import Cve_2020_13945
from cve.Apache.CVE_2023_51467 import Cve_2023_51467
from cve.Apache.CVE_2023_50290 import Cve_2023_50290
from cve.Apache.CVE_2024_21733 import Cve_2024_21733
from cve.Apache.Log4j_Check import Log4j_Check_Run
from cve.Apache.Log4j_Scan.Log4j_Scan_Run import Log4j_Scan_Scan
from cve.Struts.Struts2scan_main.Struts2scan import Struts2Scaner

from cve.Fanwei.weaver_exp_master.Weaver_Master import WeaverScan
from cve.Fanwei.Weaver_pocs import Weaver_Poc_Scan
from cve.Fanwei.FanweiDBInfo import FanweiDBInfoScan
from cve.Fanwei.Ecology_oa_file_read import Ecology_oa_file_read_Scan
from cve.Fanwei.SptmForPortalThumbnail_file_read import SptmForPortalThumbnail_file_read_Scan
from cve.Fanwei.GetE9DevelopAllNameValue2_file_read import GetE9DevelopAllNameValue2_file_read_Scan
from cve.Laravel.CVE_2021_3129 import Cve_2021_3129
from cve.Laravel.CVE_2021_3129_Check import Cve_2021_3129_Check
from cve.Laravel.LaravelInfoVul import LaravelInfoScan
from cve.Nginx.NginxRCE1 import NginxRceScan1
from cve.Nginx.Nginx_File_Read import Nginx_File_Read_Scan
from cve.Doccms.DoccmsSql import DocSqlScan
from cve.JeecgBoot.JeecgBootSql import JeecgSql
from cve.JeecgBoot.JeecgBoot_Rce import JeecgBoot_Rce_Scan
from cve.PbootCMS.PBootSql import PBSqlScan
from cve.Wso2.CVE_2022_29464 import Cve_2022_29464
from cve.JshERPboot.JshErpBoot import JshErpBootScan
from cve.Openfire.CVE_2023_32315 import Cve_2023_32315
# from cve.Ivanti.CVE_2023_38035 import Cve_2023_38035
from cve.Ivanti.CVE_2024_21887 import Cve_2024_21887
from cve.FastJson.FastJsonCheck import FastJsonCheckScan
from cve.JindieYUN.JindieYunUpFile import JindieYunUpFileScan
from cve.JindieYUN.JindieYunShell import JindieYunShellScan
from cve.JindieYUN.Jindie_File_Read import Jindie_File_Read_Scan
from cve.EasyCVR.EasyCVRInfo import EasyCVRInfoScan
from cve.MeterSphere.MeterSphereDumpFile import MeterSphereDumpFileScan
from cve.MeterSphere.MeterSphereRce import MeterSphereRceScan
from cve.Panabit.PanabitUserAdd import PanabitUserAddScan
from cve.Panabit.PanabitSql import PanabitSqlScan
from cve.Panabit.Panalog_Rce import Panalog_Rce_Scan
from cve.JumpServer.JumpServerInfo import JumpServerInfoScan
from cve.Jenkins.JenkinsWsq import JenkinsWsqScan
from cve.Jenkins.Jenkins_unauthorized_access import Jenkins_unauthorizedScan
from cve.Jenkins.Jenkin_WSQ_TO_Shell import Jenkin_WSQ_TO_Shell_Scan
from cve.Jenkins.CVE_2024_23897 import Cve_2024_23897
from cve.Fortigate.FortigateInfo import FortigateIndoScan
from cve.DLink.DlinkInfo import DlinkInfoScan
from cve.Casdoor.CasdoorSql import CasdoorSqlScan
from cve.Casdoor.CasdoorInfo import CasdoorInfoScan
from cve.EasyImage.EasyImageInfo import EasyImageInfoScan
from cve.PhpMyAdmin.PhpMyAdminSetup import PMASetupScan
from cve.PhpMyAdmin.PhpMyAdminPMA import PhpMyAdminPMAScan
from cve.Minio.CVE_2023_28432 import Cve_2023_28432
from cve.Shiziyu.ShiZiYuShell import ShiZiYuShellScan
from cve.Shiziyu.ShiZiYuShell2 import ShiZiYuShell2Scan
from cve.Shiziyu.ShiZiYu_Sql import ShiZiYu_Sql_Scan
from cve.ZhiyuanOA.ZhiyuanOAIndo import ZhiyuanOAInfoScan
from cve.ZeroShell.ZeroShellRce import ZeroShellRceScan
from cve.RoxyWi.CVE_2022_31137 import Cve_2022_31137
from cve.Ecshop.EcshopSql import EcshopSqlScan
from cve.IIS.IISPut import IISPutScan
from cve.Ruoyi.CNVD_2021_15555 import Cnvd_2021_15555
from cve.OwnCloud.CVE_2023_49103 import Cve_2023_49103
from cve.Ruby.CVE_2018_3760 import Cve_2018_3760
from cve.Ruby.CVE_2019_5418 import Cve_2019_5418
from cve.HuaWei.HUAWEI_Home_GatewayReadFile import HUAWEI_Home_GatewayReadFileScan
from cve.HuaWei.HuaWeiAuthHttpReadfile import HuaWeiAuth_Http
from cve.GeoServer.CVE_2023_25157 import Cve_2023_25157
from cve.JieLink.JieLinkWsq import JieLinkWsqScan
from cve.Arris.Arris_VAP2500_list_mac_address_rce import Arris_VAP2500Rce
from cve.KnightCMS.CNVD_2021_45280 import Cnvd_2021_45280
from cve.KnightCMS.CVE_2020_22211 import Cve_2020_22211
from cve.KnightCMS.CVE_2020_22209 import Cve_2020_22209
from cve.KnightCMS.CVE_2022_29720 import Cve_2022_29720
from cve.KnightCMS.CVE_2022_33095 import Cve_2022_33095
from cve.KnightCMS.KnightCMS_sqli import KnightCmsSql
from cve.KnightCMS.KnightCMS_sqli2 import KnightCmsSql2
from cve.KnightCMS.KnightCMS_sqli3 import KnightCmsSql3
from cve.Bladex.Bladex_SQLI import Blade_SQLSACN
from cve.Atlassian.CVE_2015_8399 import Cve_2015_8399
from cve.Atlassian.CVE_2021_26084 import Cve_2021_26084
from cve.Atlassian.CVE_2021_26084_2 import Cve_2021_26084_2
from cve.Atlassian.CVE_2021_26085 import Cve_2021_26085
from cve.Atlassian.CVE_2022_26134 import Cve_2022_26134
from cve.Atlassian.CVE_2023_22527 import Cve_2023_22527
from cve.ERP.QIWANGZHIZAO import QIWANGZHIZAORce
from cve.ERP.ZhiBangGuoJi_Sql import ZhiBangGuoJi_Sql_Scan
from cve.Craft.CVE_2023_41892 import Cve_2023_41892
from cve.Jorani.CVE_Jorani_RCE import CVE_Jorani_RCE_Scan
from cve.Nuuo.NUUORce import NUUORceScan
from cve.Caimao.Caimao_formping_rce import Caimao_formping_rce_Scan
from cve.Mini_Httpd.CVE_2018_18778 import Cve_2018_18778
from cve.Influxdb.InfluxDB_Wsq_Sql import InfluxDB_Wsq_SqlScan
from cve.YApi.YApi_NoSQL_Run import YApi_NoSQL_Scan
from cve.XXL_JOB.XXL_JOB_Wsq_Rce import XXL_JOB_Wsq_Rce_Scan
from cve.Webmin.CVE_2019_15107 import Cve_2019_15107
from cve.TikiWikiCMS.CVE_2020_15906 import Cve_2020_15906
from cve.Supervisord.CVE_2017_11610 import Cve_2017_11610
from cve.RocketChat.CVE_2021_22911 import Cve_2021_22911
from cve.Metabase.CVE_2023_38646 import Cve_2023_38646
from cve.Metabase.CVE_2021_41277 import Cve_2021_41277
from cve.Magento.Magento_Sql import Magento2_2_SQL
from cve.Libssh.CVE_2018_10933 import Cve_2018_10933
from cve.Jetty.CVE_2021_28164 import Cve_2021_28164
from cve.Hadoop.Hadoop_Wsq import Hadoop_Wsq_Scan
from cve.GlassFish.GlassFish_File_Read import GlassFish_File_Read_Scan
from cve.GitLab.CVE_2021_22205 import Cve_2021_22205
from cve.Drupal.CVE_2018_7600 import Cve_2018_7600
from cve.Drupal.CVE_2014_3704 import Cve_2014_3704
from cve.Drupal.CVE_2019_6340 import Cve_2019_6340
from cve.WangGuan.WangGuan_Rce import WangGuan_Rce_Scan
from cve.WangGuan.BYTEVALUE_Rce import BYTEVALUE_Rce_Scan
from cve.WangGuan.CVE_2024_2022 import Cve_2024_2022
from cve.CanDao.CanDao_Rce import CanDao_Rce_Scan
from cve.ShengXinFu.ShengXinFu_Rce import ShengXinFu_Rce_Scan
from cve.RuiJie.RuiJie_E_Rce import RuiJie_E_Rce_Scan
from cve.RuiJie.RuiJie_NBR_Rce import RuiJie_NBR_Rce_Scan
from cve.XinKaiPu.XinKaiPu_Rce import XinKaiPu_Rce_Scan
from cve.Telesquare.Telesquare_Rce import Telesquare_Rce_Scan
from cve.Tosei.Tosei_Rce import Tosei_Rce_Scan
from cve.Chamilo.CVE_2023_34960 import Cve_2023_34960
from cve.SPIP.CVE_2023_27372 import Cve_2023_27372
from cve.ShopXO.CNVD_2021_15822 import Cnvd_2021_15822
from cve.CodeIgniter.CodeIgniter_Rce import CodeIgniter_Rce_Scan
from cve.Coremail.Coremail_Dir_ByPass import Coremail_Dir_ByPass_Scan
from cve.Jellyfin.CVE_2021_21402 import Cve_2021_21402
from cve.PyLoad.PyLoad_Rce import PyLoad_Rce_Scan
from cve.PyLoad.CVE_2024_21644 import Cve_2024_21644
from cve.ZOHO.CVE_2023_35854 import Cve_2023_35854
from cve.NocoDB.CVE_2023_35843 import Cve_2023_35843
from cve.VMware.CVE_2023_34039 import Cve_2023_34039
from cve.IceWarp.CVE_2023_39699 import Cve_2023_39699
from cve.Wavlink.Wavlink_Rce import Wavlink_Rce_Scan
from cve.FreeRDP.FreeRDP_File_Read import FreeRDP_File_Read_Scan
from cve.Yearning.CVE_2022_27043 import Cve_2022_27043
from cve.Django.DjangoSql import DjangoSqlScan
from cve.Aliyun.AKeySearch import AKeySearchVuls
from cve.ClickHouse.ClickHouse_Sql import ClickHouse_Sql_Scan
from cve.EduSoho.EduSoho_File_Read import EduSoho_File_Read_Scan
from cve.Aria.CVE_2023_39141 import Cve_2023_39141
from cve.GoAnywhere.CVE_2024_0204 import Cve_2024_0204
from cve.PfSense.CVE_2022_31814 import Cve_2022_31814
from cve.Mymps.Mymps_Sql import Mymps_Sql_Scan
from cve.BSPHP.BSPHP_Wsq import BSPHP_Wsq_Scan
from cve.Metinfo.Metinfo_File_Read import Metinfo_File_Read_Scan
from cve.Exrick.CVE_2024_24112 import Cve_2024_24112
from cve.Jeeplus.Jeeplus_Reset_Password import Jeeplus_Reset_Password_Scan
from cve.Litemall.Litemall_RuoKouLin import Litemall_RuoKouLin_Scan
from cve.Cellinx.CVE_2024_24215 import Cve_2024_24215
from cve.LogBase.LogBase_Rce import LogBase_Rce_Scan
from cve.BTWaf.BTWaf_Sql import BTWaf_Sql_Scan
from cve.SolarView.SolarView_File_Read import SolarView_File_Read_Scan
from cve.Copyparty.CVE_2023_37474 import Cve_2023_37474
from cve.YouDian.YouDian_Sql import YouDian_Sql_Scan
from cve.Acmailer.Acmailer_Rce import Acmailer_Rce_Scan
from cve.Redmine.Redmine_Wsq import Redmine_Wsq_Scan
from cve.Redmine.Redmine_File_Read import Redmine_File_Read_Scan
from cve.WyreStorm.CVE_2024_25735 import Cve_2024_25735
from cve.Aiohttp.CVE_2024_23334 import Cve_2024_23334
from cve.KingSuperSCADA.CNVD_2024_08404 import Cnvd_2024_08404
from cve.Byzoro.CVE_2024_0939 import Cve_2024_0939
from cve.Likeshop.CVE_2024_0352 import Cve_2024_0352
from cve.ThinkAdmin.ThinkAdmin_Dir_Info import ThinkAdmin_Dir_Info_Scan
from cve.ThinkAdmin.ThinkAdmin_File_Read import ThinkAdmin_File_Read_Scan
from cve.vBulletin.CVE_2019_16759 import Cve_2019_16759
from cve.Harbor.CVE_2019_16097 import Cve_2019_16097
from cve.TMall.CVE_2024_2074 import Cve_2024_2074
from cve.AspCMS.AspCMS_Sql import AspCMS_Sql_Scan
from cve.AspCMS.AspCMS_Sql2 import AspCMS_Sql_Scan2
from cve.AspCMS.AspCMS_Admin_Path import AspCMS_Admin_Path_Scan
from cve.Kindeditor.Kindeditor_Upload_Dir import Kindeditor_Upload_Dir_Scan
from cve.Fckeditor.Fckeditor_Upload_Dir import Fckeditor_Upload_Dir_Scan
from cve.JetBrains.CVE_2024_27198 import Cve_2024_27198
from cve.Mkdocs.Mkdocs_File_Read import Mkdocs_File_Read_Scan
from cve.Ueditor.Ueditor_Upload_Dir import Ueditor_Upload_Dir_Scan



modules = [
    {"name": "Vuls", "description": "通过Url自动调用大量[b bright_red]脚本/工具[/b bright_red]扫描目标信息及漏洞([b red]耗时长[/b red])", "params": {"url": url,"header":ua,"proxy": proxy,"ssl": ssl,"threads": threads,"output":False,"cmd":cmd,"file":file,"timeout":timeout,"shell":"shhhelll.jsp","dnslog": "xxx.com","max": 5,"depth":False},'poc': VulsScanAll},
    {"name": "Vuls", "description": "快速打点工具[b bright_red]POC-bomber[/b bright_red]移植", "params": {"url": url},'poc': POC_bomber_Scan},
    {"name": "Vuls", "description": "快速打点工具[b bright_red]Vulcat[/b bright_red]移植", "params": {"url": url},'poc': Vulcat_Scan},
    {"name": "Vuls", "description": "快速打点工具[b bright_red]Vulmap[/b bright_red]移植", "params": {"url": url},'poc': Vulmap_Scan},

    {"name": "Vuls", "description": "快速打点工具[b bright_red]VulnX[/b bright_red]移植", "params": {"url": url},'poc': VulnX_Scan},
    {"name": "Vuls", "description": "快速打点工具[b bright_red]XSSCon[/b bright_red]移植", "params": {"url": url},'poc': XSSCon_Scan},


    {"name": "Vuls", "description": "[b bright_red]sqlmap[/b bright_red]移植", "params": {"sqlmap": "输入需要执行的语句,如: -u 'http://google.com' --dbs/-r sqltest.txt","Tips":"url需要引号包裹,默认--batch,默认输出result目录(写死),-r时文件放置run.py同目录"},'poc': SqlMap_Run_Scan},
    {"name": "Vuls", "description": "[b bright_red]GHR[/b bright_red]漏洞扫描工具移植", "params": {"url": url,"proxy":proxy,"update":False,"nodir":True},'poc': GHR_Scan},
    {"name": "Web", "description": "通过domain枚举子域名([b bright_red]短时间[/b bright_red])", "params": {"domain": domain,"ssl": ssl,},'poc': DomainScanInfo},
    {"name": "Web", "description": "通过domain枚举子域名([b bright_red]长时间[/b bright_red])", "params": {"domain": domain,"threads": threads,"header": ua,"ssl": ssl,"proxy": proxy},'poc': ScanDomain},
    {"name": "Web", "description": "通过url枚举[b bright_red]dir/web路径[/b bright_red]", "params": {"url": url,"threads": threads,"header": ua,"ssl": ssl,"proxy": proxy},'poc': Dirsearch},
    {"name": "Web", "description": "通过domain扫描[b bright_red]cert/dns/ip/domain[/b bright_red]信息", "params": {"domain": domain},'poc': CERTScan},
    {"name": "Web", "description": "通过domain名称随机生成[b bright_red]Password爆破字典[/b bright_red]", "params": {"domain": domain,"counts": 50000},'poc': PwdsDomain},
    {"name": "Web", "description": "通过securitytrails扫描domain的[b bright_red]ip/dns/domain[/b bright_red]信息", "params": {"domain": domain},'poc': HistoryIpScan},
    {"name": "Web", "description": "通过[b bright_red]jsfinder[/b bright_red]扫描目标网站源码敏感信息", "params": {"url": url,"cookie": cookie, "depth": False,"threads":threads,"proxy": proxy,"ssl": ssl},'poc': JsFinderScan},
    {"name": "Web", "description": "通过[b bright_red]jsfinder[/b bright_red]扫描目标网站源码敏感信息,对传参对数据进行SQL/XSS/目录穿越检测", "params": {"url": url,"cookie": cookie, "depth": False,"threads":threads,"proxy": proxy,"ssl": ssl},'poc': JsFinderScan2},
    {"name": "Web", "description": "[b bright_red]JSscanner[/b bright_red]工具移植,递归式网站目录扫描", "params": {"url": url,"header":ua,"wait":3,"height": 0,"proxy":proxy,"level":0, "timeout":0,"ssl":ssl,"*Tips1*": "wait为请求超时等待时间｜height为查找深度","*Tips2*":"level为最大递减数，默认0为全递减｜timeout为请求间隔延时"},'poc': JscannerMaster},
    {"name": "Web", "description": "通过ip扫描目标网站[b bright_red]端口[/b bright_red]信息", "params": {"ip": ip,"nums": 10000,"threads": threads},'poc': ScanProt},
    {"name": "Web", "description": "通过url扫描目标网站port[b bright_red]端口[/b bright_red]信息", "params": {"url": url,"nums": 10000,"header":ua,"ssl": ssl,"proxy": proxy,"timeout":timeout,"threads": threads},'poc': DoaminScanProt},
    {"name": "Web", "description": "扫描目标网站dir[b bright_red]中间件[/b bright_red]路径信息", "params": {"url": url,"threads": threads,"ssl": ssl,"header": ua,"proxy": proxy},'poc': ZhongJianJianScan},
    {"name": "Web", "description": "通过ip扫描目标网站[b bright_red]未授权[/b bright_red]漏洞", "params": {"ip": ip,"ssl": ssl,"header": ua,"proxy": proxy},'poc': SecurityCheckScan},
    {"name": "Web", "description": "[b bright_red]FindSomeThing[/b bright_red]工具移植", "params": {"url": url},'poc': Find_Some_Thing},

    {"name": "Web", "description": "[b bright_red]Jjjjjjjjjjjjjs[/b bright_red]工具移植,爬网站JS文件,自动fuzz api接口,指定api接口", "params": {"url": url},'poc': jjjjjjjjjjjjjs_Scan},

    {"name": "Web", "description": "[b bright_red]Dirpro[/b bright_red]工具移植,目录扫描器,自动使用随机的User-Agent", "params": {"url": url,"threads":threads,"proxy":proxy},'poc': Dirpro_Scan},
    {"name": "Web", "description": "通过[b bright_red]Shodan[/b bright_red]搜索引擎批量搜索/导出域名信息", "params": {"query": "hostname:baidu.com/product:nginx","pass": 10,"Tips":"pass为返回错误次数,当次数达到设定的pass次后自动退出"},'poc': ShodanWork},
    {"name": "Web", "description": "通过[b bright_red]Censys[/b bright_red]搜索域名相关的IP信息", "params": {"domain": domain,"cookie":censys_api},'poc': CensysDomainInfo},
    {"name": "Web", "description": "通过[b bright_red]Censys[/b bright_red]搜索IP及端口信息", "params": {"domain": domain,"cookie":censys_api},'poc': CensysInfo},
    {"name": "Web", "description": "GitHack工具移植,通过网站泄漏的[b bright_red]Git[/b bright_red]文件信息下载网站源码信息", "params": {"url": url},'poc': GitHackScan},
    {"name": "Web", "description": "通过多方平台收集[b bright_red]Domain/IP[/b bright_red]信息([b red]强烈推荐[/b red])", "params": {"domain": domain,"output":False,"max":5},'poc': DomainAll},
    {"name": "Web", "description": "通过[b bright_red]Knock[/b bright_red]收集域名信息", "params": {"domain": domain,"threads":threads},'poc': Knock},
    {"name": "Web", "description": "FOFA[b bright_red]无需会员[/b bright_red]即可爬取多页脚本", "params": {"Tips": "直接run"},'poc': Fofacrocs},
    {"name": "Web", "description": "针对Webpack等前端打包工具所构造的网站进行js/api快速、高效安全检测[b bright_red]Packer-Fuzzer[/b bright_red]工具移植", "params": {"url": url,"proxy":proxy},'poc': Packer_Fuzzer_Run_Scan},
    {"name": "Web", "description": "专注一站式解决渗透测试的信息收集任务(IP/DNS/Port/Domain/CDN/Cms/Waf)[b bright_red]SiteScan[/b bright_red]工具移植", "params": {"url": url,"proxy":proxy},'poc': SiteScan_Run},
    {"name": "Web", "description": "后台信息收集任务[b bright_red]okadminfinder[/b bright_red]工具移植", "params": {"url": url,"proxy":proxy},'poc': okadminfinder_Run_Scan},
    {"name": "Web", "description": "提供漏洞详细信息和相关验证(PoC)的工具[b bright_red]SploitScan[/b bright_red]工具移植([b red]一款不错的辅助工具[/b red])", "params": {"cve": "CVE-2020-8888","Tips":"查询多个CVE时用空格分割"},'poc': SploitScan_Run},
    {"name": "Web", "description": "利用工具从Cloudflare中发现源IP[b bright_red]CloudFail[/b bright_red]工具移植", "params": {"url": url},'poc': CloudFail_Run_Scan},
    {"name": "Web", "description": "查找Cloudflare保护的网站的真实IP地址[b bright_red]CloakQuest3r[/b bright_red]工具移植","params": {"url": url}, 'poc': CloakQuest3r_Run_Scan},


    {"name": "WordPress", "description": "[b bright_red]WpRest[/b bright_red]工具移植,检测Wordpress网站信息", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy},'poc': WpRestScan},
    {"name": "WordPress", "description": "WordPress [b bright_red]CVE-2022-21661[/b bright_red]SQL注入漏洞", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout,"batch_work":False},"attack":"wp-",'poc': Cve_2022_21661},
    {"name": "WordPress", "description": "WordPress Paid Memberships Pro[b bright_red]CVE-2023-23488[/b bright_red]SQL注入漏洞", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False},"attack":"wp-",'poc': Cve_2023_23488},
    {"name": "WordPress", "description": "WordPress Masterstudy-LMS-3.0.17[b bright_red]CVE-2023-4278[/b bright_red]Unauthenticated Instructor Account Creation", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"wp-",'poc': Cve_2023_4278},
    {"name": "WordPress", "description": "WordPress Backup Migration[b bright_red]CVE-2023-6553[/b bright_red]Rce漏洞", "params": {"url": url,"batch_work":False},"attack":"wp-",'poc': Cve_2023_6553},
    {"name": "WordPress", "description": "Wordpress 4.6[b bright_red]CVE-2016-10033[/b bright_red]PwnScriptum任意命令执行漏洞", "params": {"url": url,"proxy": proxy,"header": ua,"ssl": ssl,"adminname":"admin"},'poc': Wordpress4_6_Rce_Scan},
    {"name": "WordPress", "description": "Wordpress 漏洞检测[b bright_red]WPvSCAN[/b bright_red]工具移植", "params": {"url": url},'poc': WPvSCAN_Scan},
    {"name": "WordPress", "description": "Wordpress Elementor网站生成器[b bright_red]CVE-2023-0329[/b bright_red]SQL注入", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"wp-",'poc': Cve_2023_0329},
    {"name": "WordPress", "description": "Wordpress WP ERP 1.12.2[b bright_red]CVE-2023-2744[/b bright_red]SQL注入", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"wp-",'poc': Cve_2023_2744},
    {"name": "WordPress", "description": "Wordpress admin-ajax.php[b bright_red]文件包含[/b bright_red]注入", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="wp-content/themes/motor"'},"attack":"wp-",'poc': Wordpress_Lfi_Scan},
    {"name": "WordPress", "description": "Wordpress [b bright_red]后台用户[/b bright_red]注册开启漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},'poc': WordpressRegScan},
    {"name": "WordPress", "description": "Wordpress Listingo[b bright_red]文件上传[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="wp-content/themes/listingo"'},"attack":"wp-",'poc': Wordpress_Listingo_File_Upload_Scan},
    {"name": "WordPress", "description": "Wordpress Bricks Builder 插件[b bright_red]RCE[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="/wp-content/themes/bricks/"'},"attack":"wp-",'poc': Cve_2024_25600},
    {"name": "WordPress", "description": "WordPress Plugin HTML5 Video Player[b bright_red]CVE-2024-1061[/b bright_red]SQL注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'wordpress && body="html5-video-player"'},"attack":"wp-",'poc': Cve_2024_1061},
    {"name": "WordPress", "description": "WordPress LMS[b bright_red]CVE-2024-1208[/b bright_red]敏感信息泄漏漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'"/sfwd-question"'},"attack":"wp-",'poc': Cve_2024_1208},
    {"name": "WordPress", "description": "WordPress wp-file-manager[b bright_red]CVE-2020-25213[/b bright_red]文件上传漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"wp-",'poc': Cve_2020_25213},
    {"name": "WordPress", "description": "WordPress The Simple File List[b bright_red]CVE-2022-1119[/b bright_red]任意文件下载漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"wp-",'poc': Cve_2022_1119},
    {"name": "WordPress", "description": "WordPress SupportCandy[b bright_red]CVE-2023-1730[/b bright_red]SQL注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"wp-",'poc': Cve_2023_1730},
    {"name": "WordPress", "description": "WordPress All-in-One Video Gallery video.php[b bright_red]CVE-2022-2633[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"wp-",'poc': Cve_2022_2633},
    {"name": "WordPress", "description": "WordPress Duplicator duplicator.php[b bright_red]CVE-2020-11738[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"wp-",'poc': Cve_2020_11738},

    {"name": "Nacos", "description": "扫描目标网站[b bright_red]QVD-2023-6271[/b bright_red]及一系列nacos漏洞", "params": {"url": url,"ssl":ssl,"proxy":proxy,"batch_work":False,"fofa":'title="HTTP Status 404 – " || app="Nacos"'},"attack":"nacos",'poc': Qvd_2023_6271},
    {"name": "Nacos", "description": "工具[b bright_red]HKEcho_Nacos_main[/b bright_red]移植需windows系统执行", "params": {"url": url},'poc': NacosR},
    {"name": "JQuery", "description": "扫描jquery的[b bright_red]CVE-2018-9206[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,},'poc': Cve_2018_9206},
    {"name": "JQuery", "description": "扫描jquery[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"file":file,"header":ua,"proxy":proxy,"ssl": ssl,"batch_work":False,"fofa":'body="webui/js/jquerylib/jquery-1.7.2.min.js"'},"attack":"webui/js/jquerylib/jquery-1.7.2.min.js",'poc': JqueryDirReadScan},
    {"name": "Log", "description": "扫描网站[b bright_red]日志文件[/b bright_red]", "params": {"url": url,"threads":threads,"header":ua,"proxy":proxy,"ssl": ssl,"batch_work":False},'poc': LogScan},
    {"name": "ThinkPHP", "description": "thinkphp2x3x5x的漏洞检测[b bright_red]ThinkPHP-Scan[/b bright_red]工具移植", "params": {"url": url},"attack":"thinkphp",'poc': ThinkphpScanMaster},
    {"name": "ThinkPHP", "description": "受影响版本Thinkphp[b bright_red]6.0.1~6.0.13[/b bright_red]lang", "params": {"url": url, "header": ua,"proxy":proxy,"ssl": ssl,"batch_work":False},"attack":"Think",'poc': ThinkPhpV6},
    {"name": "ThinkPHP", "description": "Thinkphp[b bright_red]3.x/5.x[/b bright_red]全版本SQL注入检测", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout},'poc': ThinkSqlScan},
    {"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 5.0.x配置文件泄漏","params": {"url": url,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout,"batch_work":False},"attack":"Think", 'poc': ThinkDBScan},
    {"name": "ThinkPHP", "description": "[b bright_red]ThinkPHP[/b bright_red] 3.x/5.x全版本RCE扫描","params": {"url": url,"ssl": ssl,"header": ua,"proxy": proxy, "timeout": timeout}, 'poc': ThinkRCEScan},

    {"name": "JBoss", "description": "扫描历史各类[b bright_red]Jboss[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl, "header": ua,"proxy":proxy,"batch_work":False},"attack":"jboss",'poc': JbossVulsScan},
    {"name": "FastAdmin", "description": "FastAdmin后台[b bright_red]文件上传[/b bright_red]漏洞", "params": {"url": url, "header": ua, "cookie":cookie, "ssl": ssl,"proxy":proxy},'poc': FastAdminDirUploadScan},
    {"name": "FTP", "description": "通过IP检测FTP[b bright_red]笑脸[/b bright_red]漏洞", "params": {"ip": ip},'poc': FtpScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]debug.jsp代码执行[/b bright_red]漏洞", "params": {"url": url,"cmd":cmd,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Landray",'poc': LanlingDebugRceScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"file":file,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Landray",'poc': LanlingDirReadScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]SSRF-GETSHELL[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Landray",'poc': LanlingSsrfGetshellScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]SSRF-JNDI[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Landray",'poc': LanlingSsrfJndiScan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]登录绕过[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},'poc': Lanling_getLoginSessionId_login_bypass_Scan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]SQL[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'icon_hash="953405444"||app="Landray-OA系统"'},"attack":"Landray",'poc': Lanling_Sql_Scan},
    {"name": "LanLing", "description": "检测LanLing[b bright_red]信息泄露[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="Landray-EIS智慧协同平台"'},"attack":"Landray",'poc': Lanling_Info_Scan},
    {"name": "Node-JS", "description": "Node-JS[b bright_red]CVE-2021-21315[/b bright_red]监听端口转发漏洞", "params": {"url": url,"proxy":proxy,"header":ua,"lhost":lhost,"lport":lport,"ssl":ssl},'poc': Cve_2021_21315Nc},
    {"name": "Node-JS", "description": "Node-JS[b bright_red]CVE-2021-21315[/b bright_red]检测并利用", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"batch_work":False},"attack":"node.js",'poc': Cve_2021_21315},
    {"name": "Node-JS", "description": "Node-JS[b bright_red]CVE-2017-14849[/b bright_red]任意文件读取", "params": {"url": url,"proxy":proxy,"header":ua,"ssl":ssl,"batch_work":False},"attack":"node.js",'poc': Cve_2017_14849},
    {"name": "Plesk", "description": "Plesk[b bright_red]CVE-2023-24044[/b bright_red]重定向漏洞", "params": {"url": url,"cdx":"baidu.com","ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"plesk",'poc': Cve_2023_24044},
    {"name": "Redis", "description": "检测Redis[b bright_red]CVE-2022-0543/未授权[/b bright_red]漏洞", "params": {"ip": ip,"port":6379,"threads": threads},'poc': Cve_2022_0543},
    {"name": "Redis", "description": "检测Redis[b bright_red]未授权[/b bright_red]漏洞", "params": {"ip": ip,"port":6379},'poc': RedisunanthourScan},
    {"name": "Redis", "description": "Redis基于主从复制的[b bright_red]RCE[/b bright_red]4.x/5.x漏洞", "params": {"rhost":ip,"rport":6379,"lhost": ip,"lport":21000},'poc': Redis_Scan_Run},
    {"name": "Vue", "description": "检测Vue[b bright_red]接口文件[/b bright_red]是否存在敏感信息泄露", "params": {"url": url,"header":ua,"threads": threads,"proxy":proxy,"ssl":ssl,"cookie":cookie},'poc': VueJsScaner},
    {"name": "Spring", "description": "[b bright_red]SpringBootScan[/b bright_red]工具移植扫描Spring敏感信息泄露", "params": {"url": url,"proxy":proxy},'poc': SpringBootScan},
    {"name": "Spring", "description": "[b bright_red]SBScan[/b bright_red]工具移植扫描Spring敏感信息泄露及漏洞利用", "params": {"url": url,"proxy":proxy,"dnslog": None,"threads":threads,"webscan":False,"*Tips*":"webscan为True只对存在spring指纹的网站开始扫描"},'poc': SBScan},
    {"name": "Spring", "description": "JeeSpringCloud[b bright_red]uploadFile.jsp[/b bright_red]存在任意文件上传", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False,"fofa":'body="Whitelabel Error Page"'},"attack":"Whitelabel Error Page",'poc': JeeSpringCloudUploadFileScan},
    {"name": "Spring", "description": "Spring Cloud Gateway[b bright_red]CVE-2022-22947[/b bright_red]远程代码执行漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False,"fofa":'header="Vary: Accept-Encoding" && header="X-Cache: HIT"'},"attack":"Whitelabel Error Page",'poc': Cve_2022_22947},
    {"name": "Spring", "description": "Spring框架Data Binding与JDK 9+导致的[b bright_red]CVE-2022-22965[/b bright_red]远程代码执行漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="Whitelabel Error Page"'},"attack":"Whitelabel Error Page",'poc': Cve_2022_22965},
    {"name": "Spring", "description": "Spring框架Data Binding与JDK 9+导致的[b bright_red]CVE-2022-22965[/b bright_red]远程代码执行漏洞Poc2", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"timeout":timeout,"fofa":'body="Whitelabel Error Page"'},"attack":"Whitelabel Error Page",'poc': Cve_2022_22965_Poc2},
    {"name": "Spring", "description": "Spring Cloud Function[b bright_red]CVE-2022-22963[/b bright_red]SpEL表达式命令注入漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="Whitelabel Error Page"'},"attack":"Whitelabel Error Page",'poc': Cve_2022_22963},
    {"name": "Spring", "description": "Spring[b bright_red]Dump[/b bright_red]漏洞", "params": {"url": url,"proxy":proxy,"header":ua,"timeout":timeout,"ssl":ssl,"batch_work":False,"fofa":'body="Whitelabel Error Page"'},"attack":"Whitelabel Error Page",'poc': SpringDumpScan},
    {"name": "Spring", "description": "SpringBlade export-user接口[b bright_red]SQL[/b bright_red]注入漏洞", "params": {"url": url,"proxy":proxy,"header":ua,"timeout":timeout,"ssl":ssl,"batch_work":False,"fofa":'body="https://bladex.vip"'},"attack":"https://bladex.vip",'poc': SpringBlade_Sql_Scan},
    {"name": "Spring", "description": "SpringBlade /api/blade-log/error/list[b bright_red]DVB-2024-6364[/b bright_red]SQL注入漏洞", "params": {"url": url,"proxy":proxy,"header":ua,"ssl":ssl,"batch_work":False,"fofa":'body="https://bladex.vip"'},"attack":"https://bladex.vip",'poc': Dvb_2024_6364},

    {"name": "RocketMQ", "description": "RocketMQ[b bright_red]CVE-2023-33246[/b bright_red]漏洞检测", "params": {"ip": ip,"port":port},'poc': Cve_2023_33246},
    {"name": "RocketMQ", "description": "RocketMQ[b bright_red]默认用户[/b bright_red]检测", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"rocketmq",'poc': RocketUserScan},
    {"name": "Struts", "description": "[b bright_red]Struts2Scan[/b bright_red]工具移植", "params": {"url": url,"proxy":proxy},'poc': Struts2Scaner},
    {"name": "Shiro", "description": "[b bright_red]ShiroScan-master[/b bright_red]工具移植,Shiro<=1.2.4反序列化", "params": {"url": url,"cmd":cmd},'poc': ShiroScan},
    {"name": "Shiro", "description": "[b bright_red]Shiro[/b bright_red]特征检测", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"batch_work":False},'poc': Shiro_Check_Run},
    {"name": "Shiro", "description": "Shiro[b bright_red]前台任意文件下载[/b bright_red]漏洞检测", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"batch_work":False},'poc': Shiro_File_Dump_Scan},
    {"name": "Shiro", "description": "[b bright_red]Shiro-Exploit[/b bright_red]工具移植", "params": {"url": url,"ssl":ssl,"proxy":proxy},'poc': Shiro_Exp_Scan},
    {"name": "Grafana", "description": "Grafana[b bright_red]Metrics[/b bright_red]文件扫描", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"grafana",'poc': GrafanaMetricsScan},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2022-32276[/b bright_red]数据库快照泄漏漏洞扫描", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2022_32276},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2022-32275[/b bright_red]任意文件读取漏洞扫描", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2022_32275},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2021-43798[/b bright_red]任意文件读取漏洞扫描,利用点2", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2021_43798_2},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2021-43798[/b bright_red]任意文件读取", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"threads":threads},'poc': Cve_2021_43798},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2021-39226[/b bright_red]数据库快照泄露", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2021_39226},
    {"name": "Grafana", "description": "Grafana[b bright_red]CVE-2020-11110[/b bright_red]XSS漏洞检测", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"poc":"<script>alert(1)</script>"},'poc': Cve_2020_11110},
    {"name": "Swagger", "description": "[b bright_red]Swagger-Hack[/b bright_red]工具移植", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Swagger_Hack_Scan},
    {"name": "FunAdmin", "description": "FunAdmin[b bright_red]CVE-2023-24775[/b bright_red]漏洞扫描", "params": {"url": url,"ssl":ssl,"proxy":proxy},'poc': Cve_2023_24775},
    {"name": "Zimbra", "description": "Zimbra[b bright_red]CVE-2022-27925[/b bright_red]漏洞扫描", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy},'poc': Cve_2022_27925},
    {"name": "Zimbra", "description": "Zimbra[b bright_red]CVE-2022-27925[/b bright_red]漏洞扫描利用点2", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"zimbra",'poc': Cve_2022_27925Poc2},
    {"name": "Zabbix", "description": "Zabbix[b bright_red]CVE-2022-23131[/b bright_red]漏洞扫描", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"batch_work":False},"attack":"zabbix",'poc': Cve_2022_23131},
    {"name": "Zabbix", "description": "Zabbix[b bright_red]CVE-2016-10134[/b bright_red]sql注入漏洞扫描", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"batch_work":False},"attack":"zabbix",'poc': Cve_2016_10134},
    {"name": "NetScaler", "description": "NetScaler ADC&NetScaler Gateway[b bright_red]CVE-2023-4966[/b bright_red]敏感信息泄露漏洞扫描", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Cve_2023_4966},
    {"name": "Juniper", "description": "[b bright_red]CVE-2023-36845[/b bright_red]Juniper Networks Junos OS EX远程命令执行漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"juniper",'poc': Cve_2023_36845},
    {"name": "Jeecg", "description": "[b bright_red]CVE-2023-33510[/b bright_red]Jeecg P3 Biz Chat 任意文件读取漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"jeecg",'poc': Cve_2023_33510},
    {"name": "Apache", "description": "[b bright_red]CVE-2021-41773/CVE-2021-42013[/b bright_red]Apache HTTP Server 2.4.50远程代码执行漏洞", "params": {"url": url,"header":ua, "ssl":ssl},'poc': Cve_2021_41773},
    {"name": "Apache", "description": "[b bright_red]CVE-2021-41773/CVE-2021-42013[/b bright_red]Apache HTTP Server 2.4.50远程代码执行漏洞-检测Poc", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"batch_work":False},"attack":"apache",'poc': Cve_2021_41773_2},
    {"name": "Apache", "description": "[b bright_red]Apache Skywalking[/b bright_red]<=8.3 SQL注入", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},"attack":"apache",'poc': SkywalkingSqlScan},
    {"name": "Apache", "description": "Apache Tomcat[b bright_red]CVE-2018-2894[/b bright_red]文件上传", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout,"batch_work":False},"attack":"apache",'poc': Cve_2018_2894},
    {"name": "Apache", "description": "Apache[b bright_red]PUT[/b bright_red]文件上传", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},"attack":"apache",'poc': ApachePutScan},
    {"name": "Apache", "description": "Apache ActiveMQ[b bright_red]CVE-2016-3088[/b bright_red]任意文件写入漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},"attack":"apache",'poc': Cve_2016_3088},
    {"name": "Apache", "description": "Apache Struts[b bright_red]CVE-2023-50164[/b bright_red]RCE漏洞", "params": {"url": url,"batch_work":False},"attack":"apache",'poc': Cve_2023_50164},
    {"name": "Apache", "description": "Apache Weblogic漏洞[b bright_red]weblogicScaner[/b bright_red]工具移植", "params": {"ip": ip},'poc': weblogicRunScan},
    {"name": "Apache", "description": "Apache APISIX[b bright_red]CVE-2021-45232/CVE-2020-13945[/b bright_red]默认密钥|未授权访问漏洞", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False,"fofa":'title="Apache APISIX Dashboard"'},"attack":"apache",'poc': Cve_2020_13945},
    {"name": "Apache", "description": "Apache OFBiz groovy[b bright_red]远程代码执行[/b bright_red]漏洞", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False,"fofa":'app="Apache_OFBiz"'},"attack":"apache",'poc': Cve_2023_51467},
    {"name": "Apache", "description": "Apache Solr [b bright_red]CVE-2023-50290[/b bright_red]环境变量信息泄漏漏洞", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False,"fofa":'app="APACHE-Solr"'},"attack":"apache",'poc': Cve_2023_50290},
    {"name": "Apache", "description": "Apache Tomcat存在[b bright_red]CVE-2024-21733[/b bright_red]信息泄露漏洞([b yellow]判定有误[/b yellow])", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False,"fofa":'app="APACHE-Tomcat"'},"attack":"apache",'poc': Cve_2024_21733},
    {"name": "Apache", "description": "Apache 检测是否存在[b bright_red]Log4j[/b bright_red]", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False},'poc': Log4j_Check_Run},
    {"name": "Apache", "description": "Apache Log4j漏洞检测[b bright_red]Log4j-Scan[/b bright_red]工具移植", "params": {"url": url},'poc': Log4j_Scan_Scan},

    {"name": "EOffice", "description": "[b bright_red]Weaver-Exp-Scan[/b bright_red]泛微-EOffice检测工具移植", "params": {"url": url},'poc': WeaverScan},
    {"name": "EOffice", "description": "[b bright_red]2023-Weaver-Pocs[/b bright_red]泛微-EOffice检测工具移植", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy},'poc': Weaver_Poc_Scan},
    {"name": "EOffice", "description": "泛微-EOffice[b bright_red]数据库信息[/b bright_red]泄漏", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="泛微-EOffice"'},"attack":"泛微-EOffice",'poc': FanweiDBInfoScan},
    {"name": "EOffice", "description": "泛微-EOffice Officeserver[b bright_red]任意文件读取[/b bright_red]泄漏", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="泛微-EOffice"'},"attack":"泛微-EOffice",'poc': Ecology_oa_file_read_Scan},
    {"name": "EOffice", "description": "泛微-EOffice SptmForPortalThumbnail[b bright_red]任意文件读取[/b bright_red]泄漏", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="泛微-EOffice"'},"attack":"泛微-EOffice",'poc': SptmForPortalThumbnail_file_read_Scan},
    {"name": "EOffice", "description": "泛微-EOffice GetE9DevelopAllNameValue2[b bright_red]任意文件读取[/b bright_red]泄漏", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="泛微-EOffice"'},"attack":"泛微-EOffice",'poc': GetE9DevelopAllNameValue2_file_read_Scan},
    {"name": "BigIP", "description": "[b bright_red]CVE-2023-46747[/b bright_red]Big-IP CVE-2023-46747-Rce", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False,"fofa":'title="BIG-IP&reg;- Redirect"'},"attack":"BIG-IP",'poc': Cve_2023_46747},
    {"name": "BigIP", "description": "[b bright_red]CVE-2023-46747[/b bright_red]Big-IP CVE-2023-46747-Rce-Poc2", "params": {"url": url,"proxy":proxy,"ssl":ssl,"header":ua,"timeout":timeout,"cmd":cmd},'poc': Cve_2023_46747Poc2},
    {"name": "BigIP", "description": "[b bright_red]CVE-2022-1388[/b bright_red]Big-IP CVE-2022-1388-Rce", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'title="BIG-IP&reg;- Redirect"'},"attack":"BIG-IP",'poc': Cve_2022_1388},

    {"name": "Joomla", "description": "[b bright_red]CVE-2023-23752[/b bright_red]CVE-2023-23752身份验证绕过，导致Joomla上的信息泄露", "params": {"url": url,"ssl":ssl,"proxy":proxy,"timeout":timeout,"batch_work":False},"attack":"joomla",'poc': Cve_2023_23752},
    {"name": "Joomla", "description": "[b bright_red]CVE-2017-8917[/b bright_red]Joomla-3.7.0-SQL注入漏洞", "params": {"url": url,"header":ua,"proxy":proxy},'poc': Cve_2017_8917},
    {"name": "Joomla", "description": "[b bright_red]CVE-2017-8917[/b bright_red]Joomla-3.7.0-SQL注入漏洞利用点2(推荐)", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout,"batch_work":False},"attack":"joomla",'poc': Cve_2017_8917Poc2},
    {"name": "Joomla", "description": "Joomla[b bright_red]一键GetShell[/b bright_red]", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"timeout":timeout,"batch_work":False},"attack":"joomla",'poc': JoomlaGetshellScan},
    {"name": "Joomla", "description": "Joomla[b bright_red]CVE-2023-23752[/b bright_red]权限绕过漏洞POC-2", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"timeout":timeout},'poc': Cve_2023_23752_2},
    {"name": "Laravel", "description": "[b bright_red]CVE-2021-3129[/b bright_red]Laravel一键GetShell", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl},'poc': Cve_2021_3129},
    {"name": "Laravel", "description": "[b bright_red]CVE-2021-3129[/b bright_red]Laravel检测", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False},"attack":"laravel",'poc': Cve_2021_3129_Check},
    {"name": "Laravel", "description": "Laravel[b bright_red]敏感信息泄漏[/b bright_red]检测", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"timeout":timeout,"batch_work":False},"attack":"laravel",'poc': LaravelInfoScan},
    {"name": "Nginx", "description": "[b bright_red]NginxWebUI[/b bright_red]命令执行", "params": {"url": url,"cmd":cmd,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"NginxWebUI",'poc': NginxRceScan1},
    {"name": "Nginx", "description": "Nginx/OpenResty[b bright_red]目录穿越[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},'poc': Nginx_File_Read_Scan},
    {"name": "CmsEasy", "description": "[b bright_red]CmsEasy[/b bright_red] SQL注入", "params": {"url": url,"ssl":ssl,"timeout":timeout,"proxy":proxy,"batch_work":False},"attack":"cmseasy",'poc': CmsEasySqlScan},
    {"name": "DocCms", "description": "[b bright_red]DocCms[/b bright_red] SQL注入", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},"attack":"doccms",'poc': DocSqlScan},
    {"name": "JeecgBoot", "description": "[b bright_red]JeecgBoot[/b bright_red] SQL注入", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},"attack":"jeecgboot",'poc': JeecgSql},
    {"name": "JeecgBoot", "description": "Jeecg-Boot/积木报表系统testConnection接口存在[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"jeecgboot",'poc': JeecgBoot_Rce_Scan},
    {"name": "PBootCms", "description": "[b bright_red]PBootCms[/b bright_red] SQL注入", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},'poc': PBSqlScan},
    {"name": "WSO2", "description": "WSO2[b bright_red]CVE-2022-29464[/b bright_red]put文件上传", "params": {"url": url,"shell":"shhhelll.jsp","ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},"attack":"wso2",'poc': Cve_2022_29464},
    {"name": "JshERPBoot", "description": "[b bright_red]JshERPBoot[/b bright_red]敏感信息泄漏", "params": {"url": url,"ssl":ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False},'poc': JshErpBootScan},
    {"name": "Openfire", "description": "Openfire[b bright_red]CVE-2023-32315[/b bright_red]日志信息泄漏/添加用户", "params": {"url": url,"header":ua,"proxy":proxy,"batch_work":False},"attack":"openfire",'poc': Cve_2023_32315},
    # {"name": "Ivanti", "description": "Ivanti Sentry[b bright_red]CVE-2023-38035[/b bright_red]Rce漏洞", "params": {"url": url,"cmd":cmd,"header":ua,"ssl":ssl,"proxy":proxy},'poc': Cve_2023_38035},
    {"name": "Ivanti", "description": "Ivanti Connect Secure[b bright_red]CVE-2023-46805/CVE-2024-21887[/b bright_red]Rce漏洞", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"batch_work":False,"fofa":'body="welcome.cgi?p=logo"'},"attack":"welcome.cgi?p=logo",'poc': Cve_2024_21887},

    {"name": "FastJson", "description": "检测网站是否使用[b bright_red]FastJson[/b bright_red]", "params": {"url": url,"header":ua,"ssl":ssl,"proxy":proxy,"ceyedns": ceye_dns,"ceyeapi":ceye_api,"batch_work":False,},'poc': FastJsonCheckScan},
    {"name": "JindieYun", "description": "金蝶云星空[b bright_red]ScpSupRegHandler[/b bright_red]任意文件上传", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False},"attack":"kingdee",'poc': JindieYunUpFileScan},
    {"name": "JindieYun", "description": "金蝶云星空[b bright_red]GetShell[/b bright_red]", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"batch_work":False},"attack":"kingdee",'poc': JindieYunShellScan},
    {"name": "JindieEAS", "description": "金蝶EAS[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"header":ua,"proxy":proxy,"ssl":ssl,"fofa":'app="Kingdee-EAS"',"batch_work":False},"attack":"kingdee",'poc': Jindie_File_Read_Scan},
    {"name": "EasyCVR", "description": "视频监控汇聚平台EasyCVR[b bright_red]敏感信息泄漏[/b bright_red]漏洞","params": {"url": url, "ssl": ssl,"header": ua, "proxy": proxy,"batch_work":False},"attack":"easycvr", 'poc': EasyCVRInfoScan},
    {"name": "MeterSphere", "description": "MeterSphere[b bright_red]任意文件下载[/b bright_red]漏洞","params": {"url": url, "header": ua, "proxy": proxy, "ssl": ssl,"batch_work":False},"attack":"metersphere", 'poc': MeterSphereDumpFileScan},
    {"name": "MeterSphere", "description": "MeterSphere customMethod[b bright_red]远程命令执行[/b bright_red]漏洞","params": {"url": url, "header": ua, "proxy": proxy, "ssl": ssl,"batch_work":False},"attack":"metersphere", 'poc': MeterSphereRceScan},
    {"name": "Panabit", "description": "Panabit日志审计singleuser_action.php[b bright_red]任意用户添加[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False},"attack":"panabit", 'poc': PanabitUserAddScan},
    {"name": "Panabit", "description": "Panabit日志系统[b bright_red]SQL[/b bright_red]注入漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False},"attack":"panabit", 'poc': PanabitSqlScan},
    {"name": "Panabit", "description": "Panabit日志系统libres_syn_delete接口[b bright_red]远程命令执行[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False,"fofa":'app="Panabit-Panalog"'},"attack":"panabit", 'poc': Panalog_Rce_Scan},
    {"name": "JumpServer", "description": "JumpServer[b bright_red]未授权访问[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy, "batch_work":False},"attack":"jumpserver", 'poc': JumpServerInfoScan},
    {"name": "Jenkins", "description": "Jenkins[b bright_red]未授权访问[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False},"attack":"jenkins", 'poc': JenkinsWsqScan},
    {"name": "Jenkins", "description": "Jenkins[b bright_red]未授权/弱口令/注册启用[/b bright_red]漏洞扫描","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy, }, 'poc': Jenkins_unauthorizedScan},
    {"name": "Jenkins", "description": "Jenkins[b bright_red]未授权[/b bright_red]到Get Shell一键化利用","params": {"url": url}, 'poc': Jenkin_WSQ_TO_Shell_Scan},
    {"name": "Jenkins", "description": "Jenkins[b bright_red]CVE-2024-23897[/b bright_red]任意文件读取漏洞","params": {"url": url,"file":file}, 'poc': Cve_2024_23897},
    {"name": "Fortigate", "description": "Fortigate SSL VPN fgt_lang[b bright_red]敏感信息泄漏[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False,"fofa":'body="/sslvpn/js/login.js?q="'},"attack":"/sslvpn/js/login.js?q=", 'poc': FortigateIndoScan},
    {"name": "Dlink", "description": "D-Link DCS[b bright_red]密码泄露[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False},"attack":"D-LINK", 'poc': DlinkInfoScan},
    {"name": "Casdoor", "description": "Casbin get-organizations[b bright_red]SQL报错注入[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False},"attack":"casdoor", 'poc': CasdoorSqlScan},
    {"name": "Casdoor", "description": "Casbin[b bright_red]账号密码泄漏[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False},"attack":"casdoor", 'poc': CasdoorInfoScan},
    {"name": "EasyImage", "description": "EasyImage down.php[b bright_red]任意文件读取/manager.php后台任意文件上传[/b bright_red]漏洞","params": {"url": url,"ssl": ssl, "header": ua, "proxy": proxy,"batch_work":False},"attack":"easyimage", 'poc': EasyImageInfoScan},
    {"name": "PHPMyAdmin", "description": "PHPMyAdmin扫描暴露的[b bright_red]/setup/index.php[/b bright_red]路径信息", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False},"attack":"phpmyadmin",'poc': PMASetupScan},
    {"name": "PHPMyAdmin", "description": "宝塔PHPMyAdmin[b bright_red]未授权[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False},"attack":"phpmyadmin",'poc': PhpMyAdminPMAScan},

    {"name": "Minio", "description": "Minio[b bright_red]CVE-2023-28432[/b bright_red]敏感信息泄漏", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False},"attack":"minio",'poc': Cve_2023_28432},
    {"name": "Shiziyu", "description": "狮子鱼CMS[b bright_red]image_upload.php[/b bright_red]文件上传", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False,"fofa":'/seller.php?s=/Public/login'},"attack":"/seller.php?s=/Public/login",'poc': ShiZiYuShellScan},
    {"name": "Shiziyu", "description": "狮子鱼CMS[b bright_red]wxapp.php[/b bright_red]文件上传", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False,"fofa":'/seller.php?s=/Public/login'},"attack":"/seller.php?s=/Public/login",'poc': ShiZiYuShell2Scan},
    {"name": "Shiziyu", "description": "狮子鱼CMS[b bright_red]SQL[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False,"fofa":'/seller.php?s=/Public/login'},"attack":"/seller.php?s=/Public/login",'poc': ShiZiYu_Sql_Scan},
    {"name": "SeeyouOA", "description": "致远OA多处[b bright_red]敏感信息泄露[/b bright_red]", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False,"fofa":'/seeyon/index.jsp'},"attack":"/seeyon/index.jsp",'poc': ZhiyuanOAInfoScan},
    {"name": "ZeroShell", "description": "ZeroShell 3.9.0 [b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout},'poc': ZeroShellRceScan},
    {"name": "RoxyWi", "description": "Roxy-Wi options.py[b bright_red]CVE-2022-31137[/b bright_red]Haproxy远程命令执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False},"attack":"haproxy",'poc': Cve_2022_31137},
    {"name": "Ecshop", "description": "Ecshop 前台[b bright_red]SQL注入[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False},"attack":"shop",'poc': EcshopSqlScan},
    {"name": "IIS", "description": "IIS[b bright_red]PUT[/b bright_red]漏洞", "params": {"url": url,"header":ua,"ssl": ssl,"proxy":proxy,"batch_work":False},'poc': IISPutScan},
    {"name": "Ruoyi", "description": "若依管理系统[b bright_red]CNVD-2021-15555[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"ruoyi",'poc': Cnvd_2021_15555},
    {"name": "OwnCloud", "description": "OwnCloud[b bright_red]CVE-2023-49103[/b bright_red]敏感信息泄漏漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="ownCloud"'},"attack":"owncloud",'poc': Cve_2023_49103},
    {"name": "Ruby", "description": "[b bright_red]CVE-2018-3760[/b bright_red]Ruby On Rails 任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Ruby On Rails",'poc': Cve_2018_3760},
    {"name": "Ruby", "description": "[b bright_red]CVE-2019-5418[/b bright_red]Ruby On Rails 任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Ruby On Rails",'poc': Cve_2019_5418},
    {"name": "HuaWei", "description": "HUAWEI-Home-Gateway-HG659[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"huawei",'poc': HUAWEI_Home_GatewayReadFileScan},
    {"name": "HuaWei", "description": "HUAWEI-Auth-Http服务[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'server="Huawei Auth-Http Server 1.0"'},"attack":"huawei",'poc': HuaWeiAuth_Http},
    {"name": "GeoServer", "description": "GeoServer[b bright_red]CVE-2023-25157[/b bright_red]SQL注入漏洞", "params": {"url": url,"proxy":proxy},'poc': Cve_2023_25157},
    {"name": "JieLink", "description": "JieLink[b bright_red]未授权[/b bright_red]访问漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"jielink",'poc': JieLinkWsqScan},
    {"name": "Arris", "description": "Arris_VAP2500[b bright_red]RCE[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="./images/lg_05_1.gif"'},"attack":"./images/lg_05_1.gif",'poc': Arris_VAP2500Rce},
    {"name": "74CMS", "description": "KnightCMS[b bright_red]CNVD-2021-45280[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy},'poc': Cnvd_2021_45280},
    {"name": "74CMS", "description": "KnightCMS[b bright_red]CVE-2020-22211[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"74cms",'poc': Cve_2020_22211},
    {"name": "74CMS", "description": "KnightCMS[b bright_red]CVE-2020-22209[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"74cms",'poc': Cve_2020_22209},
    {"name": "74CMS", "description": "KnightCMS[b bright_red]CVE-2022-29720[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"74cms",'poc': Cve_2022_29720},
    {"name": "74CMS", "description": "KnightCMS[b bright_red]CVE-2022-33095[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"74cms",'poc': Cve_2022_33095},
    {"name": "74CMS", "description": "KnightCMS[b bright_red]Sql[/b bright_red]漏洞POC-1", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"74cms",'poc': KnightCmsSql},
    {"name": "74CMS", "description": "KnightCMS[b bright_red]Sql[/b bright_red]漏洞POC-2", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"74cms",'poc': KnightCmsSql2},
    {"name": "74CMS", "description": "KnightCMS[b bright_red]Sql[/b bright_red]漏洞POC-3", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"74cms",'poc': KnightCmsSql3},
    {"name": "Bladex", "description": "Bladex[b bright_red]Sql[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="https://bladex.vip/"'},"attack":"https://bladex.vip/",'poc': Blade_SQLSACN},
    {"name": "Atlassian", "description": "Atlassian Confluence[b bright_red]CVE-2015-8399[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="ATLASSIAN-Confluence"'},"attack":"Confluenc",'poc': Cve_2015_8399},
    {"name": "Atlassian", "description": "Atlassian Confluence[b bright_red]CVE-2021-26084[/b bright_red]远程代码执⾏漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy},'poc': Cve_2021_26084},
    {"name": "Atlassian", "description": "Atlassian Confluence[b bright_red]CVE-2021-26084[/b bright_red]远程代码执⾏漏洞POC-2", "params": {"url": url,"ssl": ssl,"header":ua,"cmd":cmd,"proxy":proxy,"batch_work":False,"fofa":'app="ATLASSIAN-Confluence"'},"attack":"Confluenc",'poc': Cve_2021_26084_2},
    {"name": "Atlassian", "description": "Atlassian Confluence[b bright_red]CVE-2021-26085[/b bright_red]远程代码执⾏漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="ATLASSIAN-Confluence"'},"attack":"Confluenc",'poc': Cve_2021_26085},
    {"name": "Atlassian", "description": "Atlassian Confluence[b bright_red]CVE-2021-26134[/b bright_red]OGNL注⼊命令执⾏漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="ATLASSIAN-Confluence"'},"attack":"Confluenc",'poc': Cve_2022_26134},
    {"name": "Atlassian", "description": "Atlassian Confluence[b bright_red]CVE-2023-22527[/b bright_red]远程代码执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"cmd":cmd,"batch_work":False,"fofa":'app="ATLASSIAN-Confluence"'},"attack":"Confluenc",'poc': Cve_2023_22527},

    {"name": "ERP", "description": "企望制造ERP[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'title="企望制造ERP系统"'},"attack":"ERP系统",'poc': QIWANGZHIZAORce},
    {"name": "ERP", "description": "智邦国际ERP GetPersonalSealData.ashx接口存在[b bright_red]SQL[/b bright_red]注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'icon_hash="-682445886"'},"attack":"ERP系统",'poc': ZhiBangGuoJi_Sql_Scan},
    {"name": "Craft", "description": "Craft CMS[b bright_red]CVE-2023-41892[/b bright_red]远程命令执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Craft CMS",'poc': Cve_2023_41892},
    {"name": "Jorani", "description": "Jorani休假管理系统[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy},'poc': CVE_Jorani_RCE_Scan},
    {"name": "Juniper", "description": "Juniper J-Web[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="J-Web"'},"attack":"J-Web",'poc': Junper_J_WebRce},
    {"name": "Juniper", "description": "Juniper[b bright_red]CVE-2023-36844[/b bright_red]远程命令执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="J-Web"'},"attack":"J-Web",'poc': Cve_2023_36844},
    {"name": "Nuuo", "description": "NUUO 摄像头[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'title="Network Video Recorder Login"'},"attack":"Network Video Recorder Login",'poc': NUUORceScan},
    {"name": "Caimao", "description": "厦门才茂通信网关[b bright_red]formping[/b bright_red]远程命令执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="CAIMORE-Gateway"'},'poc': Caimao_formping_rce_Scan},
    {"name": "Mini", "description": "Mini_Httpd[b bright_red]CVE-2018-18778[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},'poc': Cve_2018_18778},
    {"name": "InfluxDB", "description": "Influxdb[b bright_red]未授权访问/SQL[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"InfluxDB",'poc': InfluxDB_Wsq_SqlScan},
    {"name": "YApi", "description": "YApi[b bright_red]NoSQL注入[/b bright_red]导致远程命令执行漏洞", "params": {"url": url},'poc': YApi_NoSQL_Scan},
    {"name": "XXL-JOB", "description": "XXL-JOB executor[b bright_red]未授权访问到Rce利用[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"XXL-JOB",'poc': XXL_JOB_Wsq_Rce_Scan},
    {"name": "Webmin", "description": "Webmin[b bright_red]CVE-2019-15107[/b bright_red]远程命令执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Webmin",'poc': Cve_2019_15107},
    {"name": "TikiWikiCMS", "description": "Tiki Wiki CMS[b bright_red]CVE-2020-15906[/b bright_red]Groupware 认证绕过漏洞", "params": {"url": url,"cmd":cmd},'poc': Cve_2020_15906},
    {"name": "Supervisord", "description": "Supervisord[b bright_red]CVE-2017-11610[/b bright_red]远程命令执行漏洞", "params": {"url": url,"cmd":cmd,"batch_work":False},"attack":"Supervisord",'poc': Cve_2017_11610},
    {"name": "RocketChat", "description": "Rocket Chat MongoDB[b bright_red]CVE-2021-22911[/b bright_red]注入漏洞", "params": {"url": url,"ssl": ssl,"useremail":"admin@admin.com","proxy":proxy},'poc': Cve_2021_22911},
    {"name": "Metabase", "description": "Metabase未授权JDBC[b bright_red]CVE-2023-38646[/b bright_red]远程代码执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Metabase",'poc': Cve_2023_38646},
    {"name": "Metabase", "description": "Metabase[b bright_red]CVE-2021-41277[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Metabase",'poc': Cve_2021_41277},
    {"name": "Magento", "description": "Magento 2.2[b bright_red]SQL[/b bright_red]注入漏洞获取管理员Session", "params": {"url": url},'poc': Magento2_2_SQL},
    {"name": "Libssh", "description": "Libssh服务端[b bright_red]CVE-2018-10933[/b bright_red]权限认证绕过漏洞", "params": {"ip": ip,"port":port,"cmd":cmd},'poc': Cve_2018_10933},
    {"name": "Jetty", "description": "Jetty通用Servlets组件ConcatServlet[b bright_red]CVE-2021-28169/CVE-2021-28164/CVE-2021-34429[/b bright_red]信息泄露漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout": timeout,"batch_work":False},"attack":"Jetty",'poc': Cve_2021_28164},
    {"name": "Hadoop", "description": "Hadoop YARN ResourceManager[b bright_red]未授权[/b bright_red]访问漏洞", "params": {"url": url,"lhost":lhost,"lport":lport,"ssl": ssl,"header":ua,"proxy":proxy},'poc': Hadoop_Wsq_Scan},
    {"name": "GlassFish", "description": "GlassFish[b bright_red]任意文件[/b bright_red]读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"GlassFish",'poc': GlassFish_File_Read_Scan},
    {"name": "GitLab", "description": "GitLab[b bright_red]CVE-2021-22205[/b bright_red]远程命令执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"GitLab",'poc': Cve_2021_22205},
    {"name": "Drupal", "description": "Drupal Drupalgeddon2[b bright_red]CVE-2018-7600[/b bright_red]远程代码执行漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Drupal",'poc': Cve_2018_7600},
    {"name": "Drupal", "description": "Drupal < 7.32 “Drupalgeddon”[b bright_red]CVE-2014-3704[/b bright_red]SQL注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Drupal",'poc': Cve_2014_3704},
    {"name": "Drupal", "description": "Drupal REST[b bright_red]CVE-2019-6340[/b bright_red]RCE漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Drupal",'poc': Cve_2019_6340},
    {"name": "WangGuan", "description": "多家网关-安全设备存在[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="/webui/images/default/default/alert_close.jpg"'},"attack":"/webui/images/default/default/alert_close.jpg",'poc': WangGuan_Rce_Scan},
    {"name": "WangGuan", "description": "BYTEVALUE 智能流控路由器存在[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'BYTEVALUE 百为流控路由器'},"attack":"BYTEVALUE",'poc': BYTEVALUE_Rce_Scan},
    {"name": "WangGuan", "description": "网康科技NS-ASG应用安全网关[b bright_red]CVE-2024-2022[/b bright_red]SQL注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="网康科技-NS-ASG安全网关"'},"attack":"NS-ASG",'poc': Cve_2024_2022},
    {"name": "CanDao", "description": "禅道项目管理系统存在[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'title="用户登录 - 禅道"'},"attack":"禅道",'poc': CanDao_Rce_Scan},
    {"name": "ShengXinFu", "description": "深信服应用交付 AD 存在[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'fid="iaytNA57019/kADk8Nev7g=="'},"attack":"/rep/login",'poc': ShengXinFu_Rce_Scan},
    {"name": "RuiJie", "description": "锐捷 EG易网关 login.php[b bright_red]用户密码泄漏/远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"ruijie.com",'poc': RuiJie_E_Rce_Scan},
    {"name": "RuiJie", "description": "锐捷NBR路由器[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"ruijie.com",'poc': RuiJie_NBR_Rce_Scan},
    {"name": "XinKaiPu", "description": "新开普掌上校园服务管理平台service.action[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"service.action",'poc': XinKaiPu_Rce_Scan},
    {"name": "Telesquare", "description": "Telesquare TLR-2005Ksh 路由器 admin.cgi[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="TELESQUARE-TLR-2005KSH"'},"attack":"TLR-2005KSH",'poc': Telesquare_Rce_Scan},
    {"name": "Tosei", "description": "日本tosei自助洗衣机[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="tosei_login_check.php"'},"attack":"tosei_login_check.php",'poc': Tosei_Rce_Scan},
    {"name": "Chamilo", "description": "Chamilo[b bright_red]CVE-2023-34960[/b bright_red]Rce漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"cmd":cmd,"batch_work":False,"fofa":'app="Chamilo" || body="chamilo.org"'},"attack":"chamilo.org",'poc': Cve_2023_34960},
    {"name": "SPIP", "description": "SPIP-Cms <4.2.1_[b bright_red]CVE-2023-27372[/b bright_red]_序列化RCE漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="SPIP"'},"attack":"spip.php?",'poc': Cve_2023_27372},
    {"name": "ShopXO", "description": "ShopXO download[b bright_red]CNVD-2021-15822[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"shopxo",'poc': Cnvd_2021_15822},
    {"name": "CodeIgniter", "description": "CodeIgniter[b bright_red]任意代码执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"CodeIgniter",'poc': CodeIgniter_Rce_Scan},
    {"name": "Coremail", "description": "Coremail 邮箱系统[b bright_red]路径穿越[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Coremail",'poc': Coremail_Dir_ByPass_Scan},
    {"name": "Jellyfin", "description": "Jellyfin[b bright_red]CVE-2021-21402[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Jellyfin",'poc': Cve_2021_21402},
    {"name": "PyLoad", "description": "pyLoad[b bright_red]远程代码执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'"pyload_session"'},"attack":"pyLoad",'poc': PyLoad_Rce_Scan},
    {"name": "PyLoad", "description": "Pyload Flask[b bright_red]CVE-2024-21644[/b bright_red]配置信息泄露漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'"pyload_session"'},"attack":"pyLoad",'poc': Cve_2024_21644},
    {"name": "ZOHO", "description": "ZOHO ManageEngine ADSelfService Plus[b bright_red]CVE-2023-35854[/b bright_red]文件上传漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'server=="Adselfservice Plus"'},'poc': Cve_2023_35854},
    {"name": "NocoDB", "description": "NocoDB[b bright_red]CVE-2023-35843[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'icon_hash="-2017596142"'},"attack":"NocoDB",'poc': Cve_2023_35843},
    {"name": "VMware", "description": "VMware Aria[b bright_red]CVE-2023-34039[/b bright_red]SSH身份验证漏洞", "params": {"ip":ip,"port":"22"},'poc': Cve_2023_34039},
    {"name": "IceWarp", "description": "IceWarp Mail Server爱思华宝邮件服务器[b bright_red]CVE-2023-39699[/b bright_red]本地文件包含漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'title="IceWarp Web"'},"attack":"IceWarp Web",'poc': Cve_2023_39699},
    {"name": "Wavlink", "description": "Wavlink路由器[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'icon_hash="-1350437236"'},"attack":"wavlink",'poc': Wavlink_Rce_Scan},
    {"name": "FreeRDP", "description": "FreeRDP[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="css/vkb.css" || body="Advanced session parameters"'},"attack":"Advanced session parameters",'poc': FreeRDP_File_Read_Scan},
    {"name": "Yearning", "description": "Yearning front接口[b bright_red]CVE-2022-27043[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="Yearning" || title="Yearning"'},"attack":"Yearning",'poc': Cve_2022_27043},
    {"name": "Django", "description": "Django历史[b bright_red]SQL[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"Django",'poc': DjangoSqlScan},
    {"name": "Aliyun", "description": "Aliyun的[b bright_red]Key[/b bright_red]泄漏漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False},"attack":"accessKeyId",'poc': AKeySearchVuls},
    {"name": "ClickHouse", "description": "ClickHouse API数据库接口[b bright_red]未授权访问[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'"ClickHouse" && body="ok"'},"attack":"Ok.",'poc': ClickHouse_Sql_Scan},
    {"name": "EduSoho", "description": "EduSoho教培系统[b bright_red]任意文件读取[/b bright_red]漏洞(默认读取数据库信息)", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'title="Powered By EduSoho"'},"attack":"EduSoho",'poc': EduSoho_File_Read_Scan},
    {"name": "Aria", "description": "Aria2 WebUI控制台[b bright_red]CVE-2023-39141[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="Aria2-WebUI"'},"attack":"Aria2",'poc': Cve_2023_39141},
    {"name": "GoAnywhere", "description": "GoAnywhere MFT[b bright_red]CVE-2024-0204[/b bright_red]身份认证绕过漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'GoAnywhere-MFT"',"username":"adminaincn","password":"adminissuper"},'poc': Cve_2024_0204},
    {"name": "PfSense", "description": "PfSense pfBlockerNG[b bright_red]CVE-2022-31814[/b bright_red]未授权RCE漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"shodan":'http.title:"pfSense - Login" "Server: nginx" "Set-Cookie: PHPSESSID="'},"attack":"pfSense",'poc': Cve_2022_31814},
    {"name": "Mymps", "description": "Mymps cms系统[b bright_red]SQL[/b bright_red]注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'Mymps'},"attack":"MyMPS",'poc': Mymps_Sql_Scan},
    {"name": "BSPHP", "description": "BSPHP index.php[b bright_red]未授权[/b bright_red]访问信息漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'BSPHP'},"attack":"bsphp.com",'poc': BSPHP_Wsq_Scan},
    {"name": "Metinfo", "description": "Metinfo[b bright_red]任意文件[/b bright_red]读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="MetInfo"'},"attack":"Metinfo",'poc': Metinfo_File_Read_Scan},
    {"name": "Exrick", "description": "Exrick XMall开源商城 [b bright_red]SQL[/b bright_red]注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="XMall-后台管理系统"'},"attack":"xmadmin.exirck.cn",'poc': Cve_2024_24112},
    {"name": "Jeeplus", "description": "Jeeplus-resetPassword [b bright_red]SQL[/b bright_red]注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="api/change-theme" || body="static/common/css/app-"||app="Jeeplus"'},"attack":"api/change-theme",'poc': Jeeplus_Reset_Password_Scan},
    {"name": "Litemall", "description": "Litemall[b bright_red]存在多个默认口令[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'icon_hash="1367958180" || title="litemall"'},"attack":"litemall",'poc': Litemall_RuoKouLin_Scan},
    {"name": "Cellinx", "description": "Cellinx NVT Web Server[b bright_red]CVE-2024-24215[/b bright_red]信息泄露漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="local/NVT-string.js"'},"attack":"local/NVT-string.js",'poc': Cve_2024_24215},
    {"name": "LogBase", "description": "思福迪-LOGBASE运维安全管理系统test_qrcode_b[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="思福迪-LOGBASE"'},"attack":"Logbase",'poc': LogBase_Rce_Scan},
    {"name": "BT", "description": "BT宝塔 WAF[b bright_red]SQL[/b bright_red]注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'title="宝塔"'},'poc': BTWaf_Sql_Scan},
    {"name": "SolarView", "description": "Contec SolarView Compact[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'body="SolarView Compact" && title="Top"'},"attack":"SolarView Compact",'poc': SolarView_File_Read_Scan},
    {"name": "Copyparty", "description": "Copyparty[b bright_red]CVE-2023-37474[/b bright_red]路径遍历漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'"Copyparty"'},"attack":"Copyparty",'poc': Cve_2023_37474},
    {"name": "YouDian", "description": "友点cms接口存在[b bright_red]SQL[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="友点建站-CMS"'},"attack":"youdiancms.com",'poc': YouDian_Sql_Scan},
    {"name": "Acmailer", "description": "Acmailer邮件系统init_ctl.cgi[b bright_red]远程命令执行[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'product="acmailer-邮件系统"'},"attack":"ACMAILER",'poc': Acmailer_Rce_Scan},
    {"name": "Redmine", "description": "Redmine[b bright_red]未授权[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'product="Redmine"'},"attack":"Redmine",'poc': Redmine_Wsq_Scan},
    {"name": "Redmine", "description": "Redmine[b bright_red]任意文化读取[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'product="Redmine"'},"attack":"Redmine",'poc': Redmine_File_Read_Scan},
    {"name": "WyreStorm", "description": "WyreStorm Apollo VX20 < 1.3.58[b bright_red]CVE-2024-25735[/b bright_red]获取凭证等信息漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'icon_hash="-893957814"'},"attack":"WyreStorm",'poc': Cve_2024_25735},
    {"name": "Aiohttp", "description": "Aiohttp[b bright_red]CVE-2024-23334[/b bright_red]任意文件读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="AIOHTTP" && server!="aiohttp/3.9.3" && server!="aiohttp/3.9.2"'},'poc': Cve_2024_23334},
    {"name": "KingSuperSCADA", "description": "KingSuperSCADA[b bright_red]CNVD-2024-08404[/b bright_red]信息泄露漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'"KingSuperSCADA"'},"attack":"KingSuperSCADA",'poc': Cnvd_2024_08404},
    {"name": "Byzoro", "description": "(百卓)Byzoro-Smart[b bright_red]CVE-2024-0939[/b bright_red]任意文件上传漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'product="byzoro-Smart"'},"attack":"Smart",'poc': Cve_2024_0939},
    {"name": "Likeshop", "description": "Likeshop[b bright_red]CVE-2024-0352[/b bright_red]任意文件上传漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'icon_hash="874152924"'},"attack":"shop",'poc': Cve_2024_0352},
    {"name": "ThinkAdmin", "description": "ThinkAdmin[b bright_red]目录信息[/b bright_red]泄漏漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="ThinkAdmin"'},"attack":"Think",'poc': ThinkAdmin_Dir_Info_Scan},
    {"name": "ThinkAdmin", "description": "ThinkAdmin[b bright_red]任意文件[/b bright_red]读取漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"batch_work":False,"fofa":'app="ThinkAdmin"'},"attack":"Think",'poc': ThinkAdmin_File_Read_Scan},
    {"name": "vBulletin", "description": "vBulletin 5.x[b bright_red]CVE-2019-16759[/b bright_red]未授权RCE漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'"vBulletin"'},"attack":"vBulletin",'poc': Cve_2019_16759},
    {"name": "Harbor", "description": "Harbor[b bright_red]CVE-2019-16097[/b bright_red]任意管理员注册漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'"Harbor"'},"attack":"Harbor",'poc': Cve_2019_16097},
    {"name": "TMall", "description": "Mini-Tmall<=20231017版本[b bright_red]CVE-2024-2074[/b bright_red]SQL注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'body="www.tmall.com"'},"attack":"tmall",'poc': Cve_2024_2074},
    {"name": "AspCMS", "description": "AspCMS CommentList.asp[b bright_red]SQL[/b bright_red]注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'app="ASPCMS"'},"attack":"asp",'poc': AspCMS_Sql_Scan},
    {"name": "AspCMS", "description": "AspCMS ContentFun.asp[b bright_red]SQL[/b bright_red]注入漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'app="ASPCMS"'},"attack":"asp",'poc': AspCMS_Sql_Scan2},
    {"name": "AspCMS", "description": "AspCMS[b bright_red]后台地址泄露[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'app="ASPCMS"'},"attack":"asp",'poc': AspCMS_Admin_Path_Scan},
    {"name": "Kindeditor", "description": "KindEditor[b bright_red]文件上传[/b bright_red]点搜索", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'app="kindeditor"'},'poc': Kindeditor_Upload_Dir_Scan},
    {"name": "Fckeditor", "description": "Fckeditor[b bright_red]文件上传[/b bright_red]点搜索", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'app="Fckeditor"'},'poc': Fckeditor_Upload_Dir_Scan},
    {"name": "JetBrains", "description": "JetBrains TeamCity < 2023.11.4版本[b bright_red]CVE-2024-27198[/b bright_red]身份验证绕过漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"username": "adminisvuln","password":"aDmiNVnLs9","batch_work":False,"fofa":'body="Log in to TeamCity"'},"attack":"TeamCity",'poc': Cve_2024_27198},
    {"name": "Mkdocs", "description": "Mkdocs[b bright_red]任意文件读取[/b bright_red]漏洞", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'"mkdocs"'},"attack":"mkdocs",'poc': Mkdocs_File_Read_Scan},
    {"name": "Ueditor", "description": "Ueditor[b bright_red]文件上传[/b bright_red]点搜索", "params": {"url": url,"ssl": ssl,"header":ua,"proxy":proxy,"timeout":timeout,"batch_work":False,"fofa":'app="Baidu-UEditor"'},'poc': Ueditor_Upload_Dir_Scan},

]
