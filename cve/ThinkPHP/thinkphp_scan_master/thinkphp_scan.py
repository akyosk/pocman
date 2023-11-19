# coding:utf-8

import datetime
from rich.console import Console
import cve.ThinkPHP.thinkphp_scan_master.core.code_rprint as rprint
from cve.ThinkPHP.thinkphp_scan_master.core.thinkphp_payloads import start_thinkphp
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

targets = './targets.txt'
date = str(datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))

class ThinkphpScanMaster:
  def get_time(self):
    return datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

  def main(self,target):

    print('''
    ░▀█▀░█░█░▀█▀░█▀█░█░█░█▀█░█░█░█▀█░░░░░█▀▀░█▀▀░█▀█░█▀█
    ░░█░░█▀█░░█░░█░█░█▀▄░█▀▀░█▀█░█▀▀░░░░░▀▀█░█░░░█▀█░█░█
    ░░▀░░▀░▀░▀▀▀░▀░▀░▀░▀░▀░░░▀░▀░▀░░░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀░▀
    ''')

    url = target[0].strip('/ ')
    rprint.info(self.get_time(), 'Thinkphp漏洞检测')
    start_thinkphp(url)
    rprint.info(self.get_time(), 'Thinkphp漏洞检测结束')


