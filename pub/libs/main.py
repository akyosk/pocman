#!/user/bin/env python3
# -*- coding: utf-8 -*-
import random
from pub.libs.inputcheck import InputCheck
from pub.com.loadyamlset import ConfigLoader
from pub.com.banner import banner
from pub.com.outprint import PocPrint
from pub.libs import loadyaml
from set.pocset import modules
from rich.console import Console
from pub.com.getip import getIp
from time import sleep
class PocMain:
    def __init__(self):
        self.yaml_pocs = []
    # 加载数据信息
    def __options(self):
        console = Console()

        with console.status("[b blue] Pocman启动程序疯狂加载中......\n", spinner='dots', spinner_style='blue') as status:
            # ip = getIp()
            ip = getIp() or "未检测到开启系统代理"
            version = ConfigLoader().get_values()["version"]
            pocs,at_pocs = self.__get_pocs()
            yaml_pocs,nums = self.__load_yaml_pocs()
            sleep(1)
            status.stop()


        num = random.randint(0, len(banner()) - 1)
        from rich import print
        print(banner()[num])

        PocPrint(version,ip,pocs,at_pocs,len(yaml_pocs),nums)

    def __load_yaml_pocs(self):
        yaml_pocs_dir = ConfigLoader().get_values()["yaml-pocs-dir"]
        pocs,nums = loadyaml.YamlLoadFile().yaml_data(yaml_pocs_dir)
        loadyaml.yaml_pocs= pocs

        return pocs,nums
    def __get_pocs(self):
        b_list = [k for k in modules if "batch_work" in k["params"]]
        return len(modules),len(b_list)


    def main(self):
        self.__options()
        InputCheck().main()
