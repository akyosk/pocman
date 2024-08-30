import sys
from pub.com.outprint import YamlPocErr,ATShowP,OutPrintInfo,TreadsWorkP,OutPrintInfoErr,Opts,SearchPrint,SearchYamlPrint,SearchYamlDataPrint,SearchYamlResListPrint,SearchResListPrint,NoSearchRes
import re
from pub.com.loadyamlset import ConfigLoader
def get_set():
    return ConfigLoader().get_values()
config_yaml_values = get_set()
threads = config_yaml_values["threads"]
timeout = config_yaml_values["timeout"]
cookie = config_yaml_values["cookie"]
ssl = config_yaml_values["ssl"]
ua = config_yaml_values["ua"]
proxy = config_yaml_values["proxy"]
url = config_yaml_values["url"]
ceye_dns = config_yaml_values["ceye-dns"]
ceye_api = config_yaml_values["ceye-api"]
batch_work_file = config_yaml_values["batch-work-file"]

class InputCheck:
    def __init__(self):
        self.__work_flag = "SEARCH"
        self.__attack_work_canshu = {
            "url": url,
            "header": ua,
            "cookie": cookie,
            "threads": int(threads),
            "ssl": ssl,
            "proxy": proxy,
            "timeout": int(timeout),
            "max": 50000,
            "ceyeapi": ceye_api,
            "ceyedns": ceye_dns,
            "*Tips*": "max为网页爬取到最大值"
        }
    def __show_attack_params(self):
        ATShowP(self.__attack_work_canshu)

    def __listOpt(self, opts):
        try:
            key, value = opts.split(" ")
            if key in self.__attack_work_canshu:
                self.__attack_work_canshu[key] = value
        except Exception as e:
            OutPrintInfoErr(e)
    def __lazy_import(self,module_name):
        from importlib import import_module
        return lambda: import_module(module_name)
    def __batch_work(self):
        self.__work_flag = "BATCH"

    def __attack_work(self):
        self.__work_flag = "ATTACK"
        self.__show_attack_params()

    def __search_work(self):
        self.__work_flag = "SEARCH"

    def __other_work(self, opts):
        operations = {
            "batch": self.__batch_work,
            "exit": sys.exit,
            "attack": self.__attack_work,
            "search": self.__search_work,
        }
        operations.get(opts, lambda: OutPrintInfoErr(opts))()
    def __batch_run_work(self,reslist,parsesss):
        threads = None
        TreadsWorkP()
        batch_url_list = []
        work_urls = parsesss["dir"]
        OutPrintInfo("Batch", f"指定任务文件为[b bright_red]{work_urls} ")
        with open("./" + work_urls.strip("./"), "r") as f:
            for req_url in f:
                if req_url and req_url.strip() not in batch_url_list:
                    if "://" not in req_url.strip():
                        batch_url_list.append("http://" + req_url.strip())
                    else:
                        batch_url_list.append(req_url.strip())

        OutPrintInfo("BATCH", f"共识别任务[b magenta]{str(len(batch_url_list))}[/b magenta]个")
        canShu = reslist["params"]
        poc_req_list = []
        try:
            for p in batch_url_list:
                copy_sj = canShu.copy()
                copy_sj["url"] = p  # 传入字典
                # 批量模式判断条件
                copy_sj["batch_work"] = True
                poc_req_list.append(copy_sj)

        except Exception:
            OutPrintInfoErr("该POC可能暂时不支持批量检测 :(")
            return

        if poc_req_list:
            from rich.prompt import Prompt
            from rich.progress import Progress
            OutPrintInfo("Batch", "任务加载完成 [b bright_cyan];)")
            try:
                input_threads = Prompt.ask("[[b red]Batch[/b red]]\t[b yellow]输入运行线程数",choices=["10","50","100","200","exit"],default="输入默认选项之一")
                if input_threads == "exit":
                    return
                else:
                    threads = int(input_threads)
            except Exception:
                OutPrintInfoErr(f"{input_threads} :(")
                return
            try:
                if parsesss["proxy"]:
                    from pub.com.reqset import ReqSet
                    if not ReqSet(proxy=parsesss["proxy"]):
                        return
            except Exception as e:
                OutPrintInfoErr(f"{e} :(")
            from concurrent.futures import ThreadPoolExecutor, wait, as_completed
            class_name = ".".join(reslist["poc"].split(".")[0:-1])
            poc_module = self.__lazy_import(class_name)()
            poc_class = getattr(poc_module, reslist["poc"].split(".")[-1])
            poc_instance = poc_class()
            with Progress(transient=True) as progress:
                task = progress.add_task("[b green]批量任务执行中...", total=len(poc_req_list))
                with ThreadPoolExecutor(threads) as pool:
                    # futures = [pool.submit(poc.main,list(poc_req.values())) for poc_req in poc_req_list] 传入参数列表
                    futures = [pool.submit(poc_instance.main, poc_req) for poc_req in poc_req_list]  # 直接传入字典
                    for future in as_completed(futures):
                        future.result()
                        progress.update(task, advance=1)
                wait(futures)
        else:
            OutPrintInfoErr("未能在任务文件加载到任务 :(")
            OutPrintInfo("Batch", "请在[b bright_red]batch/url.txt[/b bright_red]进行核实")
    def __parses_input(self,searchList,yamlList):
        try:
            if int(self.num) < len(searchList):
                if self.__work_flag == "BATCH":
                    searchList[int(self.num)]["params"]["dir"] = batch_work_file
                SearchPrint(searchList[int(self.num)]["params"],self.__work_flag)
                return searchList[int(self.num)],None
            else:
                yaml_params = SearchOpts().yaml_main(yamlList[int(self.num)-len(searchList)][-1])
                SearchYamlPrint(yaml_params)
                return yamlList[int(self.num)-len(searchList)][-1],yaml_params
        except Exception as e:
            OutPrintInfoErr(e)
    def __params_x(self,parsesss):
        for key ,value in parsesss.items():
            if value in ("False", "false"):
                # if value == "False" or value == False or value == "false":
                parsesss[key] = False
            elif value in ("True", "true"):
                # elif value == "True" or value == True or value == "true":
                parsesss[key] = True
            elif value in ("None", "none", "null", "Null"):
                # elif value == "None" or value == None or value == "none":
                parsesss[key] = None
        return parsesss
    # 主函数
    def main(self):  # 程序第一步
        """
        :reslist search/yamlsearch 模式所含的值不同，yaml模式下为文件名
        :yamlflag
        :yaml_poc_params search yaml结果所需要的参数
        :return:
        """
        yamlflag,reslist,searchList, yamlList,yaml_poc_params = False, {},[],[],{}
        while True:
            opts = Opts(self.__work_flag)
            if opts.lower() in {"attack", "batch", "search", "exit"}:
                self.__other_work(opts)
                searchList,yamlList = [],[]
                continue

            opt = opts.split(" ")
            datas = " ".join(opt[1:]).strip()
            if self.__work_flag == "ATTACK":
                if opts == "option" or opts == "options":
                    self.__show_attack_params()
                elif opts == "run":
                    from attack.Attack import AT_RUN_WORK
                    AT_RUN_WORK().main(self.__attack_work_canshu)
                else:
                    self.__listOpt(opts)
                continue
            if "search" == opt[0]:
                searchList, yamlList = SearchOpts().optWork(datas,self.__work_flag)  # 对程序search进行搜索
                yamlflag = bool(yamlList)
            elif opts.lower() in {"options", "option"}:
                (SearchYamlDataPrint(yaml_poc_params) if yamlflag else SearchPrint(reslist.get("params", {}),self.__work_flag))
            elif "use" == opt[0].lower() and datas.isdigit():
                self.num = datas
                if int(self.num) < len(yamlList) + len(searchList):
                    reslist, yaml_poc_params = self.__parses_input(searchList, yamlList) # yaml情况下reslist是文件名，yaml_poc_params为参数
                    # print(yaml_params)
                    yamlflag = int(self.num) >= len(searchList)
                else:
                    OutPrintInfoErr(opts)
            elif opts.lower() == "run":
                if yamlflag:
                    self.__params_x(yaml_poc_params)
                    # 开发中
                    from pub.libs.loadyaml import YamlPocScan
                    try:
                        YamlPocScan().main(reslist,yaml_poc_params) # reslist ：filename ,yaml_poc_params ： poc参数
                    except Exception as e:
                        YamlPocErr(e)
                    continue
                parsesss = reslist["params"]

                self.__params_x(parsesss)
                if self.__work_flag == "BATCH":
                    self.__batch_run_work(reslist,parsesss)
                    continue

                class_name = ".".join(reslist["poc"].split(".")[0:-1])
                poc_module = self.__lazy_import(class_name)()
                try:
                    poc_class = getattr(poc_module, reslist["poc"].split(".")[-1]) # //////
                    poc_instance = poc_class()
                    poc_instance.main(parsesss)
                except Exception as e:
                    OutPrintInfoErr(e)
            else:
                if " " not in opts:
                    OutPrintInfoErr(opts)
                    continue
                # 对多命令进行组合例如ping baidu.com
                f = False
                key, value = opt[0], datas
                if yamlflag:
                    for k,v in yaml_poc_params.items():
                        if key.lower() == k.lower():
                            yaml_poc_params[k] = value
                            f = True
                            break
                else:
                    for k, v in reslist.get("params", {}).items():
                        if key.lower() == k.lower():
                            reslist["params"][k] = value
                            f = True
                            break
                NoSearchRes(opts) if not f else None
class SearchOpts:# 用于search检测
    def __init__(self):
        self.choose = None
        self.num = None
    def optWork(self, opt,flag):  # 程序第四步，开始遍历字典，搜索是否存在对应信息
        from set.pocset import modules
        yamlList,searchList = [],[] #//////////////////
        # 批量flag
        if flag == "BATCH":
            searchList = [k for k in modules if opt.lower() in k["name"].lower() or opt.lower() in k["description"].lower() if "batch_work" in k["params"]]
            yamlList = []
        else:
            from pub.libs import loadyaml
            yaml_pocs = loadyaml.yaml_pocs
            searchList = [k for k in modules if opt.lower() in k["name"].lower() or opt.lower() in k["description"].lower()]
            # yamlList = [k for k in yaml_pocs if k and any(part and opt.lower() in part.lower() for part in k)]
            yamlList = [k for k in yaml_pocs if k and any(isinstance(part, str) and opt.lower() in part.lower() for part in k)]

        if not searchList and not yamlList:
            NoSearchRes(opt)
            return [], []
        if searchList:
            SearchResListPrint(searchList)
        if yamlList: # /////////////
            SearchYamlResListPrint(searchList, yamlList)

        return searchList, yamlList

    def find_double_curly_braces(self,yaml_file):
        import yaml
        # 正则表达式匹配双花括号中的内容
        pattern = r'\{\{([^}]*)\}\}'
        with open(yaml_file, 'r') as file:
            file_content = file.read()

        matches = re.findall(pattern, file_content)

        yaml_data = yaml.safe_load(file_content)

        return matches, yaml_data
    # 读取YAML文件
    def yaml_main(self,yamlfile):
        matches_dict = {}
        matches,poc_data = self.find_double_curly_braces(yamlfile)
        if not matches:
            return {}
        for k in matches:
            if k.lower() == "baseurl" or "url" in k.lower():
                matches_dict[k] = "https://www.google.com"
            elif k.lower() == "hostname":
                matches_dict[k] = "127.0.0.1"
            else:
                matches_dict[k] = k
        if poc_data.get("variables",False):
            poc_data_params = poc_data.get("variables")
            poc_params_key = next(iter(poc_data_params))
            value = poc_data_params[poc_params_key]
            if poc_params_key in matches:
                matches_dict[poc_params_key] = value


        return matches_dict