#!/user/bin/env python3
# -*- coding: utf-8 -*-
import yaml
import os
import re
import requests
import urllib3
from pub.com.outprint import OutPrintInfo,YamlPrintSuc
urllib3.disable_warnings()
yaml_pocs = []
class YamlLoadFile():
    def load_yaml_files(self,directory):
        """

        :param directory: 默认开始遍历搜索yaml文件的目录
        :return:
        """
        yaml_data = []
        nums = 0
        # 遍历目录中的所有文件和子目录
        for root, dirs, files in os.walk(directory):
            for file in files:
                # 检查文件是否是YAML文件
                if file.endswith(".yaml") or file.endswith(".yml"):
                    # 构建完整的文件路径
                    file_path = os.path.join(root, file)
                    # 读取YAML文件
                    with open(file_path, "r") as yaml_file:
                        # 使用PyYAML库加载YAML数据
                        try:
                            data = yaml.load(yaml_file, Loader=yaml.FullLoader)
                            # print(file_path)
                            yaml_data.append((data,file_path))
                        except Exception:
                            nums += 1
        return yaml_data,nums

    def yaml_data(self,yaml_pocs_dir):
        """
        :param yaml_pocs_dir:传入的yaml文件地址
        :return:
        """
        ids = []
        pocs_dir = yaml_pocs_dir
        # 要加载的目录路径
        directory_path = pocs_dir
        # 加载目录下的所有YAML文件
        all_yaml_data,nums = self.load_yaml_files(directory_path)
        # 打印加载的数据
        for data, file in all_yaml_data:
            id = data.get("id", "Null")
            tag = data["info"].get("tags", "Null")
            name = data["info"].get("name", "Null")

            ids.append((id, name, tag, file))
        return ids,nums

class YamlPocScan:
    def load_yaml(self,file_path):
        """
        :param file_path: 加载的yaml文件
        :return:
        """
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)

    def __poc_params(self,data,placeholders):
        """

        :param data:
        :param placeholders:
        :return:
        """
        paths = []
        if data.get("path",None):
            for k in data['path']:
                if "{{" in k:
                    for placeholder, value in placeholders.items():
                        pattern = r"{{\s*" + re.escape(placeholder) + r"\s*}}"
                        k = re.sub(pattern, value, k)
                    paths.append(k)
            return data['method'], paths
        elif data.get("raw",None):
            OutPrintInfo("YAML","RAW格式暂时不支持")
            return data['raw'], paths

    def __to_poc_requests(self,poc,data, placeholders):
        """

        :param poc:
        :param data: yaml http/response遍历后的数据
        :param placeholders: 传入的参数
        :return:
        """
        responses = []
        redirects = poc.get("redirects", False)
        # max_redirects = poc.get("max_redirects", True)
        method,paths = self.__poc_params(data,placeholders)
        for url in paths:
            if method == "GET":
                responses.append(requests.get(url,verify=False,allow_redirects=redirects))
            # elif method == "POST":
            #     return requests.post(url, headers=headers, data=body, verify=False)
            # elif method == "PUT":
            #     return requests.put(url, headers=headers, data=body, verify=False)
            # elif method == "DELETE":
            #     return requests.delete(url, headers=headers, data=body, verify=False)
            # elif method == "HEAD":
            #     return requests.head(url, headers=headers, data=body, verify=False)
            # elif method == "OPTIONS":
            #     return requests.options(url, headers=headers, data=body, verify=False)
            # elif method == "PATCH":
            #     return requests.patch(url, headers=headers, data=body, verify=False)
            # else:
            #     raise ValueError(f"Unsupported HTTP method: {method}")

        return responses
    def __vuls_check(self,poc,response):
        """

        :param poc:
        :param response:
        :return:
        """
        stop_at_first_match = None
        if poc.get("matchers-condition") is not None:
            stop_at_first_match = poc.get("stop-at-first-match",False)
        return self.__vuls_matchers(poc,poc.get("matchers-condition"),response,stop_at_first_match)
    def __vuls_matchers(self,poc,module,response,stop_at_first_match):
        """
        :param poc: 读取的poc yaml文件
        :param module:  yaml文件的请求格式，目前“http”，“requests”
        :param response: 请求目标返回的response
        :stop_at_first_match: 判断是否第一次匹配推出
        :return:
        """

        if poc.get("matchers") is not None:
            type_list = {}
            for matcher in poc.get("matchers"):
                type_list[matcher['type']] = False
            for type in poc.get("matchers"):
                if type["type"] == "regex":
                    regexs = type["regex"]
                    for regex in regexs:
                        type_list["regex"] = bool(re.search(regex, response.text))
                        if stop_at_first_match and type_list["regex"]:
                            return True
                if type["type"] == "status":
                    requests_status = type["status"]
                    for status in requests_status:
                        type_list["status"] = bool(status == response.status_code)
                        if stop_at_first_match and type_list["status"]:
                            return True
                if type["type"] == "word":
                    words = type["words"]
                    part_type = type.get("part",None)
                    condition_type = type.get("condition",None)
                    if condition_type == "and" if condition_type else False:
                        if part_type == "header" if part_type else False:
                            for word in words:
                                if word in str(response.headers):
                                    type_list["words"] = True
                                    if stop_at_first_match:
                                        return True
                        for word in words:
                            type_list["words"] = bool(word in response.text)
                            if not type_list["words"]:
                                return False
                            if stop_at_first_match and type_list["words"]:
                                return True

                    elif condition_type == "or" if condition_type else False:
                        if part_type == "header" if part_type else False:
                            for word in words:
                                if word in str(response.headers):
                                    type_list["words"] = True
                                    if stop_at_first_match:
                                        return True
                        for word in words:
                            type_list["words"] = bool(word in response.text)
                            if type_list["words"]:
                                return True
                            if stop_at_first_match and type_list["words"]:
                                return True

            if module == "and":
                if all(value is True for value in type_list.values()):
                    return True
            elif module == "or":
                if any(value is True for value in type_list.values()):
                    return True
    def __load_yaml_print_info(self,poc,url):
        """
        :param poc:
        :param url: response返回的url
        :return:
        """
        params = {"id":None,"severity":None,"url":url}
        if poc.get("info") is not None:
            params["severity"] = poc["info"].get("severity") if poc["info"].get("severity") else "Not found severity"
            params["id"] = poc.get("id")
        YamlPrintSuc(params)
    def load_poc(self,poc, placeholders):
        """

        :param poc: poc 对应的yaml文件
        :param placeholders: yaml文件传入的参数
        :return:
        """
        responses = None
        vuln_flag = False
        __work_module = None
        http_module = poc.get("http",None)
        if http_module is not None:
            __work_module = "http"
        else:
            __work_module = "requests"
        requests_module = poc.get(__work_module,[])

        if not requests_module:
            return

        for http_req_data in requests_module:
            responses = self.__to_poc_requests(poc,http_req_data,placeholders)
            if responses:
                for response in responses:
                    vuln_flag = self.__vuls_check(http_req_data,response)
            else:
                OutPrintInfo("YAML", "目标请求失败")
                return

        if vuln_flag:
            self.__load_yaml_print_info(poc,responses[-1].url)
        else:
            OutPrintInfo("YAML", "目标不存在该漏洞")
        OutPrintInfo("YAML", "脚本调用结束")

    def __url_check(self,placeholders):
        for k in placeholders:
            if k == "BaseURL":
                placeholders[k] = placeholders[k].strip("/ ")
        return placeholders
    def main(self,filename,placeholders):
        """
        :param filename: yaml文件名称
        :param placeholders: yaml调用时传入的参数
        :return:
        """
        placeholders = self.__url_check(placeholders)
        self.__baseurl = next((placeholders[k] for k in placeholders if k.lower() in ("baseurl", "hostname")), None)
        poc = self.load_yaml(filename)
        OutPrintInfo("YAML","YAML-POC程序部分框架处于开发状态,部分YAML-POC无法正常使用:(")
        # Validate POC
        self.load_poc(poc, placeholders)

