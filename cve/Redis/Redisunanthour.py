#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import socket
from pub.com.outprint import OutPrintInfo
class RedisunanthourScan:
    def url_exec(self,url):#将要探测的主机地址都存入一个待测数组内
        ans = []
        group = []
        li = url.split(".")
        if (url.find('-') == -1):
            group.append(url)
            ans = group
        else:
            ans = self.url_list(li)
        return ans

    def url_list(self,li):#如果带探测的ip地址是一个范围的话那么就放到这个函数中去执行
        ss = []
        i = 0
        j = 0
        ans = []
        for s in li:
            a = s.find('-')
            i = i + 1
            if a != -1:
                ss = s.rsplit("-")
                j = i
                break
        for s in range(int(ss[0]), int(ss[1]) + 1):
            li[j - 1] = str(s)
            aa = ".".join(li)
            ans.append(aa)
        return ans

    def redis_unauthorized(self,url, port):#实际进行漏洞验证的脚本
        result = []
        s = socket.socket()
        payload = "\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a"#这个pyload是什么后面细说
        socket.setdefaulttimeout(10)
        for ip in url:
            try:
                s.connect((ip, int(port)))
                s.sendall(payload.encode())
                recvdata = s.recv(1024).decode()
                OutPrintInfo("Redis", str(recvdata))
                if recvdata and 'redis_version' in recvdata:#用关键字进行检测漏洞
                    result.append(str(ip) + ':' + str(port) + '     ' + 'succeed')
            except:
                pass
                result.append(str(ip) + ':' + str(port) + '     ' + 'failed')
        s.close()
        return result

    def main(self,target):#对脚本的传参进行判断
        OutPrintInfo("Redis", "开始检测Redis未授权")
        url = target["ip"].strip('/ ')
        if '://' in url:
            OutPrintInfo("Redis", '不需要携带协议头,最好使用[b bright_red]IP[/b bright_red]')
            return
        port = target["port"]
        type = "Redis"
        self.launcher(url, type, port)

    def launcher(self,url,type,port):#脚本启动函数
        #未授权访问类型
        if type == "Redis":
            output = self.redis_unauthorized(self.url_exec(url),port)
            self.output_exec(output,type)

    def output_exec(self,output,type):#输出规范
        OutPrintInfo("Redis", type + "......")
        OutPrintInfo("Redis", "++++++++++++++++++++++++++++++++++++++++++++++++")
        OutPrintInfo("Redis", "|         ip         |    port   |     status  |")
        for li in output:
            OutPrintInfo("Redis", "+-----------------+-----------+--------------+")
            OutPrintInfo("Redis", f'|   [b bright_red]{li.replace(":", "   |    ")}[/b bright_red]  | ')
        OutPrintInfo("Redis", "+----------------+------------+---------------+")
        OutPrintInfo("Redis", "Shutting down....")
        OutPrintInfo("Redis", "Redis未授权检测结束")




