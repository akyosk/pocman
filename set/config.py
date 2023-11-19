from fake_useragent import UserAgent
ua = UserAgent().random
domain = "xxx.com"
ip = "0.0.0.0"
url = "https://www.google.com"
port = "8080"
cmd = "whoami"
threads = 30
timeout = 5
cookie = None
ssl = False
rhost = "0.0.0.0"
lhost = "0.0.0.0"
rport = "8080"
lport = "9527"
proxy = None
# proxy = "198.18.0.3:1082"

file = "etc/passwd"

# censys-api 免费注册
censys_api = ""
# shodan-api
shodan_api = "" # 格式 polito=xxxxx
# virustotal-api 免费注册
virustotal_api = ""
# dnsdumpster-csrftoken 请求包里
dnsdump_csrftoken = "uxXaL6TLzz2H7LSTcufBjR60ahvqBHJiitZoXqZWNNCVfk6sxySdNUrjUctMEdZU"
# fofa
fofa_key = ""
fofa_email = ""
# YT
yt_key = ""
# viewdns 免费注册，每月250次
viewdns_key = ""
# securitytrails.com接口网站的密钥 每个50次，免费注册,可注册多个，当检测无使用次数时自动遍历替换
api_list = [
            "cJBbaAJFDzs-XUQwnO11IEz3dTprvPgv",
            "9Ki0DqWBRHON5IKCo9HvSkicuTkYA863",
        ]