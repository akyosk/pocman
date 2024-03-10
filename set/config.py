from fake_useragent import UserAgent
# 脚本版本
work_version = "0.0.02"
# 程序执行默认配置
ua = UserAgent().random
domain = "google.com"
ip = "0.0.0.0"
url = "https://www.google.com"
port = "8080"
# 默认执行命令
cmd = "whoami"
# 请求设置
threads = 30
timeout = 5
cookie = None
ssl = False
# 反弹设置
rhost = "0.0.0.0"
lhost = "0.0.0.0"
rport = "8080"
lport = "9527"
# 默认读取文件
file = "etc/passwd"
# 默认批量模式读取文件
batch_work_file = "batch/url.txt"
# 脚本默认代理
proxy = None
# proxy = "http://191.180.0.1:1082"

# ceye-dns
ceye_dns = ""
ceye_api = ""
# censys-api 免费注册
censys_API = ""
censys_Secret = ""
censys_api = "Basic NWUyMDM2YzItZmIyMS00NGMwLWI5N2MtZTBmNjQ0ZGZmODFiOmExRkxabUVlWHYzR1pocVpQNHVsMDdGaXNxM2ZqbFRR" # censys_cookie Basic NWUyMDM2YzItZmIyM...
# shodan-api
shodan_api = "" # 高级学术会员备用
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
# fullhunt-api 每月100 https://fullhunt.io/
fullhunt_api = ""
# zoomeye
zoomeye_key = ""
# quake https://quake.360.net/
quake_key = ""
# Binaryedge
binaryedge_key = ""
# whoisxmlapi.com 每月500条
whoisxmlapi_key = ""
# securitytrails.com接口网站的密钥 每个50次，免费注册,可注册多个，当检测无使用次数时自动遍历替换
api_list = [
            "aDBj4RaVWL1M04VqG4Q-BMTzmSGU3K8G",
        ]