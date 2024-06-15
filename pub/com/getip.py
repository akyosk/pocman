#!/user/bin/env python3
# -*- coding: utf-8 -*-
import requests


def getIp():
    headers = {
        "Host": "myip.ipip.net",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate"
    }
    url = "https://myip.ipip.net"
    from pub.com.loadyamlset import ConfigLoader
    proxy = ConfigLoader().get_values()['proxy']
    if proxy:
        if "://" not in proxy:
            proxy = "http://"+proxy
        proxies = {"http":proxy,"https":proxy}
    else:
        proxies = None
    try:
        req = requests.get(url, headers=headers,proxies=proxies,timeout=10)
        if req.status_code == 200:
            return "  ".join(req.text.split(" ")[0:-2])
        else:
            return ""
    except Exception:
        return ""
