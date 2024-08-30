import requests
import urllib3, re, time, random,tldextract,chardet,signal,os
from urllib.parse import urlparse
import xlsxwriter as xw
from bs4 import BeautifulSoup
from pub.com.reqset import ReqSet

urllib3.disable_warnings()


class JscannerMaster:
    def __init__(self):
        self.__ssl = None
        self.__level = None
        self.__time = None
        self.__headers = None
        self.__height = None
        self.__blackStatus = []
        self.__wait = None
        self.__url = None
        self.__proxy = None
# def parse_args():
#     """用户输入"""
#     parse = argparse.ArgumentParser(description="hi 你好")
#     parse.add_argument('-u', '--url',  type=str, help="输入带有http/https的网站URL")
#     parse.add_argument('-r', '--header', type=ast.literal_eval,
#                        default="{'user-Agent':'Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1'}",
#                        help="输入user-agent,格式为\"{\'cookie\':\'xxxx\',\'user-Agent\':\'xxxx\',\'xxxx\':\'xxxx\'}\"")
#     parse.add_argument('-l', '--level', type=int, default=0, help="输入最大递减数，默认为0表示全递减")
#     parse.add_argument('-H', '--height', type=int, default=0, help="查找深度")
#     parse.add_argument('-w', '--wait', type=int, default=3, help="网站请求超时等待时间")
#     # parse.add_argument('-a', '--appoint', type=str, help="读取指定文件")
#     parse.add_argument('-T', '--time', type=float, default=0, help="请求间隔延时")
#     parse.add_argument('-B', '--blackStatus', type=ast.literal_eval, default=(404, 502, 500),
#                        help="输入您不想要获得的状态码,格式：-s \"(xxx,xxx)\"")
#     parse.add_argument('-o', '--out', type=str, help="输出为Excel表格")
#     parse.add_argument('-p','--proxy',type=str,help="设置代理，格式：-p xxx.xxx.xxx.xxx:端口,如果代理需要认证，格式为：username:password@xxx.xxx.xxx.xxx:xxxx")
#     # parse.add_argument('-d','--redup',type=str,help="需要配合-o来进行输出，有标题，状态码，返回值长度三者可以选择，选中后会对其进行去重操作，默认会对URL进行去重，不可以多选。")
#     # parse.add_argument('-b','--batch',type=str,help="填入文件绝对路径，完成批量扫描，可自动去除空白行")
#     # parse.add_argument('-f','--findsomething',type=str,help="将findsomething插件当中的IncompletePath与Path放入文本文件，选项后面接路径,当然你也可以与-u一起使用")
#     return parse.parse_args()


    def read(self,filename: str) -> list:
        """文件读取"""
        with open(filename, 'r') as file:
            lines = [line.strip().split(" ")[0] for line in file if line.strip() and line.strip()[0] != "#"]
            lines = [line for line in lines if line] # 过滤空白元素
            return lines
    
    
    def url_request(self,url, header, wait_time=3):
        """对传入的URL发起请求，返回一个对象"""
        request_url_object = requests.get(url=url, headers=header, verify=self.__ssl, timeout=wait_time,proxies=self.__proxy)
        return request_url_object
    
    
    def analysis(self,source, url):
        """从网页源代码当中进行提取url，并且完成对URL的处理"""
        return_url_list = []
        # 解析传入的url，主要是用作最后与处理后的url的域名的对比，防止误伤
        extracted = tldextract.extract(url)
        # 拼接出用于判断的url main_domain
        main_domain = extracted.domain + '.' + extracted.suffix
        pattern_raw = r"""
                  (?:"|')                               # Start newline delimiter
                  (
                    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
                    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
                    [a-zA-Z]{2,}(?!png|css|jpeg|mp4|mp3|gif|ico)[^"']{0,})              # The domainextension and/or path, not ending with png/css/jpeg/mp4/mp3
                    |
                    ((?:/|\.\./|\./)                    # Start with /,../,./
                    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
                    [^"'><,;|()]{1,})                   # Rest of the characters can't be
                    |
                    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
                    [a-zA-Z0-9_\-/]{1,}                 # Resource name
                    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
                    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
                    |
                    ([a-zA-Z0-9_\-]{1,}                 # filename
                    \.(?:php|asp|aspx|jsp|json|
                         action|html|js|txt|xml)             # . + extension
                    (?:\?[^"|']{0,}|))                  # ? mark with parameters
                  )
                  (?:"|')                               # End newline delimiter
                """
        pattern = re.compile(pattern_raw, re.VERBOSE)
        links = pattern.findall(source)
        relist = [link[0] for link in links if not link[0].endswith(('.css', '.png', '.jpg', '.mp4'))]
    
        all_list = list(set(relist))
        for main_url in all_list:
            # 解析输入的url，主要是用来完整的URL的拼接
            handled_url = urlparse(url)
            # 解析http、https协议
            Protocol = handled_url.scheme
            # 解析出域名
            Domain = handled_url.netloc.strip()
            # 解析出路径
            Path = handled_url.path
            return_url = None
            if main_url.startswith('/'):
                # 处理以斜杠开头的相对路径
                if main_url.startswith('//'):
                    return_url = Protocol + ':' + main_url
                else:  # 此时也就是 / 开头的
                    return_url = Protocol + '://' + Domain + main_url
            elif main_url.startswith('./'):
                # 处理以./开头的相对路径
                return_url = Protocol + '://' + Domain + main_url[2:]
            elif main_url.startswith('../'):
                 # 处理以../开头的相对路径
                 return_url = Protocol + '://' + Domain + os.path.normpath(os.path.join(Path, main_url))
                # return_url = Protocol + '://' + Domain + Domain + main_url[2:]
            #     try:
            #         return_url = Protocol + '://' + Domain + os.path.normpath(os.path.join(Path, main_url))
            #     except Exception:
            #         pass
            elif main_url.startswith('http') or main_url.startswith('https'):
                # 处理以http或https开头的绝对路径
                return_url = main_url
            else:
                # 处理其他情况
                return_url = Protocol + '://' + Domain + '/' + main_url
    
            # 解析url获取子域名
            extracted1 = tldextract.extract(return_url)
            # 拼接出用于判断的 main_domain1
            main_domain1 = extracted1.domain + '.' + extracted1.suffix
    
            if main_domain == main_domain1:
                # 如果上述二者相同，则说明为正常资产，否则为无数
                return_url_list.append(return_url)
        return return_url_list


    def status(self,Object):
        """变更为对状态码的提取"""
        try:
            status_code = Object.status_code
        except:
            return "NULL"
        else:
            return status_code
    
    
    def return_length(self,Object):
        """返回值长度"""
        try:
            return_length = Object.text
        except:
            return "NULL"
        else:
            return len(return_length)


    def height_scan(self,get_url, header, wait_time, high):
        """深度查找"""
        return_murl_list = []
        for num in range(high):
            for i in get_url:
                object = self.url_request(i, header=header, wait_time=wait_time)
                if self.status(object) == 200:
                    urlResult = self.analysis(object.text, i)
                    return_murl_list.extend(urlResult)
            get_url = []
            get_url.extend(return_murl_list)
        return return_murl_list
    
    
    def decline(self,url, num):
        """负责逐级递减URL路径"""
        if url[:8] == "https://":
            url = url.replace("https://", "", 1)
            url_list = []
            if num > 1:
                for i in range(num):
                    url_list.append("https://" + url)
                    url = '/'.join(url.split('/')[:-1])
                url_list.append(url + '/')
                url_list.reverse()
            else:
                parts = url.split('/')
                for i in range(2, len(parts) + 1):
                    url_list.append("https://" + '/'.join(parts[:i]))
            return url_list
        else:
            url = url.replace("http://", "", 1)
            url_list = []
            if num > 1:
                for i in range(num):
                    url_list.append("http://" + url)
                    url = '/'.join(url.split('/')[:-1])
                url_list.append(url + '/')
                url_list.reverse()
            else:
                parts = url.split('/')
                for i in range(2, len(parts) + 1):
                    url_list.append("http://" + '/'.join(parts[:i]))
            return url_list


    def get_title(self,Object):
        # 使用 BeautifulSoup 解析 HTML
        html = Object.content
        # 处理编码问题
        encoding = chardet.detect(html)['encoding']
        html = html.decode(encoding)
        # 解析 HTML 内容并获取网站标题
        soup = BeautifulSoup(html, 'html.parser')
        # 获取网页标题
        try:
            title = soup.title.string
        # 返回网页标题
        except:
            return "NULL"
        else:
            return title
    
    
    def write_excel(self,dataList,name):
        # 生成文件名（当前时间戳 + 随机数）
        fileName = name + str(random.randint(1000, 9999))
        # 创建工作簿
        workbook = xw.Workbook(str(fileName) + ".xlsx")
        # 创建子表
        worksheet1 = workbook.add_worksheet("sheet1")
        # 激活表
        worksheet1.activate()
        # 设置表头
        sheet_header = ['URL', '状态码', '返回值长度', '标题']
        # 从A1单元格开始写入表头
        worksheet1.write_row('A1', sheet_header)
        # 设置第一列的宽度为 50
        worksheet1.set_column(0, 0, 50)
        # 遍历数据列表
        for i in range(len(dataList)):
            # 获取当前数据的 URL、状态码、内容长度和标题
            try:
                writeUrl, statusCode, contentLength, url_title = dataList[i]
            except ValueError:
                # 假如不足四个元素就直接忽略
                continue
            else:
                # 在表格中写入 URL、状态码、内容长度和标题
                worksheet1.write(i + 1, 0, writeUrl)
                worksheet1.write(i + 1, 1, statusCode)
                worksheet1.write(i + 1, 2, contentLength)
                worksheet1.write(i + 1, 3, url_title)
        # 关闭工作簿
        workbook.close()
    
        return fileName



    def url_calibrate(self,path, url):
        """配合findsommething来完成资产探测"""
        return_url_list = []
        # 解析传入的url，主要是用作最后与处理后的url的域名的对比，防止误伤
        extracted = tldextract.extract(url)
        # 拼接出用于判断的url main_domain
        main_domain = extracted.domain + '.' + extracted.suffix
    
        for main_url in self.read(path):
            # 解析输入的url，主要是用来完整的URL的拼接
            handled_url = urlparse(url)
            # 解析http、https协议
            Protocol = handled_url.scheme
            # 解析出域名
            Domain = handled_url.netloc.strip()
            # 解析出路径
            Path = handled_url.path
            return_url = None
            if main_url.startswith('/'):
                # 处理以斜杠开头的相对路径
                if main_url.startswith('//'):
                    return_url = Protocol + ':' + main_url
                else:  # 此时也就是 / 开头的
                    return_url = Protocol + '://' + Domain + main_url
            elif main_url.startswith('./'):
                # 处理以./开头的相对路径
                return_url = Protocol + '://' + Domain + main_url[1:]
            elif main_url.startswith('../'):
                # 处理以../开头的相对路径
                return_url = Protocol + '://' + Domain + os.path.normpath(os.path.join(Path, main_url))
                # return_url = Protocol + '://' + Domain + main_url[1:]
            #     try:
            #         return_url = Protocol + '://' + Domain + os.path.normpath(os.path.join(Path, main_url))
            #     except Exception:
            #         pass
            elif main_url.startswith('http') or main_url.startswith('https'):
                # 处理以http或https开头的绝对路径
                return_url = main_url
            else:
                # 处理其他情况
                return_url = Protocol + '://' + Domain + '/' + main_url
    
            # 解析url获取子域名
            extracted1 = tldextract.extract(return_url)
            # 拼接出用于判断的 main_domain1
            main_domain1 = extracted1.domain + '.' + extracted1.suffix
    
            if main_domain == main_domain1:
                # 如果上述二者相同，则说明为正常资产，否则为无效
                return_url_list.append(return_url)
        return return_url_list

    def exit(self,signum, frame):
        print("程序强制终止")
        return 

    def Feature_recognition(self,url_list):
    # 对总URL列表当中的url进行遍历，检查每一个URL的各种信息，识别其特征，并输出
        for url in url_list:
            # 接受信号
            signal.signal(signal.SIGINT, exit)
            signal.signal(signal.SIGTERM, exit)
            try:
                # 设置时间间隔
                time.sleep(self.__time)
                result = self.url_request(url, header=self.__headers, wait_time=self.__wait)
                # 获取状态码
                code = self.status(result)
                # 获取返回值长度
                out_length = self.return_length(result)
                # 获得标题
                title = self.get_title(result)
            except:
                # if self.__out:
                #     self.____EXCEL_LIST.append((url, "ERROR"))
                # else:
                print(url, "--->>>", "\033[31mERROR\033[0m")
            else:
                if code in self.__blackStatus:
                    pass
                else:
                    # if self.__out:
                    #     # 将所有的数据进行存储，然后写入Excel
                    #     self.____EXCEL_LIST.append((url, code, out_length, title))
                    # else:
                    print("\033[34m", url,"\033[0m", "响应:", code, "长度:", "\033[33m", out_length, "\033[0m", "Title:", "\033[32m", title, "\033[0m")

        # 用户选中了要以Excel的形式输出
        # if self.__out:
        #     # 为了方便于辨识不同域名之间的文件
        #     name = self.e_url.replace(':','_')
        #     name = name.replace('/','_')
        #     # 写入Excel文件
        #     filename = self.write_excel(self.____EXCEL_LIST,name)
        #     if self.__redup:
        #         # 用户自定义去重的列
        #         self.remove_duplicates(filename,self.__redup,name)


    def main(self,target):
        self.__url = target["url"].strip("/ ")
        headers = target["header"]
        self.__wait = int(target["wait"])
        self.__height = int(target["height"])
        proxy = target["proxy"]
        self.__level = int(target["level"])
        self.__time = int(target["timeout"])
        self.__ssl = target["ssl"]
        self.__headers, self.__proxy = ReqSet(header=headers, proxy=proxy)
        self.__blackStatus = [404,502,500]
    # 批量读取URL信息
        e_url = self.__url

        Object = self.url_request(url=e_url, header=self.__headers, wait_time=self.__wait)
        # print(Object)
        # 此时会获取得到第一次探测url得到的信息
        # print(2)
        analysis_result = self.analysis(Object.text, e_url)
        # print(1)
        if not analysis_result:
            print("未找到任何链接......")
            return
        all_url_list = []
        if self.__height > 0:
            # 假如设置了深度查找就步入
            height_scan_result = self.height_scan(analysis_result, header=self.__headers, wait_time=self.__wait, high=self.__height)
            # 第二次去重，主要是为了为下面的代码减轻工作量
            analysis_result = list(set(analysis_result + height_scan_result))
        for url in analysis_result:
            # 进行url文件路径的逐级递减
            decline_result = self.decline(url, self.__level)
            # 将递减后的demo_url 放入到all_url_list列表当中
            all_url_list.extend(decline_result)
        # 填入findsomething列表
        # if self.__findsomething:
            # noinspection PyUnboundLocalVariable
            # all_url_list.extend(fingsomething_result)

        # 此时会进行第三次去重，去重的是总url，主要是去除部分可能一级目录相同的问题
        all_url_list = list(set(all_url_list))
        # 识别url特征，并输出
        self.Feature_recognition(all_url_list)

