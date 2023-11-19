import requests
from bs4 import BeautifulSoup
from rich.progress import Progress
from rich.prompt import Prompt
from concurrent.futures import ThreadPoolExecutor,as_completed,wait
from libs.public.outprint import OutPrintInfo,OutPrintInfoErr



class ShodanWork:
    def run(self,url):
        headers = {
            "User-Agent": self.headers,
            "Cookie": self.cookie,
            "Referer": url
        }

        req = requests.get(url, headers=headers)
        # print(headers)
        # print(req.text)

        soup = BeautifulSoup(req.text, 'html.parser')
        ele = soup.find("h4")

        if ele:
            str = ele.text.replace(",", "")
            OutPrintInfo("Shodan",f"搜索 [b bright_red]{self.search}[/b bright_red] 共有 [b bright_red]{ele.text}[/b bright_red] 个相关结果, 预计 [b bright_red]{int(str) / 10}[/b bright_red] 页")
            return True


    def craw(self,search,page):
        pages = 1
        if int(page) > 1:
            pages = int(page)-1
        lis = []
        url = f"{search}&page={str(page)}"
        # print(url)

        headers = {
            "User-Agent": self.headers,
            "Cookie": self.cookie,
            "Referer": f"https://beta.shodan.io/search?query={search}&page={str(pages)}"
        }

        req = requests.get(url, headers=headers).text

        soup2 = BeautifulSoup(req, 'html.parser')
        hostnames = soup2.find_all("li", {"class": "hostnames text-secondary"})
        # print(req)
        if hostnames:
            for j in hostnames:
                if j.text not in lis:
                    lis.append(j.text)
        return lis

    def main(self,target):
        search = target[0].strip()
        self.search = search
        self.headers = target[1]
        self.cookie = target[2].strip()
        threads = int(target[3])
        is_file = target[4]
        if not self.cookie:
            OutPrintInfoErr("必须传入cookie值")
            return

        OutPrintInfo("Shodan", "开始搜索相关信息...")
        url = f"https://beta.shodan.io/search?query={search}"
        flag = self.run(url)
        if flag:
            page = Prompt.ask("[b bright_yellow]输入爬取页数｜普通用户只能爬取前20页")
            page += 1
            res_list = []
            with Progress(transient=True) as progress:
                tasks = progress.add_task("[b magenta]爬取进行中...",total=int(page))
                with ThreadPoolExecutor(threads) as pool:
                    futures = [pool.submit(self.craw,url,page) for page in range(1,int(page))]
                    for future in as_completed(futures):
                        craws = future.result()
                        for cs in craws:
                            if cs not in res_list:
                                res_list.append(cs)
                        progress.update(tasks,advance=1)

                wait(futures)

            if res_list:
                if is_file:
                    OutPrintInfo("Shodan", "开始导出文件...")
                    with open("./result/shodan.txt","a") as w:
                        for domains in res_list:
                            w.write(domains+"\n")
                    OutPrintInfo("Shodan", f"共导出信息 [b bright_red]{len(res_list)}[/b bright_red] 条")
                    OutPrintInfo("Shodan", f"文件保存与 [b bright_red]result/shodan.txt[/b bright_red] ")
                else:
                    OutPrintInfo("Shodan", "搜索结果如下")
                    for domains in res_list:
                        OutPrintInfo("Shodan", domains)
        else:
            OutPrintInfo("Shodan", "未搜索到结果或者Api次数已全部使用")
