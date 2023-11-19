import time
from cve.WebInfoScan.dirpro_main.script.results import Results
def _end(rooturl,time1,ret):
    result = Results(rooturl,ret)
    time2 = time.time()
    print("总共花费: ", time2 - time1, "秒,", f"结果保存在{result}")
    ret.clear()