#!/user/bin/env python3
# -*- coding: utf-8 -*-

import os
class weblogicRunScan:
    def main(self,target):
        os.system(f"python cve/Weblogic/weblogicScanner_master/ws.py -t {target['ip']}")