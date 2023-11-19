#!/user/bin/env python3
# -*- coding: utf-8 -*-
import random
from libs.public.banner import banner
from libs.public.main import pocMain
from rich import print

if __name__ == '__main__':
    num = random.randint(0,len(banner())-1)
    print(banner()[num])
    try:
        pocMain().main()
    except KeyboardInterrupt as e:
        pass