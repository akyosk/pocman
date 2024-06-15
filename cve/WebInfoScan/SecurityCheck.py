#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import ftplib
import socket
import memcache
import pymongo
import requests
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet

class SecurityCheckScan:
    # 检查 FTP 是否存在未授权访问漏洞å
    def run(self,ip):
        self.check_ftp(ip)
        self.check_jboss(ip)
        self.check_solr(ip)
        self.check_weblogic(ip)
        self.check_ldap(ip)
        self.check_redis(ip)
        self.check_nfs(ip)
        self.check_zookeeper(ip)
        self.check_elasticsearch(ip)
        self.check_jenkins(ip)
        self.check_kibana(ip)
        self.check_ipc(ip)
        self.check_druid(ip)
        self.check_docker(ip)
        self.check_rabbitmq(ip)
        self.check_memcached(ip)
        self.check_dubbo(ip)
        self.check_bt_phpmyadmin(ip)
        self.check_rsync(ip)
        self.check_kubernetes_api_server(ip)
        self.check_couchdb(ip)
        self.check_spring_boot_actuator(ip)
        self.check_uwsgi(ip)
        self.check_thinkadmin_v6(ip)
        self.check_php_fpm_fastcgi(ip)
        self.check_mongodb(ip)
        self.check_jupyter_notebook(ip)
        self.check_apache_spark(ip)
        self.check_docker_registry(ip)
        self.check_hadoop_yarn(ip)
        self.check_kong(ip)
        self.check_wordpress(ip)
        self.check_zabbix(ip)
        self.check_activemq(ip)
        self.check_harbor(ip)
        self.check_atlassian_crowd(ip)
    def check_ftp(self, ip):
        try:
            ftp = ftplib.FTP(ip)
            ftp.login()
            ftp.cwd('/')
            ftp.quit()
            OutPrintInfo("FTP",f"目标[b bright_red]{ip}[/b bright_red]存在FTP未授权访问漏洞")
        except:
            OutPrintInfo("FTP",f"目标{ip}FTP无法连接")



    def check_jboss(self, ip):

        # 检查 JBoss 是否存在未授权访问漏洞
        jboss_url = f'http://{ip}:8080/jmx-console/'
        try:
            jboss_response = requests.get(jboss_url,timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'jboss' in jboss_response.headers.get('Server', '') and 'Welcome to JBossAS' in jboss_response.text:
                OutPrintInfo("JBOSS",f"目标[b bright_red]{ip}[/b bright_red]存在jboss未授权访问漏洞")
                OutPrintInfo("JBOSS",f"Url: [b bright_red]{jboss_url}[/b bright_red]")

            else:
                OutPrintInfo("JBOSS",f"目标{ip}不存在jboss未授权访问漏洞")
        except:
            OutPrintInfo("JBOSS",f"目标{ip}jboss无法连接")


        # 检查 Solr 是否存在未授权访问漏洞

    def check_solr(self, ip):
        solr_url = f'http://{ip}:8983/solr/'
        try:
            response = requests.get(solr_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Apache Solr' in response.text:
                OutPrintInfo("SOLR",f"目标[b bright_red]{ip}[/b bright_red]存在solr未授权访问漏洞")
                OutPrintInfo("SOLR",f"Url: [b bright_red]{solr_url}[/b bright_red]")
            else:
                OutPrintInfo("SOLR",f"目标{ip}不存在solr未授权访问漏洞")

        except:
            OutPrintInfo("SOLR",f"目标{ip}solr无法连接")


        # 检查 WebLogic 是否存在未授权访问漏洞

    def check_weblogic(self, ip):

        weblogic_url = f'http://{ip}:7001/console/login/LoginForm.jsp'

        try:
            response = requests.get(weblogic_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Oracle WebLogic Server' in response.text:
                OutPrintInfo("WEBLOGIC",f"目标[b bright_red]{ip}[/b bright_red]存在weblogic未授权访问漏洞")
                OutPrintInfo("WEBLOGIC",f"Url: [b bright_red]{weblogic_url}[/b bright_red]")
            else:
                OutPrintInfo("WEBLOGIC",f"目标{ip}不存在weblogic未授权访问漏洞")
        except:
            OutPrintInfo("WEBLOGIC",f"目标{ip}weblogic无法连接")


    def check_ldap(self, ip):

        # 检查 LDAP 是否存在未授权访问漏洞
        ldap_url = ip + ':389'
        try:
            ldap_response = requests.get(ldap_url,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'OpenLDAP' in ldap_response.headers.get('Server', '') and '80090308' in ldap_response.text:
                OutPrintInfo("LDAP",f"目标[b bright_red]{ip}[/b bright_red]存在ldap未授权访问漏洞")
                OutPrintInfo("LDAP",f"Url: [b bright_red]{ldap_url}[/b bright_red]")
            else:
                OutPrintInfo("LDAP",f"目标{ip}不存在ldap未授权访问漏洞")
        except:
            OutPrintInfo("LDAP",f"目标{ip}ldap无法连接")

    def check_redis(self, ip):

        # 检查 Redis 是否存在未授权访问漏洞
        redis_url = ip + ':6379/info'
        try:
            redis_response = requests.get(redis_url, allow_redirects=False,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if redis_response.status_code == 200 and 'redis_version' in redis_response.text:
                OutPrintInfo("REDIS",f"目标[b bright_red]{ip}[/b bright_red]存在redis未授权访问漏洞")
                OutPrintInfo("REDIS",f"Url: [b bright_red]{redis_url}[/b bright_red]")
            else:
                OutPrintInfo("REDIS",f"目标{ip}不存在redis未授权访问漏洞")
        except:
            OutPrintInfo("REDIS",f"目标{ip}redis无法连接")

    def check_nfs(self, ip):
        # 检查 NFS 是否存在未授权访问漏洞
        try:
            nfs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            nfs_socket.settimeout(3)
            nfs_socket.connect((ip, 2049))
            nfs_socket.sendall(
                b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            response = nfs_socket.recv(1024)
            if b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x02\x00\x00\x00\x01' in response:
                OutPrintInfo("NFS",f"目标[b bright_red]{ip}[/b bright_red]存在nfs未授权访问漏洞")
            else:
                OutPrintInfo("NFS",f"目标{ip}不存在nfs未授权访问漏洞")
        except:
            OutPrintInfo("NFS",f"nfs无法连接到该 {ip}")


    def check_zookeeper(self, ip):

        # 检查 Zookeeper 是否存在未授权访问漏洞
        zookeeper_url = ip + ':2181'
        try:
            zookeeper_response = requests.get(zookeeper_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Zookeeper' in zookeeper_response.headers.get('Server',
                                                             '') and zookeeper_response.status_code == 200:
                OutPrintInfo("Zookeeper",f"目标[b bright_red]{ip}[/b bright_red]存在zookeeper未授权访问漏洞")
                OutPrintInfo("Zookeeper",f"Url: [b bright_red]{zookeeper_url}[/b bright_red]")
            else:
                OutPrintInfo("Zookeeper",f"目标{ip}不存在zookeeper未授权访问漏洞")
        except:
            OutPrintInfo("Zookeeper","无法连接到 Zookeeper 服务")


    # 检查 VNC 是否存在未授权访问漏洞
    def check_vnc(self, ip):

        vnc_url = f'vnc://{ip}'
        try:
            tigerVNC_response = requests.get(vnc_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if "RFB 003.008\n" in tigerVNC_response.content.decode('utf-8'):
                OutPrintInfo("VNC",f"目标[b bright_red]{ip}[/b bright_red]存在vnc未授权访问漏洞")
                OutPrintInfo("VNC",f"Url: [b bright_red]{vnc_url}[/b bright_red]")
            else:
                OutPrintInfo("VNC",f"目标{ip}不存在vnc未授权访问漏洞")
        except:
            OutPrintInfo("VNC",f"目标{ip}vnc无法连接")

    # 检查 Elasticsearch 是否存在未授权访问漏洞
    def check_elasticsearch(self, ip):

        url = f'http://{ip}:8000/_cat'
        try:
            response = requests.get(url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if '/_cat/master' in response.text:
                OutPrintInfo("Elasticsearch",f"目标[b bright_red]{ip}[/b bright_red]存在elasticsearch未授权访问漏洞")
                OutPrintInfo("Elasticsearch",f"Url: [b bright_red]{url}[/b bright_red]")
            else:
                OutPrintInfo("Elasticsearch",f"目标{ip}不存在elasticsearch未授权访问漏洞")
        except:
            OutPrintInfo("Elasticsearch",f"目标{ip}es无法连接")


    # 检查 Jenkins 是否存在未授权访问漏洞
    def check_jenkins(self, ip):

        jenkins_url = f'http://{ip}:8080'
        try:
            response = requests.get(jenkins_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'jenkins' in response.headers.get('X-Jenkins', '') and 'Dashboard [Jenkins]' in response.text:
                OutPrintInfo("Jenkins",f"目标[b bright_red]{ip}[/b bright_red]存在jenkins未授权访问漏洞")
                OutPrintInfo("Jenkins",f"Url: [b bright_red]{jenkins_url}[/b bright_red]")
            else:
                OutPrintInfo("Jenkins",f"目标{ip}不存在jenkins未授权访问漏洞")
        except:
            OutPrintInfo("Jenkins",f"目标{ip}jenkins无法连接")

    # 检查 Kibana 是否存在未授权访问漏洞
    def check_kibana(self, ip):

        kibana_url = f'http://{ip}:5601'
        try:
            response = requests.get(kibana_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'kbn-name="kibana"' in response.text:
                OutPrintInfo("Kibana",f"目标[b bright_red]{ip}[/b bright_red]存在kibana未授权访问漏洞")
                OutPrintInfo("Kibana",f"Url: [b bright_red]{kibana_url}[/b bright_red]")
            else:
                OutPrintInfo("Kibana",f"目标{ip}不存在kibana未授权访问漏洞")
        except:
            OutPrintInfo("Kibana",f"目标{ip}kibana无法连接")


    # 检查 IPC 是否存在未授权访问漏洞
    def check_ipc(self, ip):

        ipc_url = f'http://{ip}:445'
        try:
            response = requests.get(ipc_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'IPC Service' in response.text:
                OutPrintInfo("IPC",f"目标[b bright_red]{ip}[/b bright_red]存在ipc未授权访问漏洞")
                OutPrintInfo("IPC",f"Url: [b bright_red]{ipc_url}[/b bright_red]")
            else:
                OutPrintInfo("IPC",f"目标{ip}不存在ipc未授权访问漏洞")
        except:
            OutPrintInfo("IPC",f"目标{ip}ipc无法连接")


    # 检查 Druid 是否存在未授权访问漏洞
    def check_druid(self, ip):

        druid_url = f'http://{ip}:8888/druid/index.html'
        try:
            response = requests.get(druid_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Druid Console' in response.text:
                OutPrintInfo("Druid",f"目标[b bright_red]{ip}[/b bright_red]存在druid未授权访问漏洞")
                OutPrintInfo("Druid",f"Url: [b bright_red]{druid_url}[/b bright_red]")
            else:
                OutPrintInfo("Druid",f"目标{ip}不存在druid未授权访问漏洞")
        except:
            OutPrintInfo("Druid",f"目标{ip}druid无法连接")


    def check_swaggerui(self, ip):

        # 检查 SwaggerUI 是否存在未授权访问漏洞
        swaggerui_url = ip + '/swagger-ui.html'
        try:
            swaggerui_response = requests.get(swaggerui_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Swagger' in swaggerui_response.text:
                OutPrintInfo("SwaggerUI",f"目标[b bright_red]{ip}[/b bright_red]存在swaggerui未授权访问漏洞")
                OutPrintInfo("SwaggerUI",f"Url: [b bright_red]{swaggerui_url}[/b bright_red]")
            else:
                OutPrintInfo("SwaggerUI",f"目标{ip}不存在swaggerui未授权访问漏洞")
        except:
            OutPrintInfo("SwaggerUI","无法连接到 SwaggerUI 应用程序")


    def check_docker(self, ip):

        # 检查 Docker 是否存在未授权访问漏洞
        docker_url = 'http://' + ip + ':2375/version'
        try:
            docker_response = requests.get(docker_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if docker_response.status_code == 200 and 'ApiVersion' in docker_response.json():
                OutPrintInfo("Docker",f"目标[b bright_red]{ip}[/b bright_red]存在docker未授权访问漏洞")
                OutPrintInfo("Docker",f"Url: [b bright_red]{docker_url}[/b bright_red]")
            else:
                OutPrintInfo("Docker",f"目标{ip}不存在docker未授权访问漏洞")
        except:
            OutPrintInfo("Docker","无法连接到 Docker 守护进程")


    # 检查 RabbitMQ 是否存在未授权访问漏洞
    def check_rabbitmq(self, ip):

        rabbitmq_url = f'http://{ip}:15672/'

        try:
            response = requests.get(rabbitmq_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'RabbitMQ Management' in response.text and 'overview-module' in response.text:
                OutPrintInfo("RabbitMQ",f"目标[b bright_red]{ip}[/b bright_red]存在rabbitmq未授权访问漏洞")
                OutPrintInfo("RabbitMQ",f"Url: [b bright_red]{rabbitmq_url}[/b bright_red]")
            else:
                OutPrintInfo("RabbitMQ",f"目标{ip}不存在rabbitmq未授权访问漏洞")
        except:
            OutPrintInfo("RabbitMQ",f"目标{ip}rabbitmq无法连接")


    # 检查 Memcached 是否存在未授权访问漏洞
    def check_memcached(self, ip):

        try:
            memcached_client = memcache.Client([ip], timeout=5)
            stats = memcached_client.get_stats()
            if len(stats) > 0:
                OutPrintInfo("Memcached",f"目标[b bright_red]{ip}[/b bright_red]存在memcached未授权访问漏洞")
            else:
                OutPrintInfo("Memcached",f"目标{ip}不存在memcached未授权访问漏洞")
        except:
            OutPrintInfo("Memcached",f"目标{ip}memcached无法连接")

    # 检查 Dubbo 是否存在未授权访问漏洞
    def check_dubbo(self, ip):

        url = f'http://{ip}:8080/'
        try:
            response = requests.get(url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'dubbo' in response.headers and 'Welcome to the Dubbo' in response.text:
                OutPrintInfo("Dubbo",f"目标[b bright_red]{ip}[/b bright_red]存在dubbo未授权访问漏洞")
                OutPrintInfo("Dubbo",f"Url: [b bright_red]{url}[/b bright_red]")
            else:
                OutPrintInfo("Dubbo",f"目标{ip}不存在dubbo未授权访问漏洞")
        except:
            OutPrintInfo("Dubbo",f"目标{ip}dubbo无法连接")

    # 检查宝塔phpmyadmin是否存在未授权访问漏洞
    def check_bt_phpmyadmin(self, ip):
        phpmyadmin_url = f'http://{ip}/phpmyadmin/'
        try:
            response = requests.get(phpmyadmin_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'phpMyAdmin' in response.text:
                OutPrintInfo("PHPMYADMIN",f"目标[b bright_red]{ip}[/b bright_red]存在bt_phpmyadmin未授权访问漏洞")
                OutPrintInfo("PHPMYADMIN",f"Url: [b bright_red]{phpmyadmin_url}[/b bright_red]")
            else:
                OutPrintInfo("PHPMYADMIN",f"目标{ip}不存在bt_phpmyadmin未授权访问漏洞")
        except:
            OutPrintInfo("PHPMYADMIN",f"目标{ip}bt-phpmydamin无法连接")


    # 检查 Rsync 是否存在未授权访问漏洞
    def check_rsync(self, ip):

        rsync_url = f'rsync://{ip}'
        try:
            response = requests.get(rsync_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'rsync' in response.headers.get('Server', '') and 'rsyncd.conf' in response.text:
                OutPrintInfo("Rsync",f"目标[b bright_red]{ip}[/b bright_red]存在rsync未授权访问漏洞")
                OutPrintInfo("Rsync",f"Url: [b bright_red]{rsync_url}[/b bright_red]")
            else:
                OutPrintInfo("Rsync",f"目标{ip}不存在rsync未授权访问漏洞")
        except:
            OutPrintInfo("Rsync",f"目标{ip}rsync无法连接")


    # 检查 Kubernetes Api Server 是否存在未授权访问漏洞
    def check_kubernetes_api_server(self, ip):

        api_server_url = f'https://{ip}:6443/api/'

        try:
            response = requests.get(api_server_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Unauthorized' in response.text:
                OutPrintInfo("Kubernetes",f"目标[b bright_red]{ip}[/b bright_red]存在kubernetes_api_server未授权访问漏洞")
                OutPrintInfo("Kubernetes",f"Url: [b bright_red]{api_server_url}[/b bright_red]")
            else:
                OutPrintInfo("Kubernetes",f"目标{ip}不存在kubernetes_api_server未授权访问漏洞")
        except:
            OutPrintInfo("Kubernetes",f"目标{ip}kubernetes无法连接")


    # 检查 CouchDB 是否存在未授权访问漏洞
    def check_couchdb(self, ip):

        couchdb_url = f'http://{ip}:5984/_utils/'

        try:
            response = requests.get(couchdb_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Welcome to CouchDB' in response.text:
                OutPrintInfo("CouchDB",f"目标[b bright_red]{ip}[/b bright_red]存在couchdb未授权访问漏洞")
                OutPrintInfo("CouchDB",f"Url: [b bright_red]{couchdb_url}[/b bright_red]")
            else:
                OutPrintInfo("CouchDB",f"目标{ip}不存在couchdb未授权访问漏洞")
        except:
            OutPrintInfo("CouchDB",f"目标{ip}couchdb无法连接")


    # 检查 Spring Boot Actuator 是否存在未授权访问漏洞
    def check_spring_boot_actuator(self, ip):

        actuator_url = f'http://{ip}:8080/actuator/'

        try:
            response = requests.get(actuator_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Hystrix' in response.text and 'health" : {' in response.text:
                OutPrintInfo("Spring",f"目标[b bright_red]{ip}[/b bright_red]存在spring_boot_actuator未授权访问漏洞")
                OutPrintInfo("Spring",f"Url: [b bright_red]{actuator_url}[/b bright_red]")
            else:
                OutPrintInfo("Spring",f"目标{ip}不存在spring_boot_actuator未授权访问漏洞")
        except:
            OutPrintInfo("Spring",f"目标{ip}actuator无法连接")

    # 检查 uWSGI 是否存在未授权访问漏洞
    def check_uwsgi(self, ip):

        uwsgi_url = f'http://{ip}:1717/'

        try:
            response = requests.get(uwsgi_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'uWSGI Status' in response.text:
                OutPrintInfo("uWSGI",f"目标[b bright_red]{ip}[/b bright_red]存在uwsgi未授权访问漏洞")
                OutPrintInfo("uWSGI",f"Url: [b bright_red]{uwsgi_url}[/b bright_red]")
            else:
                OutPrintInfo("uWSGI",f"目标{ip}不存在uwsgi未授权访问漏洞")
        except:
            OutPrintInfo("uWSGI",f"目标{ip}uwsgi无法连接")


    # 检查 ThinkAdmin V6 是否存在未授权访问漏洞
    def check_thinkadmin_v6(self, ip):

        thinkadmin_url = f'http://{ip}/index/login.html'

        try:
            response = requests.get(thinkadmin_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'ThinkAdmin' in response.text and 'logincheck' in response.text:
                OutPrintInfo("ThinkAdmin",f"目标[b bright_red]{ip}[/b bright_red]存在thinkadmin_v6未授权访问漏洞")
                OutPrintInfo("ThinkAdmin",f"Url: [b bright_red]{thinkadmin_url}[/b bright_red]")
            else:
                OutPrintInfo("ThinkAdmin",f"目标{ip}不存在thinkadmin_v6未授权访问漏洞")
        except:
            OutPrintInfo("ThinkAdmin",f"目标{ip}thinkadminv6无法连接")


    # 检查 PHP-FPM Fastcgi 是否存在未授权访问漏洞
    def check_php_fpm_fastcgi(self, ip):

        php_fpm_url = f'http://{ip}/php-fpm_status'

        try:
            response = requests.get(php_fpm_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'pool:' in response.text and 'processes' in response.text:
                OutPrintInfo("PHP-FPM",f"目标[b bright_red]{ip}[/b bright_red]存在php_fpm_fastcgi未授权访问漏洞")
                OutPrintInfo("PHP-FPM",f"Url: [b bright_red]{php_fpm_url}[/b bright_red]")
            else:
                OutPrintInfo("PHP-FPM",f"目标{ip}不存在php_fpm_fastcgi未授权访问漏洞")
        except:
            OutPrintInfo("PHP-FPM",f"目标{ip}phpfpm无法连接")

    # 检查 MongoDB 是否存在未授权访问漏洞
    def check_mongodb(self, ip):

        mongodb_url = f'mongodb://{ip}:27017/'

        try:
            client = pymongo.MongoClient(mongodb_url, serverSelectionTimeoutMS=5000)
            dbs = client.list_database_names()
            if len(dbs) > 0:
                OutPrintInfo("MongoDB",f"目标[b bright_red]{ip}[/b bright_red]存在mongodb未授权访问漏洞")
                OutPrintInfo("MongoDB",f"Url: [b bright_red]{mongodb_url}[/b bright_red]")
            else:
                OutPrintInfo("MongoDB",f"目标{ip}不存在mongodb未授权访问漏洞")
        except:
            OutPrintInfo("MongoDB",f"目标{ip}mongodb无法连接")


    # 检查 Jupyter Notebook 是否存在未授权访问漏洞
    def check_jupyter_notebook(self, ip):

        notebook_url = f'http://{ip}:8888/'

        try:
            response = requests.get(notebook_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Jupyter Notebook' in response.text:
                OutPrintInfo("Jupyter Notebook",f"目标[b bright_red]{ip}[/b bright_red]存在jupyter_notebook未授权访问漏洞")
                OutPrintInfo("Jupyter Notebook",f"Url: [b bright_red]{notebook_url}[/b bright_red]")
            else:
                OutPrintInfo("Jupyter Notebook",f"目标{ip}不存在jupyter_notebook未授权访问漏洞")
        except:
            OutPrintInfo("Jupyter Notebook",f"目标{ip}jupyter无法连接")


    # 检查 Apache Spark 是否存在未授权访问漏洞
    def check_apache_spark(self, ip):

        spark_url = f'http://{ip}:8080/'

        try:
            response = requests.get(spark_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Spark Master at' in response.text and 'Workers' in response.text:
                OutPrintInfo("Apache Spark",f"目标[b bright_red]{ip}[/b bright_red]存在apache_spark未授权访问漏洞")
                OutPrintInfo("Apache Spark",f"Url: [b bright_red]{spark_url}[/b bright_red]")
            else:
                OutPrintInfo("Apache Spark",f"目标{ip}不存在apache_spark未授权访问漏洞")
        except:
            OutPrintInfo("Apache Spark",f"目标{ip}spark无法连接")


    # 检查 Docker Registry 是否存在未授权访问漏洞
    def check_docker_registry(self, ip):

        registry_url = f'http://{ip}/v2/_catalog'

        try:
            response = requests.get(registry_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'repositories' in response.json():
                OutPrintInfo("Docker Registry",f"目标[b bright_red]{ip}[/b bright_red]存在docker_registry未授权访问漏洞")
                OutPrintInfo("Docker Registry",f"Url: [b bright_red]{registry_url}[/b bright_red]")
            else:
                OutPrintInfo("Docker Registry",f"目标{ip}不存在docker_registry未授权访问漏洞")
        except:
            OutPrintInfo("Docker Registry",f"目标{ip}registry无法连接")

    # 检查 Hadoop YARN 是否存在未授权访问漏洞
    def check_hadoop_yarn(self, ip):

        yarn_url = f'http://{ip}:8088/ws/v1/cluster/info'

        try:
            response = requests.get(yarn_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'resourceManagerVersion' in response.json()['clusterInfo']:
                OutPrintInfo("Hadoop YARN",f"目标[b bright_red]{ip}[/b bright_red]存在hadoop_yarn未授权访问漏洞")
                OutPrintInfo("Hadoop YARN",f"Url: [b bright_red]{yarn_url}[/b bright_red]")
            else:
                OutPrintInfo("Hadoop YARN",f"目标{ip}不存在hadoop_yarn未授权访问漏洞")
        except:
            OutPrintInfo("Hadoop YARN",f"目标{ip}yarn无法连接")


    # 检查 Kong 是否存在未授权访问漏洞
    def check_kong(self, ip):

        kong_url = f'http://{ip}:8001/'

        try:
            response = requests.get(kong_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Welcome to Kong' in response.text:
                OutPrintInfo("Kong",f"目标[b bright_red]{ip}[/b bright_red]存在kong未授权访问漏洞")
                OutPrintInfo("Kong",f"Url: [b bright_red]{kong_url}[/b bright_red]")
            else:
                OutPrintInfo("Kong",f"目标{ip}不存在kong未授权访问漏洞")
        except:
            OutPrintInfo("Kong",f"目标{ip}kong无法连接")


    # 检查 WordPress 是否存在未授权访问漏洞
    def check_wordpress(self, ip):
        wordpress_url = f'http://{ip}/wp-login.php'

        try:
            response = requests.get(wordpress_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'WordPress' in response.text:
                OutPrintInfo("WordPress",f"目标[b bright_red]{ip}[/b bright_red]存在wordpress未授权访问漏洞")
                OutPrintInfo("WordPress",f"Url: [b bright_red]{wordpress_url}[/b bright_red]")
            else:
                OutPrintInfo("WordPress",f"目标{ip}不存在wordpress未授权访问漏洞")
        except:
            OutPrintInfo("WordPress",f"目标{ip}wordpress无法连接")


    # 检查 Zabbix 是否存在未授权访问漏洞
    def check_zabbix(self, ip):

        zabbix_url = f'http://{ip}/zabbix/jsrpc.php'

        try:
            headers = {
                'Content-Type': 'application/json-rpc',
                'User-Agent': 'Mozilla/5.0'
            }
            data = '{"jsonrpc":"2.0","method":"user.login","params":{"user":"","password":""},"id":0}'
            response = requests.post(zabbix_url, headers=headers, data=data, timeout=5,verify=self.verify,proxies=self.proexis)
            if 'result' in response.json():
                OutPrintInfo("Zabbix",f"目标[b bright_red]{ip}[/b bright_red]存在zabbix未授权访问漏洞")
                OutPrintInfo("Zabbix",f"Url: [b bright_red]{zabbix_url}[/b bright_red]")
            else:
                OutPrintInfo("Zabbix",f"目标{ip}不存在zabbix未授权访问漏洞")
        except:
            OutPrintInfo("Zabbix",f"目标{ip}zabbix无法连接")



    # 检查 Active MQ 是否存在未授权访问漏洞
    def check_activemq(self, ip):

        activemq_url = f'http://{ip}:8161/admin/'

        try:
            response = requests.get(activemq_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Apache ActiveMQ' in response.text:
                OutPrintInfo("Active MQ",f"目标[b bright_red]{ip}[/b bright_red]存在activemq未授权访问漏洞")
                OutPrintInfo("Active MQ",f"Url:[b bright_red]{activemq_url}[/b bright_red]")
            else:
                OutPrintInfo("Active MQ",f"目标{ip}不存在activemq未授权访问漏洞")
        except:
            OutPrintInfo("Active MQ",f"目标{ip}activemq无法连接")


    # 检查 Harbor 是否存在未授权访问漏洞
    def check_harbor(self, ip):

        harbor_url = f'http://{ip}/api/v2.0/statistics'

        try:
            response = requests.get(harbor_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'total_projects' in response.json():
                OutPrintInfo("Harbor",f"目标[b bright_red]{ip}[/b bright_red]存在harbor未授权访问漏洞")
                OutPrintInfo("Harbor",f"Url: [b bright_red]{harbor_url}[/b bright_red]")
            else:
                OutPrintInfo("Harbor",f"目标{ip}不存在harbor未授权访问漏洞")
        except:
            OutPrintInfo("Harbor",f"目标{ip}harbor无法连接")

    # 检查 Atlassian Crowd 是否存在未授权访问漏洞
    def check_atlassian_crowd(self, ip):

        crowd_url = f'http://{ip}:8095/crowd/'

        try:
            response = requests.get(crowd_url, timeout=5,verify=self.verify,proxies=self.proexis,headers=self.headers)
            if 'Atlassian Crowd' in response.text:
                OutPrintInfo("Atlassian Crowd",f"目标[b bright_red]{ip}[/b bright_red]存在atlassian_crowd未授权访问漏洞")
                OutPrintInfo("Atlassian Crowd",f"Url: [b bright_red]{crowd_url}[/b bright_red]")
            else:
                OutPrintInfo("Atlassian Crowd",f"目标{ip}不存在atlassian_crowd未授权访问漏洞")
        except:
            OutPrintInfo("Atlassian Crowd",f"目标{ip}atlassian无法连接")


    def main(self,target):
        ip = target["ip"]
        if '://' in ip:
            OutPrintInfo("WORK","[b bright_red]只支持IP格式[/b bright_red]")
            return
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proexis = ReqSet(header=header, proxy=proxy)
        OutPrintInfo("WORK",'开始执行任务')
        self.run(ip)
        OutPrintInfo("WORK",'执行结束')