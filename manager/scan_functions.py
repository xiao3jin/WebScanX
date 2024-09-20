import base64
import difflib
import json
from asyncio import as_completed
from concurrent.futures import ThreadPoolExecutor
import socket
import threading
from loguru import logger
import time
import platform
import dns.resolver
import requests
from lxml import etree
from bs4 import BeautifulSoup
import whois
from urllib.parse import quote, urlparse, urljoin
from requests.adapters import HTTPAdapter
from urllib3 import Retry

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Cookie': 'acw_tc=0aef39a217258685358707829e00304673c048f67caaa4b8725c07a445c1c8; __51vcke__JfvlrnUmvss1wiTZ=b3e7e668-7926-5e41-8c2b-85ad113a99e2; __51vuft__JfvlrnUmvss1wiTZ=1725868535120; machine_str=a4331058-0776-47a4-8ded-412d97b749e3; .AspNetCore.Antiforgery.OGq99nrNx5I=CfDJ8OsC2ZLMIq9Ks_KNSEOc-tZ1IZIg78oX0irMBbK7GP7d-J8bDpIK80ajo2GneXXebjjFsov2oCUTaGDPtA7YOFPppde7whmOoMJqjMXe2u6BWqMzORnfkkmrlWxQxQrqwRMj1HymHIHLwgUw6EJoniQ; __vtins__JfvlrnUmvss1wiTZ=%7B%22sid%22%3A%20%228df74cdf-7b28-53c9-9262-4531b06c097a%22%2C%20%22vd%22%3A%201%2C%20%22stt%22%3A%200%2C%20%22dr%22%3A%200%2C%20%22expires%22%3A%201725871133194%2C%20%22ct%22%3A%201725869333194%7D; __51uvsct__JfvlrnUmvss1wiTZ=3',
}
class FoundationInfo():

    def get_cdn(self,domain):
        try:
            # 获取域名的A记录
            a_records = dns.resolver.resolve(domain, 'A')
            ip_addresses = [str(record) for record in a_records]

            # 获取域名的CNAME记录
            try:
                cname_records = dns.resolver.resolve(domain, 'CNAME')
                cname = str(cname_records[0].target)
            except dns.resolver.NoAnswer:
                cname = None

            # 检查是否存在多个IP地址
            if len(ip_addresses) > 1:
                return True

            # 检查CNAME是否指向已知的CDN提供商
            cdn_providers = ['akamai', 'cloudflare', 'cloudfront', 'fastly', 'cdn77']
            if cname and any(provider in cname.lower() for provider in cdn_providers):
                return True

            # 获取HTTP响应头
            try:
                response = requests.get(f"http://{domain}", timeout=5)
                headers = response.headers

                # 检查常见的CDN相关响应头
                cdn_headers = ['X-CDN', 'X-Powered-By-ChinaCache', 'Via', 'X-Cache']
                if any(header in headers for header in cdn_headers):
                    return True

                # 检查服务器响应头
                if 'Server' in headers and any(provider in headers['Server'].lower() for provider in cdn_providers):
                    return True

            except requests.RequestException:
                pass

            return False

        except Exception:
            return False
    def get_whois(self,domain):
        res = whois.whois(domain)
        name = str(res['name']).encode('utf-8').decode()
        return res
    # get_whois('qq.com')

    def get_ipc(self,domain,type):

        dateList = []
        if type == 'ip->domain':
            url = f'https://www.beianx.cn/search/{quote(domain)}'
            try:
                res = requests.get(url=url, headers=headers)
                res.raise_for_status()  # 检查请求是否成功
            except requests.RequestException as e:
                print(f"请求失败: {e}")
                return
            soup = BeautifulSoup(res.text, 'html.parser')
            datas = soup.find_all('tr')
            for data in datas:
                findDomain = data.find_all('a')
                for targetDomain in findDomain:
                    if targetDomain['href'].find('seo') !=-1:
                        dateList.append(targetDomain.text)
        else:
            url = f'https://www.beianx.cn/search/{domain}'
            try:
                res = requests.get(url=url, headers=headers)
                res.raise_for_status()  # 检查请求是否成功
            except requests.RequestException as e:
                print(f"请求失败: {e}")
                return

            soup = BeautifulSoup(res.text, 'html.parser')
            datas = soup.find_all(class_='align-middle')

            if not datas:
                print("未找到备案信息或网站结构已更改。")
            else:
                OrganizerName = datas[1].text.replace('\n', '')
                dateList.append(OrganizerName)
                OrganizerNature = datas[2].text.replace(' ', '').replace('\n', '')
                dateList.append(OrganizerNature)
                ipc_id = datas[3].text.replace(' ', '').replace('\n', '')
                dateList.append(ipc_id)
        return dateList
    # get_ipc('京ICP证030173号','iptodomain')

    def get_registrant(self,domain):
        res = self.get_whois(domain)
        registrantName = str(res['name']).encode('utf-8').decode()
        return registrantName

# found = FoundationInfo()
# res = found.get_registrant('iredteam.cn')
# print(res)

# 检测是否存在泛解析
class SubdomainExplosion():
    def __init__(self):
        self.domain1 = 'asfsdgdfsgfasdfdsdfs'
        self.domain2 = 'yuiopiuytgvbnmkjhghfghfjb'
    # 测试泛解析
    def get_analysis(self, domain):
        try:
            dns.resolver.resolve(self.domain1 + '.' + domain, rdtype='A')
            dns.resolver.resolve(self.domain2 + '.' + domain, rdtype='A')
            res1 = requests.get('http://' + self.domain1 + '.' + domain)
            res2 = requests.get('http://' + self.domain2 + '.' + domain)
            check_ana = difflib.SequenceMatcher(None,res1.text,res2.text).quick_ratio()
            if check_ana >= 0.90:
                print('[+]该域名存在泛解析')
                return False
            else:
                res = input('[-]可能存在泛解析,是否继续爆破? Y / N')
                if res == 'Y':
                    print('继续爆破子域名')
                    return True
                else:
                    print('停止爆破子域名')
                    return False
        except:
            print('[-]未检测到泛解析')
            return True

    def get_ip_address(self, domain):
        res = requests.get(f'http://ip-api.com/json/{domain}?lang=zh-CN')
        return res.json()['country']+res.json()['regionName'], res.json()['city']
    def sub_domain(self, domain):
        is_analysis = self.get_analysis(domain)
        if is_analysis is True:
            # print(213123)
            domain_list = []
            cdn_detected = False  # 添加一个标志变量来跟踪是否检测到CDN
            with open('domains.txt', 'r') as file:
                for sdomain in file.readlines():
                    sdomain = sdomain.replace('\n', '')
                    try:
                        query_res = dns.resolver.resolve(sdomain + '.' + domain, rdtype='A')
                        # print(sdomain + '.' + domain)
                        resFinger = self.fingerscan(sdomain + '.' + domain)
                        found = FoundationInfo()
                        res = found.get_cdn(domain)
                        if res is True:
                            if cdn_detected is False:
                                print('[+]目标存在CDN服务,不进行解析ip')
                                cdn_detected = True
                            print(sdomain + '.' + domain)
                            domain_list.append(sdomain + '.' + domain)
                        else:
                            for query_item in query_res.response.answer:
                                for item in query_item.items:
                                    ipg = self.get_ip_address(item)
                                    print(sdomain + '.' + domain+'>>>'+str(item)+'>>>'+str(ipg)+">>>"+resFinger)
                                    domain_list.append(sdomain + '.' + domain + '>>>' + str(item) + '>>>' + str(ipg)+">>>"+resFinger)
                    except:
                        pass
                return domain_list
        else:
            return '[+]该域名存在泛解析'

    def normalize_url(self,url):
        """规范化 URL，确保它有正确的 scheme"""
        parsed = urlparse(url)
        if not parsed.scheme:
            # 如果没有 scheme，默认使用 http
            url = 'http://' + url
        return url

    def fingerscan(self, url):
        # 规范化 URL
        url = self.normalize_url(url)

        # 读取指纹文件
        with open('finger.json', 'r', encoding='utf-8') as f:
            cms_data = json.load(f)

        try:
            # 尝试 HTTPS
            try:
                response = requests.get(url=url, timeout=10, headers=headers,verify=False)
            except requests.exceptions.SSLError:
                # 如果 HTTPS 失败，尝试 HTTP
                url_parts = list(urlparse(url))
                url_parts[0] = 'http'
                url = self.urlunparse(url_parts)
                response = requests.get(url=url, timeout=10,headers=headers)

            response.raise_for_status()

            # 解析 HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # 遍历指纹数据
            for fingerprint in cms_data['fingerprint']:
                cms = fingerprint['cms']
                keywords = fingerprint['keyword']
                location = fingerprint['location']

                # 根据 location 确定搜索范围
                if location == 'title':
                    content = soup.title.string if soup.title else ''
                elif location == 'body':
                    content = response.textS
                else:
                    content = ''

                # 检查是否所有关键词都存在
                if all(keyword.lower() in content.lower() for keyword in keywords):
                    return f'[+] {cms}'

            # 如果没有匹配到任何 CMS
            return "[-] Unknown CMS"

        except requests.RequestException as e:
            print(f"[-] Error accessing {url}: {e}")
            return "Error"


class DirScan():
    def __init__(self, max_retries=3):
        self.max_retries = max_retries
        self.session = requests.Session()
        retries = Retry(total=self.max_retries, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def _check_url(self, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                'Referer': 'http://127.0.0.1'
            }
            res = self.session.get(url, headers=headers, verify=False, timeout=5)
            return res.status_code, url, res.headers
        except requests.RequestException as e:
            return None, str(e), {}

    def run(self, url, dir_dict):
        dic_list = []
        with open(dir_dict, 'r') as file:
            dics = file.readlines()
            urls_to_check = [url + dic.strip() for dic in dics]
            for checked_url in urls_to_check:
                status_code, url, headers = self._check_url(checked_url)
                if status_code and status_code != 404:
                    dic_list.append((status_code, checked_url, headers))
                    print(f"[+] {checked_url} >> {status_code}")
            return dic_list

class Fofa_Api():
    def get_data(self,keyword):
        keyword = base64.b64encode(keyword.encode)
        url = f'https://fofa.info/api/v1/search/all?&key=your_key&qbase64={keyword}'
        res = requests.get(url).json()
        print(res['results'])
        # return res['results']

class PortScanner:
    def __init__(self):
        self.common_ports = {
            80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP", 3306: "MySQL",
            5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"
        }

    def portscan(self, domains):
        time_start = time.time()

        targets = domains.strip().split('\n')
        ports = input('请输入端口,多个端口用,隔开:')

        threads = []
        for domain in targets:
            thread = threading.Thread(target=self._scan_target, args=(domain, ports))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        time_end = time.time()
        run_time = time_end - time_start
        logger.info(f"所有目标扫描完成,总耗时: {run_time:.2f}秒")

    def _scan_target(self, domain, ports):
        try:
            ip = socket.gethostbyname(domain)
            logger.info(f"开始扫描目标: {domain} ({ip})")

            if ',' in ports:
                port_list = ports.split(',')
                for port in port_list:
                    self._scan_port(ip, int(port))
            else:
                self._scan_port(ip, int(ports))

            self._os_detection(ip)
        except socket.gaierror:
            logger.error(f"无法解析域名: {domain}")

    def _scan_port(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                service = self._service_detection(ip, port)
                logger.debug(f'[+]{ip}:{port} 端口开放 - 服务: {service}')
            else:
                logger.error(f'[-]{ip}:{port} 端口未开放')
            s.close()
        except Exception as e:
            logger.warning(f'扫描 {ip}:{port} 时出错: {e}')

    def _os_detection(self, ip):
        try:
            # 使用TTL值进行简单的操作系统检测
            ttl = self._get_ttl(ip)
            os = self._guess_os(ttl)
            logger.info(f"{ip} 可能的操作系统: {os}")
        except Exception as e:
            logger.warning(f"{ip} 操作系统检测失败: {e}")

    def _get_ttl(self, ip):
        try:
            if platform.system().lower() == "windows":
                output = os.popen(f"ping -n 1 {ip}").read()
                ttl_str = output.split("TTL=")[1].split("\n")[0]
            else:
                output = os.popen(f"ping -c 1 {ip}").read()
                ttl_str = output.split("ttl=")[1].split(" ")[0]
            return int(ttl_str)
        except:
            return None

    def _guess_os(self, ttl):
        if ttl is None:
            return "Unknown"
        elif ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Unknown"

    def _service_detection(self, ip, port):
        if port in self.common_ports:
            return self.common_ports[port]
        else:
            try:
                service = socket.getservbyport(port)
                return service
            except:
                return "Unknown"

def nuclei_scan(target_urls):
    try:
        # 执行 Nuclei 扫描命令
        command = f'F:\\nuclei.exe -u {target_urls}'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # 处理扫描结果
        if result.returncode == 0:
            output = result.stdout
            print(f"Scan for {target_urls} succeeded: {output}")
        else:
            print(f"Error during scan for {target_urls}: {result.stderr}")

    except Exception as e:
        print(f"Exception during scan: {str(e)}")


# Django 视图函数
def run_nuclei_scan(request, target_urls):
    try:
        # 创建并启动一个后台线程来运行 Nuclei 扫描
        scan_thread = threading.Thread(target=nuclei_scan, args=(target_urls,))
        scan_thread.start()

        # 立即返回响应，告诉用户扫描已开始
        return HttpResponse(f"Started scan for {target_urls}. The results will be available later.", status=200)

    except Exception as e:
        return HttpResponse(f"Error: {str(e)}", status=500)