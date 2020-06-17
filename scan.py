import requests
import random
import multiprocessing
from concurrent import futures
import datetime
import json
import csv
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import codecs
from Wappalyzer.Wappalyzer import Wappalyzer, WebPage

requests.adapters.DEFAULT_RETRIES = 5
# 批量跑网站，输出cvs，里面包括域名，url，标题，http状态码，web指纹
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
    'Gecko/20100101 Firefox/68.0',
    'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0']

http_time_out = 60


def gen_fake_header():
    """
    生成伪造请求头
    """
    ua = random.choice(user_agents)
    headers = {
        'Accept': 'text/html,application/xhtml+xml,'
                  'application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Cache-Control': 'max-age=0',
        'Connection': 'close',
        'DNT': '1',
        'Referer': 'https://www.google.com/',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua
    }
    return headers


def get_title(markup):
    '''获取网页标题'''
    try:
        soup = BeautifulSoup(markup, 'lxml')
    except Exception as e:
        print(f"获取标题出错{e}")
        return None
    title = soup.title
    if title:
        return title.text.strip()
    h1 = soup.h1
    if h1:
        return h1.text.strip()
    h2 = soup.h2
    if h2:
        return h2.text.strip()
    h3 = soup.h3
    if h2:
        return h3.text.strip()
    desc = soup.find('meta', attrs={'name': 'description'})
    if desc:
        return desc['content'].strip()
    word = soup.find('meta', attrs={'name': 'keywords'})
    if word:
        return word['content'].strip()
    if len(markup) <= 200:
        return markup.strip()
    text = soup.text
    if len(text) <= 200:
        return text.strip()
    return None


def get_banner(response):
    # try:
    w = Wappalyzer.latest()
    webpage = WebPage.new_from_url(response)
    r = w.analyze(webpage)
    # banner = str({'Server': headers.get('Server'),
    #               'Via': headers.get('Via'),
    #               'X-Powered-By': headers.get('X-Powered-By')})
    banner = json.dumps(r, sort_keys=True, separators=(',', ':'))
    # except Exception as e:
    #     print(e)
    #     return None
    # print(banner)
    return banner


def check_http(sql_ports):
    '''HTTP服务探测'''
    url = f'{sql_ports}'
    headers = gen_fake_header()
    try:
        response = requests.get(url, timeout=http_time_out, verify=False, headers=headers)
    except requests.exceptions.Timeout:
        print(f'{sql_ports} 访问超时')
        return None
    except requests.exceptions.SSLError:
        st_sql_ports = urlparse(sql_ports).netloc
        url = f'https://{st_sql_ports}'
        print(url)
        try:
            response = requests.get(url, timeout=http_time_out, verify=False, headers=headers)
        except Exception as e:
            return None
        else:
            return response
    # 报错判断为没有加HTTP头
    except Exception as e:
        # sql_ports = urlparse(sql_ports).netloc
        url = f'http://{sql_ports}'
        try:
            response = requests.get(url, timeout=http_time_out, verify=False, headers=headers)
        # SSL错误，说明要HTTPS访问
        except requests.exceptions.SSLError:
            url = f'https://{sql_ports}'
            try:
                response = requests.get(url, timeout=http_time_out, verify=False, headers=headers)
            except Exception as e:
                return None
            else:
                return response
        except Exception as e:
            print(e)
            return None
        else:
            return response
    else:
        return response


requests.packages.urllib3.disable_warnings()


def action(task_url):
    res = check_http(task_url)
    try:
        task_domain = urlparse(task_url)
        res_title = ""
        fig = ""
        status_code = ""
        if res is None:
            res_url = task_url
        else:
            res.encoding = res.apparent_encoding
            task_domain = urlparse(res.url)
            res_url = res.url
            fig = get_banner(res)
            status_code = res.status_code
            res_title = get_title(markup=res.text)

        if res_title is None:
            res_title = ""
        csv_res = {
            '域名': task_domain.netloc,
            'url': res_url,
            '标题': res_title,
            'http状态码': status_code,
            'web指纹': fig
        }
        return csv_res

    except Exception as e:
        print(f'{task_url}出错\n错误原因:{e}')


def urlscan_main():
    print("""\033[32m
          _    _             _____           
| |  | |           /  ___|          
| |  | | __ _ _ __ \ `--.  ___  ___ 
| |/\| |/ _` | '_ \ `--. \/ _ \/ __|
\  /\  / (_| | |_) /\__/ /  __/ (__ 
 \/  \/ \__, | .__/\____/ \___|\___|
         __/ | |                    
        |___/|_|   

    快速HTTP检测工具 V0.1
    WgpSec Team
    www.wgpsec.org

    \033[0m
    """)
    print("请输入需要检测的txt地址，默认为domain.txt")
    paths = input("> ")
    if paths == "":
        paths = "domain.txt"
    process_name = multiprocessing.current_process().name
    print("扫描线程启动 " + process_name)
    # 开个100线程
    pool = futures.ThreadPoolExecutor(max_workers=100)
    task_list = []
    with open(paths, "r") as files:
        file_data = files.readlines()  # 读取文件
        for fi_s in file_data:
            fi_s = fi_s.strip('\n')
            task_list.append(fi_s)
    print(f"小弟读取到{len(task_list)}条网站，现在为大哥启动")
    wait_for = [pool.submit(action, task_url) for task_url in task_list]
    with open('%s-urlCheck.csv' % datetime.date.today(), 'a', newline='') as csvfile:
        # csvfile.write(codecs.BOM_UTF8)
        fieldnames = ['域名', 'url', '标题', 'http状态码', 'web指纹']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        # 注意header是个好东西
        writer.writeheader()
        for fs in futures.as_completed(wait_for):
            try:
                print(fs.result())
                writer.writerow(fs.result())
            except Exception as e:
                print(f'写入csv出错\n错误原因:{e}')
                pass


if __name__ == '__main__':
    urlscan_main()
