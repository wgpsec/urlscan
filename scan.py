#!/usr/bin/python3
# -*- coding: utf-8 -*-
# WgpSec Team
import csv
import datetime
import json
import multiprocessing
import random
import re
from concurrent import futures
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from lxml import etree

from Wappalyzer.Wappalyzer import Wappalyzer, WebPage
from wafw00f.main import main

requests.adapters.DEFAULT_RETRIES = 5
requests.packages.urllib3.disable_warnings()


class UrlScan(object):
    def __init__(self):
        self.version = "1.1"
        self.http_time_out = 60  # 配置HTTP请求超时时间
        self.pool_max_workers = 100  # 配置线程池
        self.url_list = []
        self.dict_url = []
        self.dir_result = []

    def main(self):
        self.get_show_banner()
        print('=' * 80)
        print(""" 1、URL存活探测，默认为domain 2、百度主域名收集 3、主域名收集+URL探测 """)
        print('=' * 80)
        choice = input(">")
        if choice == '1':
            self.get_url_list()
            self.url_scan()
        if choice == '2':
            self.get_dir_list()
            self.dir_scan()
            print(self.dir_result)
        if choice == '3':
            self.get_dir_list()
            self.dir_scan()
            print(self.dir_result)
            self.url_scan()

    def get_url_list(self):
        paths = "domain.txt"
        with open(paths, "r") as files:
            file_data = files.readlines()  # 读取文件
            for fi_s in file_data:
                fi_s = fi_s.strip('\n')
                self.url_list.append(fi_s)
        print(f"URL探测任务读取完毕，识别到 {len(self.url_list)} 条任务信息")

    def get_dir_list(self):
        paths = "keyword.txt"
        with open(paths, "r", encoding='utf-8', errors='ignore') as files:
            file_data = files.readlines()  # 读取文件
            for fi_s in file_data:
                fi_s = fi_s.strip('\n')
                self.dict_url.append(fi_s)
        print(f"关键词探测任务读取完毕，识别到 {len(self.dict_url)} 条任务信息")

    def dir_scan(self):
        process_name = multiprocessing.current_process().name
        print("【关键词线程启动】" + process_name)
        for task_url in self.dict_url:
            self.dir_scan_action(task_url)

    def dir_scan_action(self, task_keyword):
        print("【任务】" + task_keyword)
        baidu_url = "https://www.baidu.com/s?wd=" + str(task_keyword) + "&usm=3&rsv_idx=2&rsv_page=1"
        headers = self.gen_fake_header()
        edu_response_url = None
        try:
            response = requests.get(url=baidu_url, headers=headers, verify=False, timeout=30)
            re_html = etree.HTML(response.text)
            edu_url = re_html.xpath('//*[@id="1"]/h3/a[1]/@href')[0]
            edu_response_url = requests.get(url=edu_url, verify=False, headers=headers).url
            print(edu_response_url)
            try:
                edu_response = re.findall(r'www.(.*?)/', edu_response_url)[0]
            except:
                edu_response = urlparse(edu_response_url).netloc
        except:
            edu_response = "None"

        self.dir_result.append({
            "title": task_keyword,
            "domain": edu_response,
            "url": edu_response_url
        })
        self.url_list.append(edu_response_url)
        pass

    def url_scan(self):
        process_name = multiprocessing.current_process().name
        print("【URL扫描线程启动】" + process_name)
        pool = futures.ThreadPoolExecutor(max_workers=self.pool_max_workers)
        wait_for = [pool.submit(self.action, task_url) for task_url in self.url_list]
        with open('%s-urlCheck.csv' % datetime.date.today(), 'a', newline='') as csvfile:
            # csvfile.write(codecs.BOM_UTF8)
            fieldnames = ['域名', 'url', '标题', 'http状态码', 'web指纹', 'WAF']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            # 注意header是个好东西
            writer.writeheader()
            for fs in futures.as_completed(wait_for):
                try:
                    writer.writerow(fs.result())
                except Exception as e:
                    print(f'写入csv出错\n错误原因:{e}')
                    pass

    def get_show_banner(self):
        print("""\033[32m
         _       ____________  _____ ____________
        | |     / / ____/ __ \/ ___// ____/ ____/
        | | /| / / / __/ /_/ /\__ \/ __/ / /     
        | |/ |/ / /_/ / ____/___/ / /___/ /___   
        |__/|__/\____/_/    /____/_____/\____/
                                                
                快速HTTP检测工具 {}
                  WgpSec Team
                www.wgpsec.org
                \033[0m
                """.format(self.version))

    @staticmethod
    def gen_fake_header():
        """
        生成伪造请求头
        """
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
        ua = random.choice(user_agents)
        headers = {
            'Accept': 'text/html,application/xhtml+xml,'
                      'application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Cache-Control': 'max-age=0',
            'Connection': 'close',
            'DNT': '1',
            'Cookie': 'BIDUPSID=564f939a8f8a5befa67d62bdf79e6fa5; PSTM=1605847972; BAIDUID=d9e45923b4fb84761b608da331c2d66c:FG=1;',
            'Referer': 'https://www.baidu.com/',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': ua
        }
        return headers

    def get_title(self, markup):
        """
        获取网页标题
        """
        try:
            soup = BeautifulSoup(markup, 'lxml')
        except Exception as e:
            print(f"【无法获取标题】{e}")
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

    def get_banner(self, response):
        banner = None
        try:
            w = Wappalyzer.latest()
            webpage = WebPage.new_from_url(response)
            r = w.analyze(webpage)
            # banner = str({'Server': headers.get('Server'),
            #               'Via': headers.get('Via'),
            #               'X-Powered-By': headers.get('X-Powered-By')})
            banner = json.dumps(r, sort_keys=True, separators=(',', ':'))
        except Exception as e:
            print("【获取指纹信息失败】")
            print(e)
            return None
        return banner

    def check_http(self, sql_ports):
        '''HTTP服务探测'''
        url = f'{sql_ports}'
        # 随机获取一个Header头
        headers = self.gen_fake_header()
        try:
            response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
        except requests.exceptions.Timeout:
            print(f'{sql_ports} 无法访问【访问超时】')
            return None
        except requests.exceptions.SSLError:
            st_sql_ports = urlparse(sql_ports).netloc
            url = f'https://{st_sql_ports}'
            try:
                response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
            except Exception as e:
                return None
            else:
                return response
        # 报错判断为没有加HTTP头
        except Exception as e:
            print("【没有HTTP头，自动添加】" + url)
            # sql_ports = urlparse(sql_ports).netloc
            url = f'http://{sql_ports}'
            try:
                response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
            except requests.exceptions.Timeout:
                print(f'{sql_ports} 无法访问【访问超时】')
                return None
            # SSL错误，说明要HTTPS访问
            except requests.exceptions.SSLError:
                url = f'https://{sql_ports}'
                try:
                    response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
                except Exception as e:
                    return None
                else:
                    return response
            except Exception as e:
                url = f'https://{sql_ports}'
                try:
                    response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
                except Exception as e:
                    print("最终还是错误")
                    print(e)
                    return None
                else:
                    return response

            else:
                return response
        else:
            return response

    def action(self, task_url):
        res = self.check_http(task_url)
        try:
            task_domain = urlparse(task_url)
            print("【任务URL】" + task_url)
            res_title = ""
            fig = ""
            status_code = ""
            waf = ""
            if res is None:
                res_url = task_url
            else:
                res.encoding = res.apparent_encoding
                task_domain = urlparse(res.url)
                res_url = res.url
                fig = self.get_banner(res)
                status_code = res.status_code
                res_title = self.get_title(markup=res.text)
                flag, waf = main(res_url)
                if not flag:
                    waf = ''

            if res_title is None:
                res_title = ""

            csv_res = {
                '域名': task_domain.netloc,
                'url': res_url,
                '标题': res_title,
                'http状态码': status_code,
                'web指纹': fig,
                'WAF': waf
            }
            print(csv_res)
            return csv_res

        except Exception as e:
            print(f'{task_url}出错\n错误原因:{e}')


if __name__ == '__main__':
    Scan = UrlScan()
    Scan.main()
