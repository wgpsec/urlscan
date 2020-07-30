<h1 align="center">UrlScan 🛠</h1>

<p>
  <img src="https://img.shields.io/badge/Language-Python3-blue" />
  <img src="https://img.shields.io/badge/Version-0.2-blue" />
  <img src="https://img.shields.io/badge/Dependence-Wappalyzer+Wafw00f-green" />
</p>

## 背景

本项目为 [狼组信息化平台](https://plat.wgpsec.org) 部分功能开源项目

## 快速使用

1. 安装依赖
   
   `pip install -r requirements.txt`

2. 运行使用
   
   `python scan.py`
   
   运行后无报错则需要根据提示输入待检测的域名文件路径

   接着会在当前目录下会生成以 `当前日期+urlCheck.csv` 为文件名的Excel文件，文件内容包含 域名，url，标题，http状态码，web指纹，WAF信息

   > 可以写定时任务，定期探测URL存活情况，方便发现监控

    运行结果 e.g：
    ```
    www.wgpsec.org,https://www.wgpsec.org/,,200,"[{""icon"":""CloudFlare.svg"",""name"":""CloudFlare"",""version"":"""",""website"":""http://www.cloudflare.com""},{""icon"":""Nginx.svg"",""name"":""Nginx"",""version"":"""",""website"":""http://nginx.org/en""}]"
    www.baidu.com,https://www.baidu.com/,百度一下，你就知道,200,[]
    ```

## 更新日志

 - **v0.2** [2020-06-23]
   - 支持WAF识别

## 免责声明

**不能使用该工具进行非法活动，下载该工具就表示同意此条款，造成的一切后果与作者无关！！**