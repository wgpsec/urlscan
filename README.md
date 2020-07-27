# 快速HTTP检测工具 V0.2

环境 python3

本项目为 plat.wgpsec.org 狼组信息化平台部分功能开源项目

使用前 `pip install -r requirements.txt`

使用方法 ： `python scan.py`  根据提示输入域名文件路径

在目录下会生成 当前日期urlCheck.csv 文件，包含 域名，url，标题，http状态码，web指纹，WAF信息

可以写定时任务，定期探测URL存活情况，方便发现监控

```
www.wgpsec.org,https://www.wgpsec.org/,,200,"[{""icon"":""CloudFlare.svg"",""name"":""CloudFlare"",""version"":"""",""website"":""http://www.cloudflare.com""},{""icon"":""Nginx.svg"",""name"":""Nginx"",""version"":"""",""website"":""http://nginx.org/en""}]"
www.baidu.com,https://www.baidu.com/,百度一下，你就知道,200,[]
```

www.wgpsec.org

WgpSec Team


# 更新日志

v0.2 支持WAF识别