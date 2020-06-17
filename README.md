# 快速HTTP检测工具 V0.1

环境 python3

使用前 `pip install -r requirements.txt`

使用方法 ： `python scan.py`  根据提示输入域名文件路径

在目录下会生成csv文件，包含 域名，url，标题，http状态码，web指纹
```
www.wgpsec.org,https://www.wgpsec.org/,,200,"[{""icon"":""CloudFlare.svg"",""name"":""CloudFlare"",""version"":"""",""website"":""http://www.cloudflare.com""},{""icon"":""Nginx.svg"",""name"":""Nginx"",""version"":"""",""website"":""http://nginx.org/en""}]"
www.baidu.com,https://www.baidu.com/,百度一下，你就知道,200,[]
```

www.wgpsec.org

WgpSec Team