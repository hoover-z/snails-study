#这是一个py扫描xss漏洞的小脚本

import requests
# HTML转实体字符
def str_html(source):
    result = ''
    for c in source:
        result += "&#x" + hex(ord(c)) + ";"
    return result.replace('0x', '')
# 判断响应的构成
def check_resp(response, payload, type):
    index = response.find(payload)
    prefix = response[index-2:index-1]
    if type == 'Normal' and prefix != '=' and index >= 0:
        return True
    elif type == 'Prop' and prefix == '=' and index >= 0:
        return True
    elif type == 'Escape':
        index = response.find(str_html(payload))
        prefix = response[index-2:index-1]
        if prefix == '=' and str_html(payload) in response:
            return True
    elif index >= 0:
        return True
    return False
# 基于GET请求实现XSS扫描
def xss_scan(location):
    #分割，取出来地址和参数
    url = location.split('?')[0]
    param_list = location.split('?')[1].split('&')
    #读取字典
    with open('./xss-payload.txt') as file:
        payload_list = file.readlines()
    #对字典进行遍历分割取值
    for payload in payload_list:
        type = payload.strip().split(':', 1)[0]
        payload = payload.strip().split(':', 1)[1]
        if type == 'Referer' or type == 'User-Agent' or type == 'Cookie':
            header = {type: payload}
            resp = requests.get(url=url, headers=header)
        elif type == 'Escape':
            params = {}
            for param in param_list:
                key = param.split("=")[0]
                params[key] = str_html(payload)
            resp = requests.get(url=url, params=params)
        else:
            params = {}
            for param in param_list:
                key = param.split("=")[0]
                params[key] = payload
            resp = requests.get(url=url, params=params)
        if check_resp(resp.text, payload, type):
            print(f"存在XSS漏洞：Payload为：{payload}" )
if __name__ == '__main__':
    xss_scan('http://106.13.21.245/xss-labs-master/level1.php?name=test')
    # xss_scan('http://106.13.21.245/xss-labs-master/level1.php?name=test')
    # xss_scan('http://106.13.21.245/xss-labs-master/level2.php?keyword=test')
    # xss_scan('http://106.13.21.245/xss-labs-master/level3.php?keyword=test')
    # xss_scan('http://106.13.21.245/xss-labs-master/level4.php?keyword=test')
    # xss_scan('http://106.13.21.245/xss-labs-master/level5.php?keyword=test')
    # xss_scan('http://106.13.21.245/xss-labs-master/level11.php?keyword=test')
    # xss_scan('http://106.13.21.245/xss-labs-master/level17.php?arg01=a&arg02=b')


    #normal类别，就是不能作为属性存在的，而是要单独拎出来的
    #normal判断，前边的第二个位置一定不太可能是等号
