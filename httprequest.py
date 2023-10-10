# coding=utf-8
'''获取http请求'''
from scapy.all import *
import scapy_http.http as http
import re
import json
import codecs
from util import black
from util import parseutil


class HttpRequest:

    # 两种情况  1.pcap文件  2.开测上内层数据包  3.过滤规则文件
    def http_request_filter(self, file_name, pkts=[], filter_rule_list=[],uafilter=False):
        # 如果不是开测数据，读取pcap文件
        if not pkts:
            pkts = rdpcap(file_name)
        file_path = os.path.basename(file_name)
        file_path = (".").join(file_path.split(".")[:-1])
        app_path = file_path.decode("gbk").encode("utf-8")
        no = 0  # 包序号
        ack_dict = {}
        feature_dict = {}
        used_no_list = []
        for pkt in pkts:
            if pkt.haslayer('TCP'):
                curr_ack = pkt['TCP'].ack
                var = ack_dict.get(curr_ack)
                if var:
                    var.append(no)
                    ack_dict.update({curr_ack: var})
                else:
                    ack_dict.update({curr_ack: [no]})
            no = no + 1
        #print len(ack_dict)
        for index_list in ack_dict.values():
            content = ""
            for i in index_list:
                if pkts[i].haslayer(http.HTTPResponse):
                    used_no_list.append(i)
                    continue
                if pkts[i].haslayer(http.HTTPRequest):
                    # 将所有用过的包都记录下来
                    used_no_list.append(i)
                    http_header = pkts[i][http.HTTPRequest].fields
                    host = http_header.get('Host', "")
                    is_black = parseutil.judge_host_in_black(host)
                    if is_black:
                        break
                    path = http_header.get('Path', "")
                    tmpstr = "http://" + host
                    path = path.split(tmpstr)[-1]
                    url = self.parse_url(path)
                    # 获取User-Agent
                    user_agent = parseutil.filter_ua(http_header.get('User-Agent', ""))
                    appid, msg, app_type = parseutil.generate_appid_for_feature(app_path)
                    json_dict = {"appid":appid,"type":2,"class_type":app_type,"msg":msg,"keystr":"","ua":user_agent, "flags": 0, "qos_type": "0"}
                    keystr = ""
                    if url:
                        is_ip = self.judge_host_is_ip(host)
                        if not is_ip:
                            #如果是生成ua规则，只需要域名
                            if uafilter:
                                keystr = host
                            else:
                                keystr = host + "/" + url

                            json_dict.update({"keystr": keystr})
                        else:
                            if uafilter:
                                keystr = "/"
                            else:
                                keystr = "/" + url
                            json_dict.update({"keystr": keystr})
                    else:
                        is_ip = self.judge_host_is_ip(host)
                        if not is_ip:
                            keystr = host
                            json_dict.update({"keystr": host})
                        else:
                            continue
                    # 过滤掉规则文件中的http请求，如果keystr和ua相同
                    keystr_and_ua = str(keystr) + str(user_agent)
                    if keystr_and_ua in filter_rule_list:
                        continue
                    # 过滤keystr是空的
                    if keystr == "":
                        continue
                    value = json_dict
                    ua_similar = False
                    samecontent = None
                    samecontenlen = None
                    if uafilter:
                        if user_agent:
                            key = str(user_agent)
                        else:
                            key = "null"
                        #if key in feature_dict.keys():
                        for s in feature_dict.keys():
                            if key in s or key.find(s)>=0:
                                key = s
                                ua_similar = True
                        if ua_similar:
                            feature_map = feature_dict.get(key)
                            count = feature_map.values()[0]
                            count.append(i)
                            tmpvar = eval(feature_map.keys()[0])
                            if value not in tmpvar:
                                tmpvar.append(value)
                            tmpvar = str(tmpvar)
                            feature_dict.update({key: {tmpvar: count}})
                        else:
                            feature_dict.update({key: {str([value]): [i]}})
                        break
                    else:
                        if host:
                            key = str(host)
                        else:
                            key = "null"
                        if key in feature_dict.keys():
                            feature_map = feature_dict.get(key)
                            count = feature_map.values()[0]
                            count.append(i)
                            tmpvar = eval(feature_map.keys()[0])
                            if value not in tmpvar:
                                tmpvar.append(value)
                            # tmpvar.append(value)
                            tmpvar = str(tmpvar)
                            # feature_dict.update({key: {tmpvar: count}})
                            feature_dict.update({key: {tmpvar: count}})
                        else:
                            # feature_dict.update({key: {str([value]): 1}})
                            feature_dict.update({key: {str([value]): [i]}})
                        break
                else:
                    if pkts[i].haslayer('Raw'):
                        tmpstr = pkts[i]['Raw'].load
                        content += pkts[i]['Raw'].load
                        if content.find('HTTP') >= 0:
                            used_no_list.append(i)
                        if (tmpstr.find('POST') >= 0) or (tmpstr.find('GET') >= 0) or (tmpstr.find('CONNECT') >= 0):
                            used_no_list.append(i)
            if (content.find('POST') < 0) and (content.find('GET') < 0) and (content.find('CONNECT') < 0):
                # 不是http请求
                continue

            if content:
                contents = content.split("\r\n")
                url = ""
                host = ""
                for line in contents:
                    if line.find("Host") >= 0:
                        ls = line.split("Host:")
                        host = ls[-1].strip()
                        host = host.split(":")[0].strip()
                        break
                is_black = parseutil.judge_host_in_black(host)
                if is_black:
                    continue
                for line in contents:
                    if (line.find('POST') >= 0) or (line.find('GET') >= 0):
                        ls = re.split("'POST'|'GET'", line)
                        line = ls[-1]
                        tmpstr = "http://" + host
                        line = line.split(tmpstr)[-1]
                        url = self.parse_url(line)
                        break
                user_agent = ""
                for line in contents:
                    if line.find("User-Agent") >= 0:
                        ls = line.split("User-Agent:")
                        user_agent = ls[-1].strip()
                        break
                user_agent = parseutil.filter_ua(user_agent)
                appid, msg, app_type = parseutil.generate_appid_for_feature(app_path)
                # ruleid = parseutil.generate_ruleid_of_feature()
                json_dict = {"appid": appid, "type": 2, "class_type": app_type, "msg": msg, "keystr": "", "ua": user_agent, "flags": 0,"qos_type": "0"}
                keystr = ""
                if url:
                    is_ip = self.judge_host_is_ip(host)
                    if not is_ip:
                        if uafilter:
                            keystr = host
                        else:
                            keystr = host + url
                        json_dict.update({"keystr": keystr})
                    else:
                        if uafilter:
                            keystr = "/"
                        else:
                            keystr = "/" + url
                        json_dict.update({"keystr": keystr})
                else:
                    is_ip = self.judge_host_is_ip(host)
                    if not is_ip:
                        keystr = host
                        json_dict.update({"keystr": host})
                    else:
                        continue
                # 过滤规则文件中的http请求
                keystr_and_ua = keystr + user_agent
                if keystr_and_ua in filter_rule_list:
                    continue
                # 过滤keystr是空的
                if keystr == "":
                    continue
                value = json_dict
                if uafilter:
                    if user_agent:
                        key = str(user_agent)
                    else:
                        key = "null"
                    if key in feature_dict.keys():
                        feature_map = feature_dict.get(key)
                        count = feature_map.values()[0]
                        count.append(i)
                        tmpvar = eval(feature_map.keys()[0])
                        if value not in tmpvar:
                            tmpvar.append(value)
                        tmpvar = str(tmpvar)
                        feature_dict.update({key: {tmpvar: count}})
                    else:
                        feature_dict.update({key: {str([value]): [i]}})
                else:
                    if host:
                        key = str(host)
                    else:
                        key = "null"
                    if key in feature_dict.keys():
                        feature_map = feature_dict.get(key)
                        count = feature_map.values()[0]
                        count.append(i)
                        tmpvar = eval(feature_map.keys()[0])
                        if value not in tmpvar:
                            tmpvar.append(value)
                        tmpvar = str(tmpvar)
                        feature_dict.update({key: {tmpvar: count}})
                    else:
                        feature_dict.update({key: {str([value]): [i]}})


        return feature_dict, used_no_list

    def judge_host_is_ip(self, host):
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if p.match(host):
            return True
        else:
            return False


    def parse_url(self, line):
        line = line.strip()
        ls = line.split("/")
        line = line.replace(" HTTP", "")
        line = line.replace(" HTTP/1.1", "")
        # 说明路径只有一个/
        if len(ls) == 2:
            url = ls[1]
        else:
            l = re.split("/", line)
            url = ("/").join(l[1:3])
            #过滤掉一些url中的无效字段
            url = self.filter_url_noise(url)
        return url
    def filter_url_noise(self, url):
        filter_list = black.NOISEURL
        for noise in filter_list:
            pattern = re.compile(noise)
            url = pattern.sub("", url).strip()
        return url

if __name__ == '__main__':
    print 'test'

    before_ruleid = 16777217
    demo = HttpRequest()
    pcap_name = '今日头条_3.pcap'.decode("utf-8").encode("gbk")
    pcap_name = os.path.join("pcap", pcap_name)
    pkts = rdpcap(pcap_name)
    file_path = os.path.basename(pcap_name)
    file_path = (".").join(file_path.split(".")[:-1])
    app_path = file_path.decode("gbk").encode("utf-8")
    appid, msg, app_type = parseutil.generate_appid_for_feature(app_path)
    filter_rule_list = parseutil.get_pass_rule(appid,"http")
    features, pkt_no_list = demo.http_request_filter(pcap_name, filter_rule_list=filter_rule_list)
    #print "排重后.............".decode("utf-8").encode("gbk")
    tmp_path = os.path.basename(pcap_name)
    tmpstr = tmp_path.split(".")[0]
    file_name = "http" + "_" + tmpstr
    file_name = os.path.join("result", file_name)
    if os.path.exists(file_name):
        os.remove(file_name)
    feature_map = {}
    for key, value in features.items():
        feature_map.update(value)
    feature_map = sorted(feature_map.items(), key=lambda x: len(x[1]), reverse=True)
    for f in feature_map:
        #过滤掉只出现过一次的请求
        if len(f[1]) <= 1:
            continue
        v_list = eval(f[0])
        for idx, v in enumerate(v_list):
            ordered_dict = collections.OrderedDict()
            sorted_list = sorted(list(v))
            for l in sorted_list:
                ordered_dict[l] = v.get(l)
            ruleid = parseutil.generate_ruleid_of_feature(before_ruleid)
            before_ruleid = ruleid
            ordered_dict['ruleid'] = ruleid
            try:
                jstr = json.dumps(ordered_dict, separators=(',', ':'), encoding="UTF-8", ensure_ascii=False)
                with codecs.open(file_name, 'a', 'utf-8') as tf:
                    tf.write(jstr + "\n")
                if idx == len(v_list) - 1:
                    with codecs.open(file_name, 'a', 'utf-8') as tf:
                        tf.write("#num:" + str(len(f[1])) + "\n")
                        #tf.write("#no:" + str(f[1]) + "\n")
            except:
                pass
    with codecs.open(file_name, 'a', 'utf-8') as tf:
        tf.write("################rules  by  ua#################### " + "\n")
    features, pkt_no_list = demo.http_request_filter(pcap_name, filter_rule_list=filter_rule_list,uafilter=True)
    #print "排重后.............".decode("utf-8").encode("gbk")
    tmp_path = os.path.basename(pcap_name)
    tmpstr = tmp_path.split(".")[0]
    feature_map = {}
    for key, value in features.items():
        feature_map.update(value)
    feature_map = sorted(feature_map.items(), key=lambda x: len(x[1]), reverse=True)
    for f in feature_map:
        #过滤掉只出现过一次的请求
        if len(f[1]) <= 4:
            continue
        v_list = eval(f[0])
        for idx, v in enumerate(v_list):
            ordered_dict = collections.OrderedDict()
            sorted_list = sorted(list(v))
            for l in sorted_list:
                ordered_dict[l] = v.get(l)
            ruleid = parseutil.generate_ruleid_of_feature(before_ruleid)
            before_ruleid = ruleid
            ordered_dict['ruleid'] = ruleid
            try:
                jstr = json.dumps(ordered_dict, separators=(',', ':'), encoding="UTF-8", ensure_ascii=False)
                with codecs.open(file_name, 'a', 'utf-8') as tf:
                    tf.write(jstr + "\n")
                if idx == len(v_list) - 1:
                    with codecs.open(file_name, 'a', 'utf-8') as tf:
                        tf.write("#num:" + str(len(f[1])) + "\n")
                        #tf.write("#no:" + str(f[1]) + "\n")
            except:
                pass
    print "http请求处理完成:".decode("utf-8").encode("gbk")

