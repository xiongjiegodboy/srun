import requests
import time
import re
import os
from encryption.srun_md5 import *
from encryption.srun_sha1 import *
from encryption.srun_base64 import *
from encryption.srun_xencode import *
header={
	'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
}
init_url="http://10.1.2.1/"
get_challenge_api="http://10.1.2.1//cgi-bin/get_challenge"

srun_portal_api="http://10.1.2.1//cgi-bin/srun_portal"
n = '200'
type = '1'
ac_id='2'
enc = "srun_bx1"
def get_chksum():
	chkstr = token+username
	chkstr += token+hmd5
	chkstr += token+ac_id
	chkstr += token+ip
	chkstr += token+n
	chkstr += token+type
	chkstr += token+i
	return chkstr
def get_info():
	info_temp={
		"username":username,
		"password":password,
		"ip":ip,
		"acid":ac_id,
		"enc_ver":enc
	}
	i=re.sub("'",'"',str(info_temp))
	i=re.sub(" ",'',i)
	return i
def init_getip():
	global ip
	init_res=requests.get(init_url,headers=header)
	# print("初始化获取ip")
	ip=re.search('id="user_ip" value="(.*?)"',init_res.text).group(1)
	# print("ip:"+ip)
def get_token():
	# print("获取token")
	global token
	get_challenge_params={
		"callback": "jQuery112404953340710317169_"+str(int(time.time()*1000)),
		"username":username,
		"ip":ip,
		"_":int(time.time()*1000),
	}
	get_challenge_res=requests.get(get_challenge_api,params=get_challenge_params,headers=header)
	token=re.search('"challenge":"(.*?)"',get_challenge_res.text).group(1)
	# print(get_challenge_res.text)
	# print("token为:"+token)
def do_complex_work():
	global i,hmd5,chksum
	i=get_info()
	i="{SRBX1}"+get_base64(get_xencode(i,token))
	hmd5=get_md5(password,token)
	chksum=get_sha1(get_chksum())
	# print("所有加密工作已完成")
def login():
	srun_portal_params={
	'callback': 'jQuery11240645308969735664_'+str(int(time.time()*1000)),
	'action':'login',
	'username':username,
	'password':'{MD5}'+hmd5,
	'ac_id':ac_id,
	'ip':ip,
	'chksum':chksum,
	'info':i,
	'n':n,
	'type':type,
	'os':'windows+10',
	'name':'windows',
	'double_stack':'0',
	'_':int(time.time()*1000)
	}
	# print(srun_portal_params)
	srun_portal_res=requests.get(srun_portal_api,params=srun_portal_params,headers=header)
	# print(srun_portal_res.text)
	data = srun_portal_res.text
	data1 = re.findall(r'"error":"(.*?)"', data)
	if data1 and data1[0] != "login_error":
		with open(fr"{os.getcwd()}\username.txt", "a") as f:
			f.write(username + "\n")
		print(username, "√")
	else:
		print(username, "x")

if __name__ == '__main__':
    # 尝试从文件中读取用户名和密码
    try:
        with open('credentials.txt', 'r') as file:
            credentials = file.read().splitlines()
            username = credentials[0].split(': ')[1]
            password = credentials[1].split(': ')[1]
    except FileNotFoundError:
        # 如果文件不存在或者读取出错，则提示用户输入用户名和密码
        username = input("请输入用户名: ")
        password = input("请输入密码: ")
        # 保存用户名和密码到文件
        with open('credentials.txt', 'w') as file:
            file.write(f"Username: {username}\nPassword: {password}")

    init_getip()
    get_token()
    do_complex_work()
    login()
