import json
import urllib
import time
import argparse
import sys

parser = argparse.ArgumentParser(
    description='This tool allow to extract domains from  IP information on Virustotal and save the output in a file. You have to set up the IP range where you like to extract domain or subdomain. Additionally it is neccesary set up your VirusTotal API key in the code.')
parser.add_argument('-i', action="store", dest='FIRST_IP', help='The First IP of the range that you want to scan')
parser.add_argument('-f', action="store", dest='LAST_IP', help='The Last IP of the range that you want to scan.')
parser.add_argument('-w', action="store", dest='File2',
                    help='Please enter the file name where report with all domains and its IPs are going to save.')
parser.add_argument('-o', action="store", dest='File1',
                    help='Please enter the file name where the all domains found are going to save. ')
parser.add_argument('-v', action="store_false", dest='Verbose', default=True,
                    help='It shows  more information while you are scanning.')
parser.add_argument('-r', action="store", dest='File3',
                    help='Please enter the name of the final Report without duplicate domains results')
args = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
argd = parser.parse_args()

args = vars(args)

if args['FIRST_IP'] is None:
    print "Enter the IP information example... 18.2.4.4"
    sys.exit()
else:
    fi = args['FIRST_IP']

if args['LAST_IP'] is None:
    print "Enter the IP information example... 18.2.4.10"
    sys.exit()
else:
    li = args['LAST_IP']

if argd.Verbose:
    cp = 'False'
else:
    cp = 'True'

f1 = ''
f2 = ''

if args['File1'] is None:
    if args['File2'] is None:
        print "Enter -w or -o in orden to save the results in a file and no lose the progress if there is a problem"
        sys.exit()
    else:
        ctr = 1
        f2 = args['File2']
else:
    f1 = args['File1']
    if args['File2'] is None:
        ctr = 0
    else:
        ctr = 2
        f2 = args['File2']

oa = False
if args['File3'] is not None:
    f3 = args['File3']
    oa = True


def ipRange(start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_ange = [start_ip]

    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i - 1] += 1
        ip_ange.append(".".join(map(str, temp)))

    return ip_ange


if f1 != '':
    file1 = open(f1, "a")

if f2 != '':
    file2 = open(f2, "a")

if oa:
    file3 = open(f3, "w")

s = list()
ok = 0
ip_range = ipRange(fi, li)

for ip in ip_range:
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': ip,
                  'apikey': '3c052e9a7339f3a73f00bd67baea747e47f59ee6c1596e59590fd953d00ce519'}  # please enter your Virustotal API key, if you do not have one, there is a free API... sign up to Virustotal
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)

    if cp == 'True':
        print 'Scanning IP: ', ip

    cod = (response_dict.get("response_code"))

    if cod == 1:
        u = (response_dict.get("resolutions"))

        i = len(u)

        while i > 0:
            i -= 1
            b = response_dict.get("resolutions")[i].get("hostname")
            s.append(b)
            m = list(set(s))
            print b

            if ctr == 2:

                file2.write(ip + '    ' + b + '\n')
                file1.write(b + '\n')

            elif ctr == 1:
                file2.write(ip + '    ' + b + '\n')

            else:
                file1.write(b + '\n')

    time.sleep(15)

if oa:
    qw = 0
    owa = list(set(m))
    ot = len(owa) - 1
    while qw < ot:
        file3.write(m[qw] + '\n')
        qw += 1
