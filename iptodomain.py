import json
import time
import argparse
import sys
import urllib.request


parser = argparse.ArgumentParser(
    description='This tool allow to extract domains from  IP information on Virustotal and save the output in a file. You have to set up the IP range where you like to extract domain or subdomain. Additionally it is neccesary set up your VirusTotal API key in the code.')
parser.add_argument('-l', action="store", dest='FIRST_IP', help='The First IP of the range that you want to scan')
parser.add_argument('-k', action="store", dest='LAST_IP', help='The Last IP of the range that you want to scan.')
parser.add_argument('-f', action="store", dest='INPUT_FILE', help='Input file with IPs.')
parser.add_argument('-w', action="store", dest='File2',
                    help='Please enter the output file name, it will save a report with all domains and its IPs in .csv format')
parser.add_argument('-o', action="store", dest='File1',
                    help='Please enter the file name where the all IPs and domains found are going to save in txt format. ')
parser.add_argument('-v', action="store_false", dest='Verbose', default=True,
                    help='It shows  more information while you are scanning.')
parser.add_argument('-r', action="store", dest='File3',
                    help='Please enter the output file name, it will save a report without duplicate domains results')
args = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
argd = parser.parse_args()

args = vars(args)

if args['INPUT_FILE'] is None:

    if (args['FIRST_IP'] or args['LAST_IP']) is None:
        print ("Enter the input IP information example... 18.2.4.4")
        sys.exit()
    else:
        fi = args['FIRST_IP']
        li = args['LAST_IP']
        it = True
else:
    it = False
    inputfile = args['INPUT_FILE']




if argd.Verbose:
    cp = 'False'
else:
    cp = 'True'

f1 = ''
f2 = ''

if args['File1'] is None:
    if args['File2'] is None:
        print ("Enter -w or -o in orden to save the results in a file and no lose the progress if there is a problem")
        sys.exit()
    else:
        ctr = 1
        f2 = args['File2']
else:
    f1 = args['File1']
    ctr = 0
        
    

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


if (it == True):

   ip_range = ipRange(fi, li)
   

else:

   ip_range = []
   with open(inputfile) as my_file:
    for line in my_file:
        line= line.rstrip('\n')
        ip_range.append(str(line))
   


if ctr == 1:
            file2.write('IP'+','+'Domains' + '\n')


for ip in ip_range:
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': ip,
                  'apikey': 'aeead79c23a596d96bbc8e45a01c2d3b0d33e39ec9a2424b203835d88f318d04'}  # please enter your Virustotal API key, if you do not have one, it is a free API... sign up to Virustotal
    response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()


    print ('Scanning IP: ', ip)
    if cp =='True' :
        print (response)
    response_dict = json.loads(response)

    
        

    cod = (response_dict.get("response_code"))

    if cod == 1:
        u = (response_dict.get("resolutions"))

        i = len(u)
        
        if ctr == 1:
            file2.write(ip +  ',')
 
        while i > 0:
            i -= 1
            b = response_dict.get("resolutions")[i].get("hostname")
            s.append(b)
            m = list(set(s))
            print (b)

            if ctr == 1:

                file2.write(  b + '  ')
                                 

            elif ctr == 0:
                file1.write(ip + '    ' + b + '\n')
        
        if ctr == 1:
            file2.write  ('\n')   

    
    if cod == 0:
        if ctr == 1:
              file2.write(ip + ',' + '\n')

    time.sleep(15)

if oa:
    qw = 0
    owa = list(set(m))
    ot = len(owa) - 1
    while qw < ot:
        file3.write(m[qw] + '\n')
        qw += 1
