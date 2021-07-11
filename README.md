# iptodomain V2
<img src="https://cloud.githubusercontent.com/assets/6917066/21866468/6590ab3a-d818-11e6-89f7-609e2d8f1171.jpg" alt="iptodomain" height="228" width="504">



<b>Update V2 :It was migrated from python 2.7 to 3.8.10. Now It supports an input file and csv output file.</b>


Description:

This tool allows you to extract domains from a IP range, using the historic information archived in Virustotal(using API key). It is usefull if you want to know what domains are behind of this IP address, for example in bug bounty programs one of the first steps is to extract subdomains, this tool can help with this task... first you have to find out the IP range that uses a company OR you can provide a file with the IP list. Many times a good start point is to know the AS (Autonomus system) number, then you can find the IP range.


To use this tool you have to set up your Virustotal API key in the code, please sign up on Virustotal then they provide you the API key or use my testing API key.


Example:

<pre>
  <code>

python3 iptodomain3.py -f ips.txt  -w output.csv -v

python3 iptodomain.py -l 103.22.201.25 -k 103.22.201.255 -o result.txt

</code>
</pre>


Usage:

<pre>
  <code>

python3 iptodomain.py 


usage: iptodomain.py [-h] [-l FIRST_IP] [-k LAST_IP] [-f INPUT_FILE] [-w FILE2] [-o FILE1] [-v] [-r FILE3]

  -h, --help     show this help message and exit
  
  -l FIRST_IP    The First IP of the range that you want to scan
  
  -k LAST_IP     The Last IP of the range that you want to scan.
  
  -f INPUT_FILE  Input file with IPs.
  
  -w FILE2       Please enter the output file name, it will save a report with all domains and its IPs in .csv format
  
  -o FILE1       Please enter the file name where the all IPs and domains found are going to save in txt format.
  
  -v             It shows more information while you are scanning.
  
  -r FILE3       Please enter the output file name, it will save a report without duplicate domains results
  

This tool allow to extract domains from IP information on Virustotal and save
the output in a file(txt, csv). You have to set up the IP range where you like to
extract domain or subdomain or provide an IP list. Additionally it is neccesary set up your
VirusTotal API key in the code.

</code>
</pre>
  
  This tool was created by:
  
  Juan Esteban Valencia Pantoja
