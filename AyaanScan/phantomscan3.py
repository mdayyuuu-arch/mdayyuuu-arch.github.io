import time,socket,urllib.request,json,threading
from datetime import datetime
RED='\033[91m';GREEN='\033[92m';YELLOW='\033[93m';BLUE='\033[94m';BOLD='\033[1m';RESET='\033[0m'
print(f"PHANTOMSCAN v3.0{RESET}\n{GREEN}Mohammed Ayaan | Bug Hunter | India{RESET}\n")
findings=[];lock=threading.Lock()
def scan_port(host,port,name):
 try:
  with socket.socket() as s:
   s.settimeout(1)
   if s.connect_ex((host,port))==0:
    msg=f"OPEN: Port {port} ({name})"
    with lock:print(f"{GREEN}✅ {msg}{RESET}");findings.append(msg)
 except:pass
def scan_ports(host):
 print(f"\n{BLUE}[PORT SCAN]{RESET}")
 services={80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",53:"DNS",8080:"ALT",3306:"MySQL"}
 ts=[threading.Thread(target=scan_port,args=(host,p,n)) for p,n in services.items()]
 for t in ts:t.start()
 for t in ts:t.join()
def find_subdomains(host):
 print(f"\n{BLUE}[SUBDOMAINS]{RESET}")
 subs=["www","mail","admin","api","dev","test","app","staging","beta","login","dashboard"]
 def chk(s):
  try:ip=socket.gethostbyname(f"{s}.{host}");print(f"{GREEN}FOUND: {s}.{host} -> {ip}{RESET}");findings.append(f"FOUND: {s}.{host}")
  except:pass
 ts=[threading.Thread(target=chk,args=(s,)) for s in subs]
 for t in ts:t.start()
 for t in ts:t.join()
def ip_lookup(host):
 print(f"\n{BLUE}[IP LOOKUP]{RESET}")
 try:
  ip=socket.gethostbyname(host)
  r=urllib.request.urlopen(f"http://ip-api.com/json/{ip}")
  d=json.loads(r.read())
  for line in[f"IP: {ip}",f"Country: {d['country']}",f"City: {d['city']}",f"ISP: {d['isp']}"]:
   print(f"{YELLOW}{line}{RESET}");findings.append(line)
 except:print(f"{RED}Failed{RESET}")
def vuln_check(host):
 print(f"\n{BLUE}[VULN CHECK]{RESET}")
 try:
  r=urllib.request.urlopen(f"http://{host}",timeout=3);h=dict(r.headers)
  for hdr,msg in{"X-Frame-Options":"Clickjacking","X-XSS-Protection":"XSS not blocked","Strict-Transport-Security":"HSTS missing","Content-Security-Policy":"CSP missing"}.items():
   if hdr not in h:print(f"{RED}VULN: {msg}{RESET}");findings.append(f"VULN: {msg}")
   else:print(f"{GREEN}SAFE: {hdr}{RESET}")
 except:pass
start=time.time()
host=input("Enter target: ")
scan_ports(host);find_subdomains(host);ip_lookup(host);vuln_check(host)
elapsed=round(time.time()-start,2)
open(f"{host.replace('.','_')}_report.txt","w").write(f"AyaanScan v3.0\nTarget:{host}\n"+"\n".join(findings))
print(f"\n{GREEN}Findings: {len(findings)} | Time: {elapsed}s{RESET}")
print(f"{BOLD}{GREEN}AyaanScan Complete! By Mohammed Ayaan{RESET}")
