import os, json, hashlib, subprocess, uuid, ipaddress, datetime, pathlib, threading
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

app = FastAPI(title='Nexora VulnScan API', version='0.1.0')
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in os.getenv('FRONTEND_ORIGINS','http://localhost:3000').split(',') if x.strip()], allow_methods=['GET','POST'], allow_headers=['Authorization','Content-Type'])
DATA = pathlib.Path(os.getenv('DATA_DIR', './data')); DATA.mkdir(parents=True, exist_ok=True)
LOCK = threading.Lock()
PORTS = '21,22,25,53,80,110,143,443,445,3306,5432,6379,8080,8443'

class ScanRequest(BaseModel):
    target: str
    consent: bool


def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(v): return hashlib.sha256(canonical(v)).hexdigest()
def api_auth(authorization):
    key = os.getenv('SCAN_API_KEY','')
    if not key or authorization != 'Bearer '+key:
        raise HTTPException(401,'Invalid API key')

def allowed_target(value):
    try:
        addr=ipaddress.ip_address(value)
        if addr.version != 4: raise ValueError('Only IPv4 supported in MVP')
    except ValueError:
        raise HTTPException(400,'Enter a single IPv4 address (no hostnames, URLs, or ranges)')
    allow=[v.strip() for v in os.getenv('ALLOWED_TARGETS','127.0.0.1').split(',') if v.strip()]
    if value not in allow: raise HTTPException(403,'This target is not on the server-side authorized allowlist')
    return value

def save_report(report):
    body={k:v for k,v in report.items() if k!='sha256'}
    report['sha256']=digest(body)
    path=DATA/(report['id']+'.json')
    path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report

def read_report(identifier):
    try: uuid.UUID(identifier)
    except ValueError: raise HTTPException(400,'Invalid scan ID')
    path=DATA/(identifier+'.json')
    if not path.exists(): raise HTTPException(404,'Scan not found')
    report=json.loads(path.read_text(encoding='utf-8'))
    expected=report.get('sha256')
    verified=(expected==digest({k:v for k,v in report.items() if k!='sha256'}))
    return {**report,'integrity_verified':verified}

@app.get('/health')
def health(): return {'status':'ok','timestamp':now()}

@app.post('/scans')
async def scan(req:ScanRequest,authorization:str|None=Header(default=None)):
    api_auth(authorization)
    if not req.consent: raise HTTPException(400,'You must confirm authorization before scanning')
    target=allowed_target(req.target)
    with LOCK:
        report={'id':str(uuid.uuid4()),'target':target,'created_at':now(),'status':'completed','services':[],'findings':[],'events':[]}
        def event(label,details=''):
            prev=report['events'][-1]['entry_sha256'] if report['events'] else '0'*64
            entry={'timestamp':now(),'event':label,'details':details,'previous_sha256':prev}
            entry['entry_sha256']=digest(entry)
            report['events'].append(entry)
        event('scan.started','Authorized IP confirmed against server allowlist')
        try:
            # Fixed, bounded non-script TCP connect scan. No user-supplied flags.
            proc=subprocess.run(['nmap','-sT','-sV','--version-light','-Pn','-T2','--max-retries','1','-p',PORTS,'-oX','-',target],capture_output=True,text=True,timeout=100,check=False)
            if proc.returncode != 0: raise RuntimeError(proc.stderr.strip()[:300] or 'Nmap exited with an error')
            root=ET.fromstring(proc.stdout)
            for port in root.findall('.//port'):
                state=port.find('state')
                if state is None or state.get('state')!='open': continue
                service=port.find('service')
                report['services'].append({'port':int(port.get('portid')),'protocol':port.get('protocol'),'service':service.get('name','unknown') if service is not None else 'unknown','product':service.get('product','') if service is not None else '', 'version':service.get('version','') if service is not None else ''})
            event('nmap.completed',f"{len(report['services'])} open ports discovered")
            for svc in report['services']:
                p=svc['port']
                if p in (21,23,445,6379,3306,5432):
                    report['findings'].append({'title':f"Review exposed {svc['service']} service on port {p}",'severity':'medium','evidence':f"TCP port {p} is open",'recommendation':'Confirm that this service is needed and restrict access using firewall and network policies.','validation':'Observed open TCP port; exploitability not established'})
                if p not in (80,443,8080,8443): continue
                scheme='https' if p in (443,8443) else 'http'
                try:
                    async with httpx.AsyncClient(timeout=6,follow_redirects=False,verify=True,trust_env=False) as client:
                        res=await client.get(f'{scheme}://{target}:{p}/')
                    headers={k.lower():v for k,v in res.headers.items()}
                    checks={'x-content-type-options':'Set X-Content-Type-Options: nosniff','content-security-policy':'Define a restrictive Content-Security-Policy'}
                    if scheme=='https': checks['strict-transport-security']='Enable HTTP Strict Transport Security (HSTS) if appropriate'
                    for name,fix in checks.items():
                        if name not in headers:
                            report['findings'].append({'title':f'Missing {name} header (port {p})','severity':'low','evidence':f'HTTP {res.status_code}; {name} absent','recommendation':fix,'validation':'Confirmed by inspecting the HTTP response headers; not an exploitation test'})
                    event('http.checked',f'{scheme} port {p}: HTTP {res.status_code}')
                except Exception as exc:
                    event('http.check_incomplete',f'port {p}: {type(exc).__name__}')
            event('scan.completed',f"{len(report['findings'])} potential findings")
        except (subprocess.TimeoutExpired, FileNotFoundError, RuntimeError, ET.ParseError) as exc:
            report['status']='failed'; event('scan.failed',str(exc)[:250])
        return save_report(report)

@app.get('/scans')
def scans(authorization:str|None=Header(default=None)):
    api_auth(authorization)
    results=[]
    for p in sorted(DATA.glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True)[:50]:
        try:
            r=read_report(p.stem)
            results.append({'id':r['id'],'target':r['target'],'created_at':r['created_at'],'status':r['status'],'findings':len(r['findings']),'integrity_verified':r['integrity_verified']})
        except Exception: pass
    return results

@app.get('/scans/{identifier}')
def one_scan(identifier:str,authorization:str|None=Header(default=None)):
    api_auth(authorization)
    return read_report(identifier)
