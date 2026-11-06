#!/usr/bin/env python3
"""NORDLYNX public-node test aggregator.

A node is published only after sing-box starts its protocol outbound and a real
HTTPS request succeeds through the local proxy. Country is derived from the
observed egress IP, not the node label. This is still a point-in-time test from
the GitHub Actions runner, not a guarantee for a user's ISP or device.
"""
from __future__ import annotations
import base64, concurrent.futures, json, os, re, shutil, socket, subprocess, tempfile, time, uuid
from pathlib import Path
from urllib.parse import urlsplit, unquote, parse_qs
from urllib.request import Request, urlopen, ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SUB_FILE = OUT / "sub.txt"
STATUS_FILE = OUT / "status.json"
MIN_NODES = int(os.getenv("MIN_NODES", "20"))
MIN_COUNTRIES = int(os.getenv("MIN_COUNTRIES", "20"))
MAX_PER_COUNTRY = int(os.getenv("MAX_PER_COUNTRY", "3"))
PROBE_TIMEOUT = int(os.getenv("PROBE_TIMEOUT", "12"))
SING_BOX = os.getenv("SING_BOX_BIN", "sing-box")
SOURCES = [x.strip() for x in os.getenv("SOURCES", "").splitlines() if x.strip()] or [
    "https://radarhub.top/v2ray.txt",
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/all.txt",
]
ALLOWED = ("vless://", "vmess://", "trojan://", "ss://")

def decode_feed(raw: str) -> str:
    s = raw.strip().lstrip("\ufeff")
    if re.search(r"(?m)^(?:vless|vmess|trojan|ss)://", s, re.I): return s
    compact = re.sub(r"\s+", "", s)
    try:
        d = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", "ignore")
        if re.search(r"(?m)^(?:vless|vmess|trojan|ss)://", d, re.I): return d
    except Exception: pass
    return s

def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent":"NORDLYNX-personal-test/2.0"})
    with urlopen(req, timeout=20) as r:
        if r.status != 200: raise RuntimeError(f"HTTP {r.status}")
        return decode_feed(r.read(8_000_000).decode("utf-8","ignore"))

def b64decode(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def tls_config(host: str, q: dict) -> dict | None:
    security = (q.get("security") or [""])[0].lower()
    if security not in ("tls","reality"): return None
    tls = {"enabled": True, "server_name": (q.get("sni") or q.get("servername") or [host])[0],
           "insecure": (q.get("allowInsecure") or ["false"])[0].lower() in ("1","true")}
    if security == "reality":
        tls["reality"] = {"enabled": True,
                          "public_key": (q.get("pbk") or q.get("publicKey") or [""])[0],
                          "short_id": (q.get("sid") or q.get("shortId") or [""])[0]}
        if not tls["reality"]["public_key"]: raise ValueError("REALITY URI has no public key (pbk)")
    fp = (q.get("fp") or [""])[0]
    if fp: tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls

def transport_config(q: dict) -> dict | None:
    typ = (q.get("type") or ["tcp"])[0].lower()
    if typ in ("tcp",""): return None
    if typ == "ws":
        tr = {"type":"ws","path":(q.get("path") or ["/"])[0]}
        host = (q.get("host") or [""])[0]
        if host: tr["headers"] = {"Host":host}
        return tr
    if typ == "grpc":
        return {"type":"grpc","service_name":(q.get("serviceName") or q.get("service_name") or [""])[0]}
    if typ == "httpupgrade":
        return {"type":"httpupgrade","path":(q.get("path") or ["/"])[0],"host":(q.get("host") or [""])[0]}
    raise ValueError("unsupported transport: "+typ)

def outbound_from_uri(uri: str) -> tuple[dict,str,int]:
    scheme = uri.split(":",1)[0].lower()
    if scheme == "vmess":
        data = json.loads(b64decode(uri[8:]).decode())
        host, port = str(data.get("add","")), int(data.get("port",0))
        method = data.get("scy") or "auto"
        out = {"type":"vmess","tag":"proxy","server":host,"server_port":port,
               "uuid":str(data["id"]),"security":method}
        net = str(data.get("net","tcp")).lower()
        if net == "ws":
            tr={"type":"ws","path":data.get("path") or "/"}
            if data.get("host"): tr["headers"]={"Host":data["host"]}
            out["transport"]=tr
        elif net == "grpc": out["transport"]={"type":"grpc","service_name":data.get("path","")}
        elif net not in ("tcp",""): raise ValueError("unsupported VMess transport: "+net)
        if str(data.get("tls","")).lower() in ("tls","1","true"):
            out["tls"]={"enabled":True,"server_name":data.get("sni") or data.get("host") or host,
                        "insecure":str(data.get("allowInsecure","")).lower() in ("1","true")}
        return out,host,port
    if scheme == "ss":
        raw = uri[5:].split("#",1)[0].split("?",1)[0]
        if "@" not in raw: raw = b64decode(raw).decode()
        userinfo, authority = raw.rsplit("@",1)
        if ":" not in userinfo: userinfo = b64decode(userinfo).decode()
        method,password = userinfo.split(":",1)
        p=urlsplit("//"+authority); host=p.hostname or ""; port=p.port or 0
        return {"type":"shadowsocks","tag":"proxy","server":host,"server_port":port,
                "method":unquote(method),"password":unquote(password)},host,port
    p=urlsplit(uri); host=p.hostname or ""; port=p.port or 0
    if scheme == "vless":
        q=parse_qs(p.query); user=unquote(p.username or "")
        if not user: raise ValueError("VLESS UUID missing")
        out={"type":"vless","tag":"proxy","server":host,"server_port":port,"uuid":user,
             "flow":(q.get("flow") or [""])[0]}
        out["flow"] = out["flow"] or None
        if not out["flow"]: out.pop("flow")
        tls=tls_config(host,q)
        if tls: out["tls"]=tls
        tr=transport_config(q)
        if tr: out["transport"]=tr
        return out,host,port
    if scheme == "trojan":
        q=parse_qs(p.query); password=unquote(p.username or "")
        if not password: raise ValueError("Trojan password missing")
        out={"type":"trojan","tag":"proxy","server":host,"server_port":port,"password":password}
        tls=tls_config(host,q) or {"enabled":True,"server_name":(q.get("sni") or [host])[0]}
        out["tls"]=tls
        tr=transport_config(q)
        if tr: out["transport"]=tr
        return out,host,port
    raise ValueError("unsupported scheme")

def probe(uri: str) -> dict:
    proc=None
    try:
        outbound,host,port=outbound_from_uri(uri)
        if not host or not 1 <= port <= 65535: raise ValueError("invalid host/port")
        cfg={"log":{"level":"error"},"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}],
             "outbounds":[outbound,{"type":"direct","tag":"direct"}],"route":{"final":"proxy"}}
        # sing-box does not support listen_port=0 on all releases; allocate an ephemeral local port.
        with socket.socket() as s:
            s.bind(("127.0.0.1",0)); local_port=s.getsockname()[1]
        cfg["inbounds"][0]["listen_port"]=local_port
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"config.json"; path.write_text(json.dumps(cfg),encoding="utf-8")
            check=subprocess.run([SING_BOX,"check","-c",str(path)],capture_output=True,text=True,timeout=8)
            if check.returncode: raise ValueError("sing-box config rejected: "+(check.stderr or check.stdout)[-300:])
            proc=subprocess.Popen([SING_BOX,"run","-c",str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.time()+5
            while time.time()<deadline:
                if proc.poll() is not None: raise RuntimeError("sing-box exited during startup")
                try:
                    with socket.create_connection(("127.0.0.1",local_port),timeout=.3): break
                except OSError: time.sleep(.1)
            else: raise TimeoutError("local proxy did not start")
            opener=build_opener(ProxyHandler({"http":f"http://127.0.0.1:{local_port}","https":f"http://127.0.0.1:{local_port}"}))
            req=Request("https://api.ipify.org?format=json",headers={"User-Agent":"NORDLYNX-probe/2.0"})
            with opener.open(req,timeout=PROBE_TIMEOUT) as r: observed=json.loads(r.read(4096))
            egress=observed.get("ip")
            if not egress: raise RuntimeError("proxy test returned no egress IP")
            geo_req=Request(f"https://ipwho.is/{egress}",headers={"User-Agent":"NORDLYNX-probe/2.0"})
            with urlopen(geo_req,timeout=8) as r: geo=json.loads(r.read(8192))
            if not geo.get("success"): raise RuntimeError("egress IP geolocation failed")
            return {"ok":True,"country":geo.get("country"),"country_code":geo.get("country_code"),
                    "egress_ip":egress,"host":host,"port":port}
    except Exception as exc:
        return {"ok":False,"error":f"{type(exc).__name__}: {exc}"[:400]}
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=2)
            except Exception: proc.kill()

def main() -> int:
    OUT.mkdir(parents=True,exist_ok=True)
    errors=[]; uris={}
    if not shutil.which(SING_BOX):
        print("sing-box executable not found; refusing TCP-only fallback",file=__import__("sys").stderr); return 3
    for src in SOURCES:
        try:
            for line in fetch(src).splitlines():
                line=line.strip()
                if line.lower().startswith(ALLOWED): uris.setdefault(line,src)
        except Exception as e: errors.append(f"{src}: {type(e).__name__}: {e}")
    candidates=list(uris)
    print(f"Unique candidates: {len(candidates)}")
    results=[]
    # Limit concurrency to avoid overloading public community endpoints.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures={pool.submit(probe,u):u for u in candidates}
        for f in concurrent.futures.as_completed(futures):
            u=futures[f]; r=f.result()
            if r["ok"]: results.append((u,r))
    by_country={}
    for uri,r in results: by_country.setdefault(r["country"],[]).append((uri,r))
    selected=[]
    for country in sorted(by_country):
        selected.extend(by_country[country][:MAX_PER_COUNTRY])
    countries=sorted({r["country"] for _,r in selected})
    status={"project":"NORDLYNX end-to-end public-node test","generated_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            "sources":SOURCES,"source_errors":errors,"unique_candidates":len(candidates),
            "end_to_end_success":len(results),"selected_nodes":len(selected),"countries":countries,
            "minimum_nodes":MIN_NODES,"minimum_countries":MIN_COUNTRIES,
            "country_source":"GeoIP lookup of observed egress IP after HTTPS request through sing-box proxy",
            "test":"sing-box protocol outbound + HTTPS request to api.ipify.org + egress GeoIP",
            "status":"ok" if len(selected)>=MIN_NODES and len(countries)>=MIN_COUNTRIES else "below_threshold",
            "warning":"Point-in-time tests from GitHub Actions runner. Availability may differ by user ISP/location. Third-party nodes are not operated or security-audited by NORDLYNX."}
    STATUS_FILE.write_text(json.dumps(status,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(status,ensure_ascii=False,indent=2))
    if len(selected)<MIN_NODES or len(countries)<MIN_COUNTRIES:
        print("Threshold not met; preserving previously published subscription.",file=__import__("sys").stderr); return 2
    lines=["#profile-title: NORDLYNX TEST","#profile-update-interval: 1",
           "# End-to-end tested from GitHub Actions runner; third-party nodes, no security audit."]
    lines.extend(uri for uri,_ in selected)
    SUB_FILE.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return 0

if __name__=="__main__": raise SystemExit(main())
