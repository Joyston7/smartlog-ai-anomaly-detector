from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import re, math
import numpy as np
from sklearn.ensemble import IsolationForest

BASE=Path(__file__).parent
app=FastAPI(title="SMARTLOG")
app.mount("/static",StaticFiles(directory=BASE/"static"),name="static")
LEVEL={"DEBUG":0,"INFO":1,"NOTICE":1,"WARN":2,"WARNING":2,"ERROR":3,"CRITICAL":4,"FATAL":4}
PAT=re.compile(r'(?P<ts>\\d{4}-\\d\\d-\\d\\d[ T]\\d\\d:\\d\\d:\\d\\d)?.*?\\b(?P<level>DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL)\\b\\s*[:\\-]?\\s*(?P<msg>.*)',re.I)
def parse(raw):
 out=[]
 for i,line in enumerate(raw.splitlines()):
  line=line.strip()
  if not line: continue
  m=PAT.search(line); level=m.group("level").upper() if m else "INFO"
  msg=(m.group("msg") if m else line) or line
  out.append({"id":i+1,"timestamp":m.group("ts") if m else None,"level":level,"message":msg[:500],"raw":line[:1000]})
 return out
def feats(rows):
 counts={}
 for r in rows: counts[r["level"]]=counts.get(r["level"],0)+1
 out=[]
 for r in rows:
  s=r["message"].lower()
  out.append([LEVEL.get(r["level"],1),min(len(s),500)/100,
   sum(w in s for w in ["timeout","failed","refused","exception","denied","overflow","crash"]),
   sum(w in s for w in ["retry","latency","slow","unavailable","disconnect"]),
   math.log1p(counts[r["level"]]),sum(c.isdigit() for c in s)/max(1,len(s)),
   int(bool(re.search(r'\\b(500|502|503|504)\\b',s)))])
 return np.asarray(out,float)
rng=np.random.default_rng(42)
baseline=np.column_stack([rng.choice([0,1,2],1200,p=[.05,.88,.07]),np.clip(rng.normal(.42,.12,1200),.05,1.5),rng.binomial(1,.015,1200),rng.binomial(1,.04,1200),rng.normal(2,.25,1200),rng.uniform(0,.08,1200),rng.binomial(1,.008,1200)])
model=IsolationForest(n_estimators=160,contamination=.045,random_state=42).fit(baseline)
@app.get("/")
def home(): return FileResponse(BASE/"static/index.html")
@app.get("/sample_logs.log")
def sample(): return FileResponse(BASE/"sample_logs.log",media_type="text/plain")
@app.get("/api/health")
def health(): return {"status":"online","model":"Isolation Forest"}
@app.post("/api/analyze")
async def analyze(file:UploadFile=File(...)):
 if not file.filename.lower().endswith((".log",".txt",".csv")): raise HTTPException(400,"Upload a .log, .txt or .csv file.")
 rows=parse((await file.read()).decode("utf-8",errors="replace"))
 if len(rows)<5: raise HTTPException(400,"Please upload at least 5 non-empty log lines.")
 scores=model.decision_function(feats(rows)); preds=model.predict(feats(rows)); result=[]
 for r,s,p in zip(rows,scores,preds):
  sev="Critical" if r["level"] in ("CRITICAL","FATAL") else "High" if r["level"]=="ERROR" else "Warning" if r["level"] in ("WARN","WARNING") else "Normal"
  flag=bool(p==-1 or sev in ("Critical","High"))
  result.append({**r,"anomaly":flag,"score":round(float(max(0,min(1,.5-float(s)))),3),"severity":sev if sev!="Normal" else ("Suspicious" if flag else "Normal")})
 return {"filename":file.filename,"total":len(result),"anomalies":sum(x["anomaly"] for x in result),"normal":sum(not x["anomaly"] for x in result),"critical":sum(x["severity"]=="Critical" for x in result),"model":"Isolation Forest","results":result,"note":"Anomaly scores indicate statistical unusualness, not proof of an incident. Review flagged events in context."}
