"""Run tests and each benchmark family in a fresh process, fail on any error."""
import argparse,hashlib,json,os,subprocess,sys,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--quick',action='store_true');p.add_argument('--runs',type=int,default=200);p.add_argument('--out',default='results');a=p.parse_args()
    out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    cmds=[[sys.executable,'-m','pytest','-q','--junitxml='+str(out/'tests.xml')]]
    for section in ['latency','scaling','network','wire','anchoring','security']:
        cmd=[sys.executable,'experiments.py','--out',str(out),'--runs',str(a.runs),'--section',section]
        if a.quick:cmd+=['--quick']
        cmds.append(cmd)
    for i,cmd in enumerate(cmds):
        print('RUN',' '.join(cmd),flush=True)
        r=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (out/f'execution_{i}.log').write_text(r.stdout);print(r.stdout,flush=True)
        if r.returncode:raise SystemExit(r.returncode)
    manifest={'all_commands_succeeded':True,'commands':cmds,'quick':a.quick,'runs':a.runs,
        'completed_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        'source_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path('.').rglob('*.py')) if '__pycache__' not in str(p)}}
    (out/'execution_manifest.json').write_text(json.dumps(manifest,indent=2))
if __name__=='__main__':main()
