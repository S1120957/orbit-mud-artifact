"""Generate every empirical paper table/plot from this revision's recorded results.
Usage: python build_paper_assets.py --results results --paper ../paper
Plotting uses matplotlib's default colors.
"""
from pathlib import Path
import argparse, csv, json, hashlib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.rcParams["pdf.fonttype"] = 42
import numpy as np

def readcsv(p):
    with open(p,newline='') as f:return list(csv.DictReader(f))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--results',default='results');ap.add_argument('--paper',default='../paper');args=ap.parse_args()
    r=Path(args.results);p=Path(args.paper);g=p/'generated';f=p/'figures';g.mkdir(parents=True,exist_ok=True);f.mkdir(parents=True,exist_ok=True)
    s=json.loads((r/'latency_summary.json').read_text());net=json.loads((r/'network_summary.json').read_text())
    status=readcsv(r/'status_scaling.csv');hist=readcsv(r/'history_scaling.csv');anchor=readcsv(r/'anchoring_summary.csv');wire=readcsv(r/'wire_sizes.csv')
    def write(name,head,rows):
        (g/name).write_text(head+'\n'+ '\n'.join(' & '.join(map(str,row))+r' \\' for row in rows)+'\n'+r'\bottomrule\end{tabular}'+'\n')
    names=['B1','B2','B3','B4-first','B4-return','B5-first','B5-return','B6-first','B6-return','B5-return-durable']
    labels={'B1':'B1: signed URL/profile','B2':'B2: class proof','B3':'B3: class proof + version cache',
        'B4-first':'B4: first contact','B4-return':'B4: returning','B5-first':'B5: first contact',
        'B5-return':'B5: returning','B6-first':'B6: first contact','B6-return':'B6: returning (cached anchor)',
        'B5-return-durable':'B5: returning + durable storage'}
    rows=[]
    for k in names:
        a=s[k];rows.append([labels[k],f"{a['median_ms']:.3f}",f"{a['q3_ms']-a['q1_ms']:.3f}",f"[{a['ci_low_ms']:.3f}, {a['ci_high_ms']:.3f}]"])
    write('latency_table.tex',r'\begin{tabular}{lrrr}\toprule Configuration & Median & IQR & 95\% median CI \\\midrule',rows)
    micro=[('device_commit_and_response','Commitment + response'),('device_response_only','Response only (commitment precomputed)'),('schnorr_verify','Schnorr verification'),('anchor_uncached','Uncached anchor verification'),('authenticated_withdrawal','Authenticated withdrawal (software PEP)')]
    rows=[]
    for k,l in micro:
        a=s[k];rows.append([l,f"{a['median_ms']*1000:.2f}",f"{(a['q3_ms']-a['q1_ms'])*1000:.2f}",f"[{a['ci_low_ms']*1000:.2f}, {a['ci_high_ms']*1000:.2f}]"])
    write('micro_table.tex',r'\begin{tabular}{lrrr}\toprule Operation & Median & IQR & 95\% median CI \\\midrule',rows)
    rows=[[f"$10^{{{int(np.log10(int(a['N'])))}}}$",a['proof_bytes'],f"{float(a['verify_us']):.2f}",f"{float(a['update_us']):.2f}",f"{float(a['build_ms']):.2f}"] for a in status]
    write('status_table.tex',r'\begin{tabular}{rrrrr}\toprule $N$ & Path (B) & Verify ($\mu$s) & Update ($\mu$s) & Build (ms) \\\midrule',rows)
    rows=[[a['L'],a['old_prefix'],a['inclusion_bytes'],a['consistency_bytes'],f"{float(a['inclusion_verify_us']):.2f}",f"{float(a['consistency_verify_us']):.2f}"] for a in hist]
    write('history_table.tex',r'\begin{tabular}{rrrrrr}\toprule $L$ & Prior size & Incl. (B) & Cons. (B) & Incl. ($\mu$s) & Cons. ($\mu$s) \\\midrule',rows)
    rows=[]
    nr=readcsv(r/'network_raw.csv')
    for d in ['0','2','10']:
        a=net[d];b=np.median([int(x['application_bytes']) for x in nr if x['delay_per_rpc_ms']==d])
        rows.append([d,f"{a['median_ms']:.2f}",f"{a['q3_ms']-a['q1_ms']:.2f}",f"[{a['ci_low_ms']:.2f}, {a['ci_high_ms']:.2f}]",f"{b/1000:.2f}"])
    write('network_table.tex',r'\begin{tabular}{rrrrr}\toprule Delay/RPC (ms) & Median (ms) & IQR (ms) & 95\% median CI & JSON (kB) \\\midrule',rows)
    rows=[[a['batch'],a['header_certificate_bytes'],f"{float(a['bytes_per_checkpoint']):.2f}",a['all_anchor_payload_bytes'],a['inclusion_bytes'],f"{float(a['verify_ms']):.3f}"] for a in anchor]
    write('anchor_table.tex',r'\begin{tabular}{rrrrrr}\toprule $B$ & Header + QC (B) & B/CP & Payloads (B) & Path (B) & Verify (ms) \\\midrule',rows)
    rows=[[a['url_bytes'],a['custom_options_bytes'],a['dhcp_payload_bytes'],a['ipv4_udp_bytes']] for a in wire if a['message']=='Discover']
    write('wire_table.tex',r'\begin{tabular}{rrrr}\toprule URL (B) & MUD + ORBIT options (B) & DHCP (B) & IPv4/UDP (B) \\\midrule',rows)
    sm=readcsv(r/'security_matrix.csv');scenarios=['active','unregistered-key','revoked','full-package-rollback','expired-checkpoint']
    lab=['Active enrolled key','Unregistered key','Revoked key','Complete old package','Expired checkpoint']
    rows=[]
    for sc,l in zip(scenarios,lab):
        rows.append([l]+['A' if next(x for x in sm if x['configuration']==m and x['scenario']==sc)['accepted']=='True' else 'R' for m in ['B1','B2','B3','B4','B5','B6']])
    write('security_table.tex',r'\begin{tabular}{lcccccc}\toprule Scenario & B1 & B2 & B3 & B4 & B5 & B6 \\\midrule',rows)
    macros={'FirstBfive':s['B5-first']['median_ms'],'ReturnBfive':s['B5-return']['median_ms'],'FirstBsix':s['B6-first']['median_ms'],'ReturnBsix':s['B6-return']['median_ms'],'DurableBfive':s['B5-return-durable']['median_ms'],'Withdrawal':s['authenticated_withdrawal']['median_ms'],'UncachedAnchor':s['anchor_uncached']['median_ms'],'CommitZero':net['0']['median_ms'],'CommitTwo':net['2']['median_ms'],'CommitTen':net['10']['median_ms']}
    (g/'numbers.tex').write_text('\n'.join('\\newcommand{\\'+k+'}{'+f'{v:.3f}'+'}' for k,v in macros.items())+'\n')
    # Each figure is an independent axis/plot. Median CIs are aligned with medians.
    fig,ax=plt.subplots(figsize=(6.2,3.8));ys=np.arange(len(names));vals=np.array([s[k]['median_ms'] for k in names]);lo=np.array([s[k]['ci_low_ms'] for k in names]);hi=np.array([s[k]['ci_high_ms'] for k in names])
    ax.errorbar(vals,ys,xerr=[vals-lo,hi-vals],fmt='o',capsize=3);ax.set_yticks(ys,[labels[k] for k in names],fontsize=8);ax.invert_yaxis();ax.set_xlabel('Admission median (ms); 95% bootstrap median CI');ax.grid(axis='x',alpha=.25);fig.tight_layout();fig.savefig(f/'latency.pdf',metadata={'Author':'','Title':'Common-platform admission costs'});plt.close(fig)
    fig,ax=plt.subplots(figsize=(5.5,2.8));ns=[int(a['N']) for a in status]
    ax.plot(ns,[float(a['verify_us']) for a in status],marker='o',label='Verify membership');ax.plot(ns,[float(a['update_us']) for a in status],marker='s',label='Single-leaf update');ax.set_xscale('log');ax.set_xlabel('Synthetic status leaves N');ax.set_ylabel('Median time (microseconds)');ax.legend(fontsize=8);ax.grid(alpha=.25);fig.tight_layout();fig.savefig(f/'status.pdf',metadata={'Author':''});plt.close(fig)
    fig,ax=plt.subplots(figsize=(5.5,2.8));ds=np.array([0,2,10]);vals=np.array([net[str(d)]['median_ms'] for d in ds]);lo=np.array([net[str(d)]['ci_low_ms'] for d in ds]);hi=np.array([net[str(d)]['ci_high_ms'] for d in ds]);ax.errorbar(ds,vals,yerr=[vals-lo,hi-vals],fmt='o-',capsize=4);ax.set_xticks(ds);ax.set_xlabel('Injected server delay per RPC (ms), not WAN RTT');ax.set_ylabel('Finalize + replicate median (ms)');ax.grid(alpha=.25);fig.tight_layout();fig.savefig(f/'network.pdf',metadata={'Author':''});plt.close(fig)
    fig,ax=plt.subplots(figsize=(5.5,2.8));ax.loglog([int(a['batch']) for a in anchor],[float(a['bytes_per_checkpoint']) for a in anchor],marker='o');ax.set_xlabel('Checkpoint batch B');ax.set_ylabel('Amortized header + QC (B/checkpoint)');ax.grid(alpha=.25);fig.tight_layout();fig.savefig(f/'anchoring.pdf',metadata={'Author':''});plt.close(fig)
    manifest={str(x.relative_to(p)):hashlib.sha256(x.read_bytes()).hexdigest() for folder in [g,f] for x in sorted(folder.glob('*'))}
    (g/'assets_manifest.json').write_text(json.dumps(manifest,indent=2))
    print('Generated 8 data tables, numerical macros, and 4 vector figures from recorded results.')
if __name__=='__main__':main()
