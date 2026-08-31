"""Ledger figures generated strictly from results/ledger_*.csv."""
import csv, os
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
R = os.path.join(os.path.dirname(__file__), "..", "results")
OUT = os.path.join(os.path.dirname(__file__), "..", "paper-lncs")

B, per, tot = [], [], []
for r in csv.DictReader(open(os.path.join(R, "ledger_aggregation.csv"))):
    B.append(int(r["batch_B"])); per.append(float(r["on_chain_bytes_per_checkpoint"]))
    tot.append(int(r["on_chain_bytes_total"]))
vB, vms, vnodes = [], [], []
for r in csv.DictReader(open(os.path.join(R, "ledger_verify.csv"))):
    vB.append(int(r["batch_B"])); vms.append(float(r["verify_median_ms"]))
    vnodes.append(int(r["inclusion_path_nodes"]))

fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.4, 2.2))
a1.plot(B, per, "o-", color="#3b6ea5")
a1.set_xscale("log"); a1.set_yscale("log")
a1.set_xlabel("Aggregation batch $B$", fontsize=8)
a1.set_ylabel("On-chain bytes\nper checkpoint", fontsize=8)
a1.tick_params(labelsize=7); a1.grid(ls=":", alpha=.5)
a2.plot(vB, vms, "s-", color="#a53b3b")
a2.set_xscale("log"); a2.set_ylim(0, max(vms) * 1.25)
a2.set_xlabel("Aggregation batch $B$", fontsize=8)
a2.set_ylabel("Anchor verify (ms)", fontsize=8)
a2.tick_params(labelsize=7); a2.grid(ls=":", alpha=.5)
fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_ledger.pdf")); plt.close(fig)
print("wrote fig_ledger.pdf")
