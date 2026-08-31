"""Figures for the LNICST revision, generated strictly from result files."""
import csv, json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = os.path.join(os.path.dirname(__file__), "..", "results")
OUT = os.path.join(os.path.dirname(__file__), "..", "paper-lncs")
os.makedirs(OUT, exist_ok=True)

# --- fig_scenarios: outcome classes of the 17 scenarios (honest categories) ---
sec = {s["id"]: s for s in json.load(open(os.path.join(R, "security_experiments.json")))}
assert all(s["passed"] for s in sec.values()) and len(sec) == 22
cats = [
    ("Attack rejected", ["E1","E2","E3b","E4","E5","E6","E7","E10","E14","E16","E17","E19","E20"]),
    ("Fork refused on-chain", ["E18"]),
    ("Containment /\nlimitation shown", ["E8","E9","E21"]),
    ("Accepted by design\n(bounded freshness)", ["E3","E13"]),
    ("Quorum policy sweep", ["E12"]),
    ("Equivocation detected\n(off-chain)", ["E11"]),
    ("Emergency withdrawal", ["E15"]),
]
assert sum(len(ids) for _, ids in cats) == 22
labels = [c for c, _ in cats][::-1]
vals = [len(ids) for _, ids in cats][::-1]
fig, ax = plt.subplots(figsize=(4.9, 2.3))
ax.barh(range(len(vals)), vals, color="#3b6ea5")
ax.set_yticks(range(len(vals))); ax.set_yticklabels(labels, fontsize=7)
ax.set_xlabel("Scenarios (of 22)", fontsize=8)
ax.set_xticks(range(0, 15, 2)); ax.tick_params(axis="x", labelsize=7)
for i, v in enumerate(vals):
    ax.text(v + 0.1, i, str(v), va="center", fontsize=7)
ax.grid(axis="x", ls=":", alpha=0.5)
fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_scenarios.pdf")); plt.close(fig)

# --- fig_latency ---
summ = {r["metric"]: r for r in csv.DictReader(open(os.path.join(R, "summary_results.csv")))}
order = ["device_proof_gen_ms", "membership_proof_verify_ms",
         "controller_schnorr_verify_ms", "returning_onboarding_ms",
         "first_contact_onboarding_ms"]
labs = ["Device\nproof gen", "Status proof\nverify", "Ctrl Schnorr\nverify",
        "Returning\nonboard", "First-contact\nonboard"]
med = [float(summ[m]["median"]) for m in order]
lo = [max(0.0, float(summ[m]["median"]) - float(summ[m]["ci95_lo"])) for m in order]
hi = [max(0.0, float(summ[m]["ci95_hi"]) - float(summ[m]["median"])) for m in order]
fig, ax = plt.subplots(figsize=(4.7, 2.1))
ax.bar(range(len(order)), med, yerr=[lo, hi], capsize=3, color="#3b6ea5")
ax.set_xticks(range(len(order))); ax.set_xticklabels(labs, fontsize=7)
ax.set_ylabel("Latency (ms, log)", fontsize=8); ax.set_yscale("log")
ax.tick_params(axis="y", labelsize=7); ax.grid(axis="y", ls=":", alpha=0.5)
fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_latency.pdf")); plt.close(fig)

# --- fig_scale ---
N, mb, us = [], [], []
for r in csv.DictReader(open(os.path.join(R, "scalability.csv"))):
    N.append(int(r["population_N"])); mb.append(int(r["membership_bytes"]))
    us.append(float(r["membership_verify_ms"]) * 1000)
fig, ax1 = plt.subplots(figsize=(4.7, 2.1))
ax1.plot(N, mb, "o-", color="#3b6ea5"); ax1.set_xscale("log")
ax1.set_xlabel("Device population $N$ (log)", fontsize=8)
ax1.set_ylabel("Proof size (bytes)", fontsize=8, color="#3b6ea5")
ax1.tick_params(labelsize=7)
ax2 = ax1.twinx(); ax2.plot(N, us, "s--", color="#a53b3b")
ax2.set_ylabel("Verify time ($\\mu$s)", fontsize=8, color="#a53b3b")
ax2.tick_params(labelsize=7); ax1.grid(ls=":", alpha=0.5)
fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_scale.pdf")); plt.close(fig)
print("wrote fig_scenarios.pdf fig_latency.pdf fig_scale.pdf")
