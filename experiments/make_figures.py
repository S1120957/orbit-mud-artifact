"""Generate figures strictly from result CSV files."""
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RESULTS = os.path.join(os.path.dirname(__file__), "..", "results")
PAPER = os.path.join(os.path.dirname(__file__), "..", "paper")


def load_summary():
    rows = {}
    with open(os.path.join(RESULTS, "summary_results.csv")) as f:
        for r in csv.DictReader(f):
            rows[r["metric"]] = r
    return rows


def fig_latency():
    s = load_summary()
    order = ["device_proof_gen_ms", "membership_proof_verify_ms",
             "controller_schnorr_verify_ms", "returning_onboarding_ms",
             "first_contact_onboarding_ms"]
    labels = ["Device\nproof gen", "Membership\nverify",
              "Ctrl Schnorr\nverify", "Returning\nonboard",
              "First-contact\nonboard"]
    med = [float(s[m]["median"]) for m in order]
    # error bars from the 95% CI of the mean, clamped non-negative and
    # centered on the median (CI can straddle the median on tight data)
    lo = [max(0.0, float(s[m]["median"]) - float(s[m]["ci95_lo"]))
          for m in order]
    hi = [max(0.0, float(s[m]["ci95_hi"]) - float(s[m]["median"]))
          for m in order]
    fig, ax = plt.subplots(figsize=(5.2, 2.6))
    ax.bar(range(len(order)), med, yerr=[lo, hi], capsize=3,
           color="#3b6ea5")
    ax.set_xticks(range(len(order)))
    ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylabel("Latency (ms)", fontsize=8)
    ax.set_yscale("log")
    ax.tick_params(axis="y", labelsize=7)
    ax.grid(axis="y", ls=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(os.path.join(PAPER, "fig_latency.pdf"))
    plt.close(fig)


def fig_scalability():
    N, mbytes, vms = [], [], []
    with open(os.path.join(RESULTS, "scalability.csv")) as f:
        for r in csv.DictReader(f):
            N.append(int(r["population_N"]))
            mbytes.append(int(r["membership_bytes"]))
            vms.append(float(r["membership_verify_ms"]) * 1000)  # us
    fig, ax1 = plt.subplots(figsize=(5.2, 2.6))
    ax1.plot(N, mbytes, "o-", color="#3b6ea5", label="membership proof (B)")
    ax1.set_xscale("log")
    ax1.set_xlabel("Device population $N$ (log scale)", fontsize=8)
    ax1.set_ylabel("Membership proof (bytes)", fontsize=8, color="#3b6ea5")
    ax1.tick_params(labelsize=7)
    ax2 = ax1.twinx()
    ax2.plot(N, vms, "s--", color="#a53b3b", label="verify time")
    ax2.set_ylabel("Verify time ($\\mu$s)", fontsize=8, color="#a53b3b")
    ax2.tick_params(labelsize=7)
    ax1.grid(axis="both", ls=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(os.path.join(PAPER, "fig_scalability.pdf"))
    plt.close(fig)


if __name__ == "__main__":
    fig_latency()
    fig_scalability()
    print("figures written to paper/: fig_latency.pdf, fig_scalability.pdf")
