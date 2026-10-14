import csv, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
from matplotlib import font_manager as fm

for f in fm.findSystemFonts():
    if "NotoSansCJK" in f and ("Regular" in f or "-Medium" not in f):
        pass
plt.rcParams["font.family"] = ["Noto Sans CJK KR", "Noto Sans CJK TC", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

rows = list(csv.DictReader(open(sys.argv[1])))
out = sys.argv[2]

INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
COL = {  # 기본 팔레트 순서 고정
    "baseline": "#2a78d6", "authn-only": "#eb6834", "authz-cached": "#1baf7a",
    "authz-uncached-nolimit": "#4a3aa7", "authz-uncached-qps50": "#e34948",
}
LABEL = {
    "baseline": "baseline (인증·인가 off)",
    "authn-only": "인증만",
    "authz-cached": "인증+인가, 캐시 on (인증만과 거의 같음)",
    "authz-uncached-nolimit": "인증+인가, 캐시 off (속도 제한 없음)",
    "authz-uncached-qps50": "인증+인가, 캐시 off (QPS 50 기본값)",
}
ORDER = list(COL)
concs = [1, 10, 50]
data = {c: {} for c in ORDER}
for r in rows:
    data[r["condition"]][int(r["concurrency"])] = r

def style(ax, ylabel):
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    for s in ("left", "bottom"): ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9, length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8); ax.set_axisbelow(True)
    ax.set_ylabel(ylabel, color=INK2, fontsize=9)
    ax.set_xlabel("동시 요청 수", color=INK2, fontsize=9)

# ---------- 그림 1: 처리량 (그룹 막대, 로그 축) ----------
fig, ax = plt.subplots(figsize=(8, 4.6), dpi=200)
w = 0.16
for i, c in enumerate(ORDER):
    xs = [j + (i - 2) * (w + 0.012) for j in range(3)]
    ys = [float(data[c][k]["ops_per_sec"]) for k in concs]
    ax.bar(xs, ys, width=w, color=COL[c], label=LABEL[c], zorder=2)
    for x, y in zip(xs, ys):
        ax.text(x, y * 1.12, f"{y:,.0f}", ha="center", va="bottom",
                fontsize=6.5, color=INK2, rotation=90)
ax.set_yscale("log"); ax.set_ylim(20, 2e5)
ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v,_: f"{v:,.0f}"))
ax.set_xticks(range(3)); ax.set_xticklabels([str(k) for k in concs])
style(ax, "처리량 (ops/sec, 로그 축)")
ax.set_title("접근 제어 조건별 encrypt 처리량 (1KB, 각 10초)", loc="left",
             fontsize=11, color=INK, pad=12)
ax.legend(frameon=False, fontsize=8, loc="upper left", ncol=2, labelcolor=INK)
fig.tight_layout(); fig.savefig(f"{out}/fig1-throughput.png", facecolor="white")

# ---------- 그림 2: p50 지연 (선, 로그 축) ----------
fig, ax = plt.subplots(figsize=(8, 4.6), dpi=200)
for c in ORDER:
    ys = [float(data[c][k]["p50_ms"]) for k in concs]
    ax.plot(concs, ys, color=COL[c], linewidth=2, linestyle=(0,(4,2)) if c=="authz-cached" else "-", marker="o", markersize=6,
            markeredgecolor="white", markeredgewidth=1.5, label=LABEL[c], zorder=3)
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xticks(concs); ax.set_xticklabels([str(k) for k in concs])
ax.minorticks_off()
style(ax, "p50 지연 (ms, 로그 축)")
q = [float(data["authz-uncached-qps50"][k]["p50_ms"]) for k in concs]
ax.annotate("속도 제한 대기: 지연 ≈ 동시성 ÷ 50초", xy=(10, q[1]), xytext=(11, 40),
            fontsize=8, color=INK2, arrowprops=dict(arrowstyle="-", color=INK2, lw=0.8))
ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v,_: f"{v:g}"))
ax.set_title("접근 제어 조건별 encrypt 중앙값 지연", loc="left",
             fontsize=11, color=INK, pad=12)
ax.legend(frameon=False, fontsize=8, loc="upper left", labelcolor=INK)
fig.tight_layout(); fig.savefig(f"{out}/fig2-latency.png", facecolor="white")
print("ok")
