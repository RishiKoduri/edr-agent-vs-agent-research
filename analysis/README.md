# Analysis

This folder is for scripts, notebooks, figures, and summaries that analyze experiment outputs.

Current role:

- turn simulator CSV outputs into tables and charts
- compare detection performance across EDR architecture modes
- prepare figures for professor updates and research writeups

Generate the current SVG charts from the repository root:

```bash
python3 analysis/generate_charts.py
```

The charts are written to `analysis/figures/`.
