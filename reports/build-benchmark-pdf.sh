#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "==> Generating charts …"
python3 generate_charts.py

echo "==> Building PDF …"
pandoc irify-sast-benchmark-report.md -o irify-sast-benchmark-report.pdf \
  --pdf-engine=weasyprint \
  --css=benchmark-pdf-style.css \
  --include-before-body=benchmark-cover.html

echo "✓ irify-sast-benchmark-report.pdf"
