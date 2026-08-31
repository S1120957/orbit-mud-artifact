.PHONY: all test security bench figures paper clean

all: test security bench figures paper

test:
	python3 -m pytest tests/ -q

security:
	python3 attacks/security_experiments.py

bench:
	python3 experiments/benchmark.py

figures:
	python3 experiments/make_figures_lncs.py && python3 experiments/make_figures_ledger.py

paper: figures
	cd paper-lncs && pdflatex -interaction=nonstopmode main.tex && \
	bibtex main && \
	pdflatex -interaction=nonstopmode main.tex && \
	pdflatex -interaction=nonstopmode main.tex && \
	cp main.pdf orbit-mud.pdf

clean:
	rm -f paper-lncs/*.aux paper-lncs/*.log paper-lncs/*.bbl paper-lncs/*.blg paper-lncs/*.out
