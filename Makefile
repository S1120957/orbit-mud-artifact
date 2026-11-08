.PHONY: test reproduce assets paper
PYTHON ?= python
RESULTS ?= results

test:
	$(PYTHON) -m pytest -q

reproduce:
	$(PYTHON) run_all.py --runs 200 --out reproduced_results

assets:
	$(PYTHON) build_paper_assets.py --results $(RESULTS) --paper ../paper

paper: assets
	cd ../paper && latexmk -pdf main.tex
