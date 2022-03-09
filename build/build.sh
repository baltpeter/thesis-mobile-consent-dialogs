#!/bin/bash

pandoc --template latex-template.tex --filter pandoc-crossref --citeproc --csl citations.csl --top-level-division=chapter --pdf-engine=xelatex $(find ../thesis -name '[[:digit:]]*_*.md' | sort) -o thesis.pdf
