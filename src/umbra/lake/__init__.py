"""Umbra data lake — owned, primary-source OSINT corpora.

Unlike the per-case collectors (which query external services to answer one
investigation), the lake *ingests primary public sources into a corpus Umbra
owns and can query with no third-party API*. First corpus: Certificate
Transparency (see ``ct``), replacing the crt.sh dependency by tailing the CT
logs directly and building our own searchable certificate/domain index.
"""
