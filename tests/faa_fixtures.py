"""Fixture builders for the FAA lake tests.

A plain module rather than helpers imported across test files: `from
tests.test_faa_lake import ...` only resolves when the repo root happens to be
on sys.path, which is true under `python -m pytest` and false under the bare
`pytest -q` in the definition of done. Three suites need these builders, so
they live somewhere both invocations can reach.

The header constants are the **real** ones, read off
https://registry.faa.gov/database/ReleasableAircraft.zip on 2026-09-02. See the
module docstring in test_faa_lake.py for why guessing them is not safe.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

# Real headers, verbatim from the published archive.
MASTER_HEADER = (
    "﻿N-NUMBER,SERIAL NUMBER,MFR MDL CODE,ENG MFR MDL,YEAR MFR,TYPE REGISTRANT,"
    "NAME,STREET,STREET2,CITY,STATE,ZIP CODE,REGION,COUNTY,COUNTRY,LAST ACTION DATE,"
    "CERT ISSUE DATE,CERTIFICATION,TYPE AIRCRAFT,TYPE ENGINE,STATUS CODE,MODE S CODE,"
    "FRACT OWNER,AIR WORTH DATE,OTHER NAMES(1),OTHER NAMES(2),OTHER NAMES(3),"
    "OTHER NAMES(4),OTHER NAMES(5),EXPIRATION DATE,UNIQUE ID,KIT MFR, KIT MODEL,"
    "MODE S CODE HEX,"
)
ACFTREF_HEADER = (
    "﻿CODE,MFR,MODEL,TYPE-ACFT,TYPE-ENG,AC-CAT,BUILD-CERT-IND,NO-ENG,NO-SEATS,"
    "AC-WEIGHT,SPEED,TC-DATA-SHEET,TC-DATA-HOLDER,"
)


def _master_row(*, n_number, name, mfr_code, year="1978", type_reg="1",
                city="KETCHUM", state="OK", country="US", status="V",
                mode_s_hex="A00001", serial="5334"):
    """One MASTER.txt row, space-padded exactly like the real file."""
    cols = [
        n_number.ljust(5), serial.ljust(30), mfr_code.ljust(7), "17003", year,
        type_reg, name.ljust(50), "PO BOX 329".ljust(33), " " * 33,
        city.ljust(18), state, "743490329 ", "2", "097", country,
        "20230122", "20050506", "1        ", "4", "1 ", status.ljust(2),
        "50002263", " ", "19540430", " " * 50, " " * 50, " " * 50, " " * 50,
        " " * 50, "20261231", "00123456", " " * 30, " " * 20, mode_s_hex,
    ]
    return ",".join(cols) + ","


def _acftref_row(*, code, mfr, model, seats="004", engines="01", weight="CLASS 1",
                 type_acft="4", type_eng="1"):
    cols = [code.ljust(7), mfr.ljust(30), model.ljust(20), type_acft,
            type_eng.ljust(2), "1", "0", engines, seats, weight, "0120",
            " " * 15, " " * 50]
    return ",".join(cols) + ","


def build_zip(path: Path, master_rows, acftref_rows) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("MASTER.txt", "\n".join([MASTER_HEADER, *master_rows]) + "\n")
        z.writestr("ACFTREF.txt", "\n".join([ACFTREF_HEADER, *acftref_rows]) + "\n")
        z.writestr("ardata.pdf", b"%PDF-1.6 not parsed")
    return path
