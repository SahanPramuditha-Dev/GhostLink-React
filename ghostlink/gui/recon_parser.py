from __future__ import annotations

import re
from typing import TypedDict


class ReconRecord(TypedDict, total=False):
    tag: str
    kind: str
    content: str
    label: str
    value: str
    columns: list[str]
    index: int
    col_count: int


SECTION_KW = [
    "route table", "ipv4", "ipv6", "persistent routes", "active routes", "active tcp", "active udp",
    "connections", "system identity", "network interfaces", "dns servers", "internet identity",
    "my device", "infrastructure", "performance", "resources", "security", "traffic analysis",
    "recon result", "wireless", "ghostlink",
]


def strip_ansi(text: str) -> str:
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    text = re.sub(r"\uFFFD?\[[0-9;]*m", "", text)
    return text.replace("\r", "")


def split_into_lines(raw: str) -> list[str]:
    raw = re.sub(r"\b(LOG|DATA|INFO|WARN|ERROR)(None|null|n/a|-)\b", r"\1 \2", raw, flags=re.IGNORECASE)
    text = re.sub(r"(?<!\n)(?<!\A)\b(LOG|DATA|INFO|WARN|ERROR)\b", r"\n\1", raw)
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def is_meter_line(line: str) -> bool:
    compact = line.strip()
    if len(compact) < 8:
        return False
    return bool(re.fullmatch(r"[#=\[\]\(\)\|/\\+\-_.:;%\s]+", compact))


def split_table_cols(body: str) -> list[str]:
    return [c.strip() for c in re.split(r"\s{2,}|\t+", body.strip()) if c.strip()] or [body.strip()]


def looks_like_table_header(body: str) -> bool:
    cols = split_table_cols(body)
    if len(cols) < 2:
        return False
    if any(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9A-Fa-f]{2}:", c) for c in cols):
        return False
    return sum(1 for c in cols if re.search(r"[A-Za-z]", c)) / max(len(cols), 1) >= 0.8


def classify_line(line: str) -> tuple[str, str]:
    if line.strip().lower() in ("none", "null", "n/a", "-"):
        return "LOG", "-"
    m = re.match(r"^(LOG|DATA|INFO|WARN|ERROR|DONE)\s*(.*)", line, re.IGNORECASE)
    if m:
        tag, body = m.group(1).upper(), m.group(2).strip()
        if len(body) >= 6 and re.fullmatch(r"[=\-_.\s]+", body):
            return "DIVIDER", body
        return tag, body if body and body.lower() not in ("none", "null", "n/a", "-") else "-"
    if len(line) >= 6 and re.fullmatch(r"[=\-_.\s]+", line):
        return "DIVIDER", line
    if is_meter_line(line):
        return "METER", line.strip()
    kv = re.match(r"^([A-Za-z][A-Za-z0-9 _/\-(). ]{2,36}):\s+(.+)$", line)
    if kv:
        return "KV", f"{kv.group(1).strip()}\t{kv.group(2).strip()}"
    kv2 = re.match(r"^([A-Za-z][A-Za-z0-9 _/\-(). ]{2,36})\s{2,}(.+)$", line)
    if kv2 and len(re.split(r"\s{2,}|\t+", kv2.group(2).strip())) <= 2:
        return "KV", f"{kv2.group(1).strip()}\t{kv2.group(2).strip()}"
    low = line.lower()
    is_section = (
        bool(re.match(r"^\[\d+\]", line))
        or bool(re.fullmatch(r"[=\-]{3,}.*", line))
        or (len(line) <= 64 and any(kw in low for kw in SECTION_KW) and not line.rstrip().endswith("."))
        or bool(re.match(r"^[A-Za-z][A-Za-z0-9 _/\-(). ]{2,80}:$", line))
    )
    if is_section:
        return "SECTION", line
    if "\t" in line or re.search(r" {3,}", line):
        return "TABLE", line
    return "LOG", line


def parse_recon_output(raw: str) -> list[ReconRecord]:
    lines = split_into_lines(strip_ansi(raw))
    parsed: list[ReconRecord] = []
    in_table = False
    table_row_i = 0
    table_cols = 0
    for line in lines:
        tag, body = classify_line(line)
        # Some recon tools print 2-column output with aligned spaces but no colon.
        # Reclassify KV-like lines as table entries when they look like a header,
        # or when we are already inside a detected table block.
        if tag == "KV" and re.search(r"\t| {3,}", line):
            if in_table or looks_like_table_header(line):
                tag, body = "TABLE", line.strip()
        if tag == "LOG" and body == "-":
            continue
        entering_table = tag == "TABLE" and not in_table
        leaving_table = tag != "TABLE" and in_table
        if entering_table:
            in_table = True
            table_row_i = 0
            table_cols = 0
        elif leaving_table:
            in_table = False
            table_row_i = 0
            table_cols = 0

        if tag == "DIVIDER":
            parsed.append({"tag": "DIVIDER", "kind": "divider", "content": body})
        elif tag == "SECTION":
            parsed.append({"tag": "SECTION", "kind": "section", "content": body})
        elif tag == "KV":
            label, value = body.split("\t", 1) if "\t" in body else (body, "")
            parsed.append({"tag": "DATA", "kind": "kv", "label": label.strip(), "value": value.strip(), "content": f"{label.strip()}: {value.strip()}"})
        elif tag == "METER":
            parsed.append({"tag": "DATA", "kind": "meter", "content": body})
        elif tag == "TABLE":
            cols = split_table_cols(body)
            is_header = entering_table and looks_like_table_header(body)
            if is_header:
                table_cols = len(cols)
                parsed.append({"tag": "DATA", "kind": "table_header", "columns": cols, "content": " | ".join(cols)})
            else:
                parsed.append({"tag": "DATA", "kind": "table_row", "index": table_row_i, "col_count": table_cols, "columns": cols, "content": " | ".join(cols)})
                table_row_i += 1
        else:
            parsed.append({"tag": tag, "kind": "line", "content": body})
    return parsed
