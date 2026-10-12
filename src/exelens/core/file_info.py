import json
import math
import os
from collections import Counter

import r2pipe

MAX_RESOURCES = 15


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return abs(sum(n / len(data) * math.log2(n / len(data)) for n in Counter(data).values()))


def r2_json(r2, command: str) -> list:
    # radare2 prints nothing (not "[]") for e.g. a file without resources, which r2pipe's cmdj reports as an error.
    output = r2.cmd(command).strip()
    return json.loads(output) if output else []


def file_info_markdown(sample_path: str) -> str:
    r2 = r2pipe.open(sample_path, flags=["-2"])
    try:
        sections = r2_json(r2, "iSj entropy")
        resources = r2_json(r2, "iRj")
    finally:
        r2.quit()

    buffer = "## Sections:\n"
    for s in sections:
        buffer += (f"- {s.get('name')}: size={s.get('size')}, vsize={s.get('vsize')}, perm={s.get('perm')}, "
                   f"entropy={float(s.get('entropy', 0)):.2f}\n")

    resources = sorted(resources, key=lambda r: r.get("size", 0), reverse=True)
    buffer += f"## Resources ({len(resources)}, largest first):\n"
    for r in resources[:MAX_RESOURCES]:
        buffer += f"- {r.get('type')} {r.get('name')}: size={r.get('size')}\n"

    # The overlay is the data appended after the last section, a common place for an encrypted payload.
    file_size = os.path.getsize(sample_path)
    sections_end = max((s.get("paddr", 0) + s.get("size", 0) for s in sections), default=file_size)
    if file_size > sections_end:
        with open(sample_path, "rb") as f:
            f.seek(sections_end)
            overlay = f.read()
        buffer += f"## Overlay: {len(overlay)} bytes (of {file_size}), entropy={shannon_entropy(overlay):.2f}\n"
    else:
        buffer += f"## Overlay: none (file size {file_size})\n"
    return buffer
