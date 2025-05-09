#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit("pyelftools not found. Install with: pip install pyelftools")

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

ARCH_MAP = {
    ("EM_386", 32): "x86",
    ("EM_X86_64", 64): "x86_64",
    ("EM_ARM", 32): "armv7",
    ("EM_AARCH64", 64): "aarch64",
}

def detect_arch(path: Path) -> str | None:
    with path.open("rb") as f:
        try:
            elf = ELFFile(f)
        except Exception:
            return None
        machine = elf["e_machine"]
        bits = 64 if elf.elfclass == 64 else 32
        return ARCH_MAP.get((machine, bits), f"{machine.lower()}_{bits}")

def get_needed_libs(path: Path) -> Set[str]:
    libs: Set[str] = set()
    try:
        with path.open("rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if section.name == ".dynamic":
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            libs.add(tag.needed)
    except Exception:
        pass
    return libs

def walk_elves(root: Path, max_depth: int) -> List[Path]:
    root = root.resolve()
    elves: List[Path] = []
    for dirpath, dirs, files in os.walk(root):
        depth = Path(dirpath).relative_to(root).parts
        if len(depth) >= max_depth:
            dirs[:] = []
        for name in files:
            full = Path(dirpath) / name
            try:
                if full.is_file() and os.access(full, os.X_OK):
                    with full.open("rb") as f:
                        if f.read(4) == b"\x7fELF":
                            elves.append(full)
            except (PermissionError, OSError):
                pass
    return elves

def build_index(elves: List[Path]) -> Dict[str, Dict[str, List[str]]]:
    inverted: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    with ThreadPoolExecutor() as pool:
        fut_to_file = {pool.submit(get_needed_libs, e): e for e in elves}
        for fut in as_completed(fut_to_file):
            exe = fut_to_file[fut]
            libs = fut.result()
            arch = detect_arch(exe) or "unknown"
            for lib in libs:
                inverted[arch][lib].append(str(exe))
    return inverted

def generate_report(index: Dict[str, Dict[str, List[str]]], full: bool = False) -> str:
    lines: List[str] = []
    for arch in sorted(index):
        lines.append(f"---------- {arch} ----------")
        for lib, exes in sorted(
            index[arch].items(), key=lambda kv: len(kv[1]), reverse=True
        ):
            lines.append(f"{lib} ({len(exes)} execs)")
            iterable = sorted(exes)
            if full:
                chosen = iterable
            else:
                chosen = iterable[:10]
            for exe in chosen:
                lines.append(f" -> {exe}")
            if not full and len(exes) > 10:
                lines.append(f" -> ... and {len(exes) - 10} more files")
        lines.append("")
    return "\n".join(lines)

def save_pdf(text: str, path: Path) -> None:
    if not REPORTLAB_AVAILABLE:
        sys.exit("reportlab is required for PDF output. Install with: pip install reportlab")
    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    y = height - 20
    for line in text.splitlines():
        c.drawString(20, y, line)
        y -= 12
        if y < 20:
            c.showPage()
            y = height - 20
    c.save()

def compose_header(scan_dir: Path, duration: float, timestamp: _dt.datetime) -> str:
    return (
        f"Scan directory: {scan_dir}\n"
        f"Timestamp: {timestamp:%Y-%m-%d %H:%M:%S}\n"
        f"Duration: {duration:.2f} seconds\n\n"
    )

def main() -> None:
    examples = (
        """
  Examples:
    bldd -d /usr/bin -o report.txt                # plain text report
    bldd -d /usr/bin -o report.txt --full         # no truncation
    bldd -d /opt/firmware -o deps.pdf             # PDF output
    """
    )

    p = argparse.ArgumentParser(
        prog="bldd",
        description="Reverse LDD: list executables depending on shared libraries",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-d", "--dir", default="/", help="root directory to scan")
    p.add_argument("--max-depth", type=int, default=5, help="maximum recursion depth")
    p.add_argument("-o", "--output", default=None, help="report file (.txt or .pdf)")
    p.add_argument(
        "--full",
        action="store_true",
        help="do not truncate executable lists (show every file)",
    )
    args = p.parse_args()

    root = Path(args.dir)
    print(f"[bldd] Scanning {root} ...")
    start = time.perf_counter()
    elves = walk_elves(root, args.max_depth)
    print(f"[bldd] ELF files found: {len(elves)}")

    index = build_index(elves)
    duration = time.perf_counter() - start
    timestamp = _dt.datetime.now()

    body = generate_report(index, full=args.full)
    report = compose_header(root, duration, timestamp) + body

    try:
        if args.output:
            out_path = Path(args.output)
            if out_path.suffix.lower() == ".pdf":
                save_pdf(report, out_path)
            else:
                out_path.write_text(report, encoding="utf-8")
            print(f"[bldd] Report saved to {out_path}")
        else:
            print(report)
    except BrokenPipeError:
        pass

if __name__ == "__main__":
    main()
