#!/usr/bin/env python3
import argparse, hashlib, re, subprocess, sys

def swap32(v): return ((v<<24)&0xFF000000)|((v<<8)&0x00FF0000)|((v>>8)&0x0000FF00)|((v>>24)&0xFF)

def cpuid():
    out = subprocess.check_output(["cpuid", "-r", "-l", "1"], text=True)
    eax = int(re.search(r"eax=0x([0-9a-f]{8})", out, re.I).group(1), 16)
    edx = int(re.search(r"edx=0x([0-9a-f]{8})", out, re.I).group(1), 16)
    return eax, edx

def hwid():
    eax, edx = cpuid()
    return f"{swap32(eax):08X}{swap32(edx):08X}"

def key(h): return "".join(f"{b:02x}" for b in hashlib.md5(h.encode()).digest()[::-1])

if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("--id", help="override HWID (16 hex)")
    args = a.parse_args()
    hw = args.id or hwid()
    if not re.fullmatch(r"[0-9A-F]{16}", hw): sys.exit("HWID missing; use --id")
    print(key(hw))
