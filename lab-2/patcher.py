#!/usr/bin/env python3
import argparse, os, stat, sys

OFF = 0x159e          # смещение в файле
ORIG = b"\x75\x07"
PATCH = b"\x90\x90"

def patch(src, dst):
    data = bytearray(open(src, "rb").read())
    if data[OFF:OFF+2] != ORIG:
        sys.exit("unexpected bytes at offset")
    data[OFF:OFF+2] = PATCH
    open(dst, "wb").write(data)
    os.chmod(dst, os.stat(src).st_mode | stat.S_IXUSR)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("infile")
    p.add_argument("outfile")
    args = p.parse_args()
    patch(args.infile, args.outfile)
