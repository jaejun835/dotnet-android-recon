#!/usr/bin/env python3
"""
extract_assembly_store.py - extract managed .NET assemblies from a .NET for
Android / Xamarin / .NET MAUI app's assembly store.

The store is wrapped in an ELF shared library (libassembly-store.so) or, on
older builds, lives in assemblies.blob / libassemblies.<abi>.blob.so. This
reads the XABA store format (v2 and v3, 32- and 64-bit, any ABI), decompresses
LZ4 (XALZ) and Zstandard (XAZS) payloads, and writes each assembly as a .dll.

Usage:
    python3 extract_assembly_store.py libassembly-store.so out_dir
    python3 extract_assembly_store.py store1.so store2.so out_dir
    python3 extract_assembly_store.py ./unpacked_apk out_dir   # scans for stores

Needs lz4 for XALZ (python3 -m pip install --user lz4) and, if the app uses
XAZS, zstandard (python3 -m pip install --user zstandard). Install only when a
payload actually needs it.

Format reference: dotnet/android Documentation/project-docs/AssemblyStores.md
"""
import argparse
import os
import struct
import sys

XABA = b"XABA"          # store magic, little-endian 0x41424158
XALZ = 0x5A4C4158       # 'XALZ' LZ4
XAZS = 0x535A4158       # 'XAZS' Zstandard

ABI_NAMES = {0x00010000: "arm64-v8a", 0x00020000: "armeabi-v7a",
             0x00030000: "x86_64", 0x00040000: "x86"}
VERSION_MASK = 0xF0000000
ABI_MASK = 0x00FF0000
FMT_MASK = 0x0000FFFF


def decode_version(version):
    is_64 = bool(version & VERSION_MASK)
    abi = ABI_NAMES.get(version & ABI_MASK, "unknown")
    fmt = version & FMT_MASK
    return is_64, abi, fmt


def decompress(blob, name):
    """Return (data, kind). kind is 'plain'|'lz4'|'zstd'."""
    if len(blob) < 4:
        return blob, "plain"
    magic = struct.unpack_from("<I", blob, 0)[0]
    if magic == XALZ:
        try:
            import lz4.block
        except ImportError:
            raise RuntimeError("LZ4 payload needs the lz4 module: python3 -m pip install --user lz4")
        out_len = struct.unpack_from("<I", blob, 8)[0]
        return lz4.block.decompress(blob[12:], uncompressed_size=out_len), "lz4"
    if magic == XAZS:
        try:
            import zstandard
        except ImportError:
            raise RuntimeError("Zstandard payload needs the zstandard module: python3 -m pip install --user zstandard")
        out_len = struct.unpack_from("<I", blob, 8)[0]
        return zstandard.ZstdDecompressor().decompress(blob[12:], max_output_size=out_len), "zstd"
    return blob, "plain"


def parse_store(path):
    """Yield (name, data, kind) for every assembly in one store file."""
    data = open(path, "rb").read()
    base = data.find(XABA)
    if base < 0:
        raise RuntimeError(f"{path}: no XABA store magic found (not an assembly store?)")

    magic, version, count, index_count, index_size = struct.unpack_from("<5I", data, base)
    is_64, abi, fmt = decode_version(version)
    print(f"{path}")
    print(f"  version 0x{version:08x}  format v{fmt}  {'64' if is_64 else '32'}-bit  abi={abi}  assemblies={count}")
    if fmt not in (2, 3):
        print(f"  WARNING: format v{fmt} is not v2/v3; parsing may be wrong (v1 uses a separate manifest).")

    # layout: header(20) + index(index_size) + descriptors(count*28) + names + data
    pos = base + 20 + index_size
    descriptors = []
    for _ in range(count):
        descriptors.append(struct.unpack_from("<7I", data, pos))  # mapping, data_off, data_size, dbg_off, dbg_size, cfg_off, cfg_size
        pos += 28
    names = []
    for _ in range(count):
        (nlen,) = struct.unpack_from("<I", data, pos)
        pos += 4
        names.append(data[pos:pos + nlen].decode("utf-8", "replace"))
        pos += nlen

    for name, d in zip(names, descriptors):
        off, size = d[1], d[2]
        blob = data[base + off: base + off + size]
        yield name, blob


def find_stores(root):
    hits = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f == "libassembly-store.so" or (f.startswith("libassemblies.") and f.endswith(".blob.so")) \
               or f == "assemblies.blob":
                hits.append(os.path.join(dirpath, f))
    return sorted(hits)


def main():
    ap = argparse.ArgumentParser(description="Extract .NET assemblies from an Android assembly store.")
    ap.add_argument("inputs", nargs="+", help="store file(s), and/or a directory to scan; last arg is the output dir")
    args = ap.parse_args()

    *inputs, out_dir = args.inputs
    if not inputs:
        ap.error("need at least one store file/dir plus an output directory")

    stores = []
    for inp in inputs:
        if os.path.isdir(inp):
            found = find_stores(inp)
            if not found:
                print(f"no assembly store found under {inp}", file=sys.stderr)
            stores.extend(found)
        else:
            stores.append(inp)

    os.makedirs(out_dir, exist_ok=True)
    total = {"plain": 0, "lz4": 0, "zstd": 0, "failed": 0, "written": 0}

    for store in stores:
        # one subdir per store so different ABIs don't overwrite each other
        tag = parse_tag(store)
        store_out = os.path.join(out_dir, tag) if len(stores) > 1 else out_dir
        os.makedirs(store_out, exist_ok=True)
        try:
            for name, blob in parse_store(store):
                try:
                    data, kind = decompress(blob, name)
                    total[kind] += 1
                except Exception as e:
                    print(f"  FAILED {name}: {e}", file=sys.stderr)
                    total["failed"] += 1
                    continue
                fname = name if name.endswith(".dll") else name + ".dll"
                target = os.path.join(store_out, fname)
                os.makedirs(os.path.dirname(target) or store_out, exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(data)
                total["written"] += 1
        except Exception as e:
            print(f"  ERROR {store}: {e}", file=sys.stderr)

    print(f"\ntotals: {total}")


def parse_tag(store_path):
    # use the parent abi dir (lib/arm64-v8a/...) or the filename stem as a tag
    parent = os.path.basename(os.path.dirname(store_path))
    if parent in ABI_NAMES.values():
        return parent
    return os.path.splitext(os.path.basename(store_path))[0]


if __name__ == "__main__":
    main()
