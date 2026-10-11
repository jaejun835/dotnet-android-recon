# dotnet-android-recon

Two small, dependency-light recon helpers for **.NET for Android / Xamarin / .NET MAUI** apps.

These apps compile their managed code into .NET assemblies and pack them into an
**assembly store** (libassembly-store.so), not into the usual classes.dex. So a normal
jadx pass shows only the Android glue, and the real API logic lives in the .dll files
inside that store. These scripts get at it:

1. extract_assembly_store.py - pull the .dll assemblies out of the store.
2. attack_surface.py - triage hosts, API paths, auth/token strings and likely secrets
   out of strings output or a decompiled source tree.

Neither script is hardcoded to any target, and neither talks to the network. They are
triage aids for your own analysis, not a judgement - review the raw hits yourself.

## Why

- .NET for Android assembly stores wrap the managed .dll files in an ELF shared library
  whose payload starts at the XABA magic. Assemblies are usually LZ4 (XALZ) and, on newer
  builds, Zstandard (XAZS) compressed.
- Format reference: https://github.com/dotnet/android/blob/main/Documentation/project-docs/AssemblyStores.md

## Requirements

- Python 3.8+
- lz4 for XALZ payloads, zstandard for XAZS payloads. Install only what a store actually
  uses; prefer per-user pip so the system Python is left alone:

```
python3 -m pip install --user lz4
python3 -m pip install --user zstandard   # only if the app uses XAZS
```

## Usage

### 1. Extract assemblies from the store

```
# single store
python3 extract_assembly_store.py libassembly-store.so out_assemblies

# or point it at an unpacked APK/AAB dir; it finds the stores itself
python3 extract_assembly_store.py ./unpacked_apk out_assemblies
```

It prints the store version, bitness, ABI and assembly count, then writes each .dll.
When several stores are given it splits output per ABI so they do not overwrite.

Getting the store out of a split APK first:

```
unzip -o config.arm64_v8a.apk 'lib/*/libassembly-store.so' -d native_libs
```

### 2. Triage the attack surface

```
# straight from strings on the app's own assemblies
strings -el out_assemblies/App.dll | python3 attack_surface.py -

# or over a decompiled source tree
python3 attack_surface.py ./decompiled_src --ext cs,xml,json
```

Output sections: in-scope hosts, third-party hosts, API path markers, folded image/asset
handlers, identifier params (IDOR candidates), auth/token/session strings, and secret
candidates.

Flags:

- --noise foo,bar  add extra substrings to treat as third-party/noise
- --keep foo,bar   force-keep lines even if they look like noise
- --max N          cap lines shown per section

## Notes

- Static analysis finds candidates only. Whether the server enforces access control on a
  given endpoint must be confirmed against the live service, within whatever program or
  authorization you are operating under.
- attack_surface.py is a filter, so it can quietly drop something important. On a real
  target, read the raw strings output once as well.
