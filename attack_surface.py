#!/usr/bin/env python3
"""
attack_surface.py - extract an app's attack surface from strings output or a
decompiled source tree.

It pulls out hosts, API path markers, auth/token-related strings and likely
hardcoded secrets, folds down repeated image/CDN URLs, and drops common
third-party SDK noise (ads, analytics, crash reporting).

Usage:
    strings -el app.dll | python3 attack_surface.py -
    python3 attack_surface.py dump.txt
    python3 attack_surface.py ./decompiled_src --ext cs,xml,json

Nothing is hardcoded to a specific target. Review the raw hits yourself; this
is a triage aid, not a judgement.
"""
import argparse
import os
import re
import sys

# Third-party SDK / tracker noise. Hosts matching these are listed separately
# under "third_party" instead of "hosts", and their lines are dropped from the
# auth/secret scans. Extend with --noise.
DEFAULT_NOISE = [
    "criteo", "sentry", "crashlytics", "firebaseio", "firebase",
    "google-analytics", "googletagmanager", "googleapis", "gstatic",
    "doubleclick", "facebook", "fb.com", "fbcdn", "appsflyer", "adjust.com",
    "branch.io", "onelink.me", "bugsnag", "datadog", "newrelic", "segment.io",
    "amplitude", "mixpanel", "braze", "batch.com", "didomi", "onetrust",
    "cookielaw", "apple.com", "itunes.apple", "play.google", "licensing",
    "schemas.xmlsoap", "schemas.android", "w3.org", "microsoft.com/schemas",
]

URL_RE = re.compile(r"https?://[^\s\"'<>)\\]+", re.I)
HOST_RE = re.compile(r"https?://([a-z0-9.\-]+)", re.I)
# strip a leading shard prefix like fd12- so fd1-courses and fd9-courses fold together
SHARD_RE = re.compile(r"^fd\d+-", re.I)
# A real host has at least one dot and a sane TLD, or is localhost / an IP.
# This drops truncated fragments (fd, infomil-j) and bare hex (Sentry DSN ids).
HOST_OK_RE = re.compile(r"^(localhost|(\d{1,3}\.){3}\d{1,3}|[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,})$", re.I)
HEX_ONLY_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)

AUTH_RE = re.compile(
    r"token|bearer|oauth|oidc|authoriz|authentic|\bauth\b|\blogin\b|logout|"
    r"\bsession\b|set-cookie|cookieset|cookie-set|\bjwt\b|refresh_token|"
    r"access_token|id_token|code[_ -]?secret|codesecret|\bpassword\b|"
    r"mot de passe|credential|step.?up|stepup|challenge|captcha|"
    r"\b2fa\b|\bmfa\b|\botp\b|callback|redirect_uri|client_id|"
    r"client_secret|\bnonce\b|oidc_state|pkce|trusted_device",
    re.I,
)

# Store-directory / company-registry rows that collide with 'identifiant',
# and UI translation-resource keys that are display strings, not endpoints.
AUTH_DROP_RE = re.compile(
    r"Identifiant Adressage:|\bSiren:|\bSiret:|"
    r"_(HelpPopup|Description|Descriptif|Titre|Title|Placeholder|CTA|Libelle|"
    r"Header|Subtitle|Infobulle|VoiceOver|Accessibility|Warning|Message|Texte\d*|"
    r"Content|Popup|Erreur|Obligatoire|Field|Entry|Color|Button|Bold|Normal)\b",
    re.I,
)

# High-signal secret shapes. Deliberately conservative to limit false hits.
SECRET_RES = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Bearer literal", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{12,}")),
    ("Generic key=value secret", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|passwd|password|client[_-]?secret|"
        r"access[_-]?token|auth[_-]?token)\b\s*[=:]\s*[\"']?[A-Za-z0-9/+_\-\.]{8,}")),
]

# API path markers: REST-ish paths, versioned APIs, ASP.NET handlers.
API_RE = re.compile(r"(?:/v\d+\b|/api/|API_|\.ash[xz]\b|\.asmx\b|/rest/|/graphql\b)", re.I)

# Image / asset handlers that tend to repeat hundreds of times with only an id
# changing. We fold these: count them, show a couple, and keep them out of the
# api section. Tune with --noise if a target differs.
IMAGE_RE = re.compile(r"(image|visuel\w*|logo\w*|photo\w*|thumb\w*|media)\.ash[xz]\b", re.I)

# Identifier-style query params worth checking for IDOR.
IDPARAM_RE = re.compile(r"[?&]([a-z0-9_]*(?:id|no|num|uid|guid|order|commande|compte|user|client)[a-z0-9_]*)=", re.I)


def is_noise(text, noise):
    low = text.lower()
    return any(n in low for n in noise)


def iter_lines(path, exts):
    if path == "-":
        for line in sys.stdin:
            yield line.rstrip("\n")
        return
    if os.path.isfile(path):
        with open(path, errors="replace") as fh:
            for line in fh:
                yield line.rstrip("\n")
        return
    for root, _, files in os.walk(path):
        for name in files:
            if exts and name.rsplit(".", 1)[-1].lower() not in exts:
                continue
            fp = os.path.join(root, name)
            try:
                with open(fp, errors="replace") as fh:
                    for line in fh:
                        yield line.rstrip("\n")
            except OSError:
                continue


def main():
    ap = argparse.ArgumentParser(description="Extract attack surface from strings/source.")
    ap.add_argument("input", help="'-' for stdin, a file, or a directory")
    ap.add_argument("--ext", default="", help="comma-separated extensions to scan in a dir (e.g. cs,xml,json)")
    ap.add_argument("--noise", default="", help="extra comma-separated noise substrings")
    ap.add_argument("--keep", default="", help="comma-separated substrings to force-keep even if noise")
    ap.add_argument("--max", type=int, default=0, help="cap lines shown per section (0 = no cap)")
    args = ap.parse_args()

    exts = {e.strip().lower().lstrip(".") for e in args.ext.split(",") if e.strip()}
    noise = DEFAULT_NOISE + [n.strip().lower() for n in args.noise.split(",") if n.strip()]
    keep = [k.strip().lower() for k in args.keep.split(",") if k.strip()]

    hosts, third_party = set(), set()
    api_lines, auth_lines, id_params = set(), set(), set()
    secrets = []  # (kind, line)
    image_samples, image_count = set(), 0
    auth_dropped = 0

    for line in iter_lines(args.input, exts):
        if not line.strip():
            continue
        forced = any(k in line.lower() for k in keep)

        for m in HOST_RE.finditer(line):
            host = SHARD_RE.sub("", m.group(1).lower())
            # reject truncated fragments and bare hex (e.g. Sentry DSN ids)
            if not HOST_OK_RE.match(host) or HEX_ONLY_RE.match(host):
                continue
            if is_noise(host, noise) and not forced:
                third_party.add(host)
            else:
                hosts.add(host)

        if IMAGE_RE.search(line) and not forced:
            image_count += 1
            if len(image_samples) < 3:
                image_samples.add(line.strip()[:200])
        elif API_RE.search(line):
            if not is_noise(line, noise) or forced:
                api_lines.add(line.strip()[:200])

        for m in IDPARAM_RE.finditer(line):
            id_params.add(m.group(1).lower())

        if AUTH_RE.search(line) and (not is_noise(line, noise) or forced):
            # skip pure URLs here; hosts already captured them
            if not URL_RE.fullmatch(line.strip()):
                if AUTH_DROP_RE.search(line) and not forced:
                    auth_dropped += 1
                else:
                    auth_lines.add(line.strip()[:200])

        for kind, rx in SECRET_RES:
            for m in rx.finditer(line):
                secrets.append((kind, line.strip()[:200]))

    def dump(title, items, sort=True):
        seq = sorted(items) if sort else items
        if args.max:
            seq = seq[: args.max]
        print(f"\n=== {title} ({len(items)}) ===")
        for it in seq:
            print(it)

    dump("in-scope hosts", hosts)
    dump("third-party hosts (review scope, usually out)", third_party)
    dump("api path markers", api_lines)
    print(f"\n=== image/asset handlers folded ({image_count}) ===")
    for it in sorted(image_samples):
        print(it)
    if image_count > len(image_samples):
        print(f"... and {image_count - len(image_samples)} more (folded)")
    dump("identifier params (IDOR candidates)", id_params)
    dump("auth / token / session strings", auth_lines)
    if auth_dropped:
        print(f"    ({auth_dropped} store-directory / UI-resource lines dropped from this section)")
    print(f"\n=== secret candidates ({len(secrets)}) ===")
    seen = set()
    for kind, line in secrets:
        key = (kind, line)
        if key in seen:
            continue
        seen.add(key)
        print(f"[{kind}] {line}")


if __name__ == "__main__":
    main()
