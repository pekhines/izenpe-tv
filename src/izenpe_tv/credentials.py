"""Extract the OAuth client credentials from the user's own copy of the official app.

The official Windows app (TarjetaVirtual-Setup-<ver>.msi, downloadable from Izenpe)
embeds a confidential OAuth client: a client_id and the client_secret candidates.
This project does not redistribute them; instead `izenpe-tv setup-credentials` reads
them from the installer (or from the extracted TarjetaVirtual.exe) on the user's machine.

Pure Python, no external tools: a minimal OLE/CFB reader to find the cabinet stream(s)
inside the MSI, and a minimal CAB reader (uncompressed or MSZIP folders).
"""
from __future__ import annotations

import os
import re
import struct
import zlib

CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
CAB_MAGIC = b"MSCF"
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF


class CredentialsError(Exception):
    pass


# ----------------------------------------------------------------------- OLE / CFB

def _cfb_streams(buf: bytes):
    """Yield (name, data) for every regular-FAT stream of a CFB (MSI) file."""
    if buf[:8] != CFB_MAGIC:
        raise CredentialsError("not an MSI/OLE file")
    ssize = 1 << struct.unpack_from("<H", buf, 0x1E)[0]
    n_fat, first_dir = struct.unpack_from("<II", buf, 0x2C)
    cutoff = struct.unpack_from("<I", buf, 0x38)[0]
    first_difat, n_difat = struct.unpack_from("<II", buf, 0x44)

    def sector(sid: int) -> bytes:
        off = (sid + 1) * ssize
        return buf[off:off + ssize]

    per = ssize // 4
    difat = list(struct.unpack_from("<109I", buf, 0x4C))
    sid = first_difat
    for _ in range(n_difat):
        if sid in (ENDOFCHAIN, FREESECT):
            break
        vals = struct.unpack(f"<{per}I", sector(sid))
        difat.extend(vals[:-1])
        sid = vals[-1]
    fat: list[int] = []
    for s in difat[:n_fat]:
        fat.extend(struct.unpack(f"<{per}I", sector(s)))

    def chain(sid: int) -> bytes:
        out, seen = [], set()
        while sid not in (ENDOFCHAIN, FREESECT) and sid < len(fat) and sid not in seen:
            seen.add(sid)
            out.append(sector(sid))
            sid = fat[sid]
        return b"".join(out)

    dirs = chain(first_dir)
    for off in range(0, len(dirs) - 127, 128):
        e = dirs[off:off + 128]
        nlen = struct.unpack_from("<H", e, 64)[0]
        etype = e[66]
        start, size = struct.unpack_from("<IQ", e, 116)
        if etype != 2 or size < cutoff:      # only regular streams (cabinets are big)
            continue
        if ssize == 512:
            size &= 0xFFFFFFFF
        name = e[:max(nlen - 2, 0)].decode("utf-16-le", "replace")
        yield name, chain(start)[:size]


# ----------------------------------------------------------------------- CAB

def _cab_data(cab: bytes) -> bytes:
    """Return the concatenated uncompressed contents of every folder of a cabinet."""
    if cab[:4] != CAB_MAGIC:
        raise CredentialsError("not a cabinet")
    n_folders, _n_files, flags = struct.unpack_from("<HHH", cab, 26)
    p = 36
    res_folder = res_data = 0
    if flags & 0x0004:                       # cfhdrRESERVE_PRESENT
        res_hdr, res_folder, res_data = struct.unpack_from("<HBB", cab, p)
        p += 4 + res_hdr
    for flag in (0x0001, 0x0002):            # prev / next cabinet names: skip
        if flags & flag:
            for _ in range(2):
                p = cab.index(b"\0", p) + 1
    out = []
    for _ in range(n_folders):
        start, n_data, ctype = struct.unpack_from("<IHH", cab, p)
        p += 8 + res_folder
        method = ctype & 0x000F
        if method not in (0, 1):
            raise CredentialsError(
                "the installer uses LZX/Quantum compression, which is not supported; "
                "extract TarjetaVirtual.exe with `msiextract` or `7z x` and pass the .exe")
        q, hist = start, b""
        for _ in range(n_data):
            cb, ucb = struct.unpack_from("<HH", cab, q + 4)
            q += 8 + res_data
            blk = cab[q:q + cb]
            q += cb
            if method == 0:
                chunk = blk
            else:
                if blk[:2] != b"CK":
                    raise CredentialsError("bad MSZIP block")
                d = zlib.decompressobj(-15, zdict=hist) if hist else zlib.decompressobj(-15)
                chunk = d.decompress(blk[2:]) + d.flush()
                hist = (hist + chunk)[-32768:]
            out.append(chunk[:ucb])
    return b"".join(out)


# ----------------------------------------------------------------------- strings

_SECRET_RE = re.compile(r"^[A-Za-z0-9]{8,64}$")


def _looks_like_secret(s: str) -> bool:
    return (bool(_SECRET_RE.match(s)) and any(c.isdigit() for c in s)
            and any(c.islower() for c in s) and any(c.isupper() for c in s))


def find_credentials(blob: bytes) -> tuple[str | None, list[str]]:
    """Find (client_id, secret candidates) in the strings of TarjetaVirtual.exe.

    In v4.0.x the strings appear in this order:
        ... app_locale, <client_id>, oauth_profile, legacy, "OAuth profile: ",
        ideable, 1d34bl3_g1ltz4, 1d34bl3_g1ltz4_pr0d, <secret>, <secret>, ...
    """
    strings = [m.group().decode() for m in re.finditer(rb"[\x20-\x7e]{4,}", blob)]
    client_id = None
    secrets: list[str] = []
    for i, s in enumerate(strings):
        if s == "oauth_profile" and i > 0 and client_id is None:
            cand = strings[i - 1]
            if re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", cand):
                client_id = cand
        if s.startswith("OAuth profile"):
            for t in strings[i + 1:i + 12]:
                if _looks_like_secret(t) and t not in secrets:
                    secrets.append(t)
    return client_id, secrets


_EXTRACTORS = (  # (binary, argv builder) — tried in order for LZX-compressed MSIs
    ("7z", lambda msi, out: ["x", "-y", f"-o{out}", msi]),
    ("7zz", lambda msi, out: ["x", "-y", f"-o{out}", msi]),
    ("7za", lambda msi, out: ["x", "-y", f"-o{out}", msi]),
    ("msiextract", lambda msi, out: ["-C", out, msi]),
)

TOOLS_HINT = ("install one of: 7zip / p7zip (`7z`) or msitools (`msiextract`), e.g.\n"
              "  Debian/Ubuntu: sudo apt install 7zip      Fedora: sudo dnf install 7zip\n"
              "  Arch: sudo pacman -S 7zip                 openSUSE: sudo zypper in 7zip")


def _extract_with_tool(msi: str) -> tuple[str | None, list[str]]:
    import shutil
    import subprocess
    import tempfile
    tried = []
    for tool, argv in _EXTRACTORS:
        exe = shutil.which(tool)
        if not exe:
            continue
        tried.append(tool)
        with tempfile.TemporaryDirectory(prefix="izenpe-tv-msi-") as out:
            r = subprocess.run([exe, *argv(os.path.abspath(msi), out)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode != 0:
                continue
            # biggest-first: the main exe is near the top; stop at the first hit
            files = []
            for root, _dirs, names in os.walk(out):
                files += [os.path.join(root, n) for n in names]
            for fp in sorted(files, key=lambda p: "TarjetaVirtual" not in p):
                with open(fp, "rb") as f:
                    blob = f.read()
                if blob[:2] != b"MZ":
                    continue
                cid, secs = find_credentials(blob)
                if secs:
                    return cid, secs
    if not tried:
        raise CredentialsError("the installer is LZX-compressed and no extractor was found;\n"
                               + TOOLS_HINT)
    return None, []


def extract(path: str) -> tuple[str | None, list[str]]:
    """Accept the official .msi or the extracted TarjetaVirtual.exe."""
    with open(path, "rb") as f:
        buf = f.read()
    if buf[:8] != CFB_MAGIC:
        return find_credentials(buf)
    for _name, data in _cfb_streams(buf):
        if data[:4] != CAB_MAGIC:
            continue
        try:
            cid, secs = find_credentials(_cab_data(data))
        except CredentialsError:          # LZX: fall back to an external extractor
            return _extract_with_tool(path)
        if secs:
            return cid, secs
    return _extract_with_tool(path)


def config_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "izenpe-tv", "client.toml")


def write_config(client_id: str, secrets: list[str], path: str | None = None) -> str:
    path = path or config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    body = (
        "# Extracted by `izenpe-tv setup-credentials` from the official Izenpe app.\n"
        "# Do not share this file or commit it anywhere.\n"
        f'client_id = "{client_id}"\n'
        "client_secrets = [" + ", ".join(f'"{s}"' for s in secrets) + "]\n"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(body)
    return path
