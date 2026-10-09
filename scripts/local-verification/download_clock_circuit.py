#!/usr/bin/env python3
"""Download only the pinned public SP1 circuit files into a fresh owned directory.
Streaming extraction avoids storing a second 6 GB archive. Paths, sizes, archive
hash and each extracted file hash are checked before proving is permitted.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

URL = "https://sp1-circuits.s3-us-east-2.amazonaws.com/v6.1.0-groth16.tar.gz"
ARCHIVE_SHA256 = "18beebb6cd0cc9b4d4a240ee4f49511da6c2a7e51724bad4232de538a9147810"
ARCHIVE_SIZE = 6211807514
FILES = {
    "groth16_vk.bin": (492, "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"),
    "groth16_circuit.bin": (2437991441, "d6a66be2702206e2b1a20bebf7096142864feac9e399a309e5e6e00353264cbc"),
    "groth16_pk.bin": (5862173061, "c3760e0e3b58487f8704680d5b3ad32a9fbca9f3cb0749d69055c4f1271ca167"),
}
class HashedStream:
    def __init__(self, response):
        self.response, self.digest, self.count = response, hashlib.sha256(), 0
    def read(self, count=-1):
        data = self.response.read(count)
        self.digest.update(data)
        self.count += len(data)
        if self.count > ARCHIVE_SIZE:
            raise ValueError("oversized circuit archive")
        return data

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    request = urllib.request.Request(URL, headers={"Accept-Encoding": "identity"})
    found = {}
    with urllib.request.urlopen(request, timeout=120) as response:
        stream = HashedStream(response)
        with tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for entry in archive:
                parts = Path(entry.name).parts
                if entry.isdir():
                    continue
                if not entry.isfile() or ".." in parts or Path(entry.name).is_absolute():
                    raise ValueError("unsafe archive member")
                name = parts[-1]
                if name not in FILES:
                    # Ignore unneeded regular upstream files, but never extract them.
                    continue
                size, expected = FILES[name]
                if name in found or entry.size != size:
                    raise ValueError("duplicate or wrong-sized circuit file")
                digest = hashlib.sha256()
                source = archive.extractfile(entry)
                with (args.output / name).open("xb") as target:
                    while block := source.read(1024 * 1024):
                        digest.update(block)
                        target.write(block)
                if digest.hexdigest() != expected:
                    raise ValueError("circuit file hash mismatch")
                found[name] = {"size": size, "sha256": expected}
                print("VERIFIED", name, flush=True)
        while stream.read(1024 * 1024):
            pass
        if stream.count != ARCHIVE_SIZE or stream.digest.hexdigest() != ARCHIVE_SHA256:
            raise ValueError("circuit archive identity mismatch")
    if set(found) != set(FILES):
        raise ValueError("missing circuit files")
    (args.output / "verified.json").write_text(json.dumps({"archive_sha256": ARCHIVE_SHA256, "files": found}, indent=2))
    print("PINNED_CIRCUIT_VERIFIED", flush=True)
if __name__ == "__main__":
    main()
