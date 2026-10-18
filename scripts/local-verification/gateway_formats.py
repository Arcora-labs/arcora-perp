#!/usr/bin/env python3
"""Gateway on-disk format magics, parsed from the Rust sources that define them.

The drills check the framing of files the real gateway wrote. Reading the magic
from `snapshot.rs` and `rollback_journal.rs` keeps them from carrying a second,
hand-copied value that a format bump would leave behind.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_SOURCE = "crates/gateway/src/snapshot.rs"
JOURNAL_SOURCE = "crates/gateway/src/rollback_journal.rs"
MAGIC_BYTES = 8
_ESCAPES = {"0": 0, "n": 10, "r": 13, "t": 9, "\\": 92, "'": 39, '"': 34}


def byte_string(literal):
    """Decode the body of a Rust `b"..."` literal (ASCII plus simple and \\xNN escapes)."""
    out, index = bytearray(), 0
    while index < len(literal):
        char = literal[index]
        if char != "\\":
            if not (0x20 <= ord(char) < 0x7f):
                raise ValueError("non-ASCII byte string literal")
            out.append(ord(char))
            index += 1
            continue
        escape = literal[index + 1:index + 2]
        if escape == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", literal[index + 2:index + 4]):
            out.append(int(literal[index + 2:index + 4], 16))
            index += 4
        elif escape in _ESCAPES:
            out.append(_ESCAPES[escape])
            index += 2
        else:
            raise ValueError("unsupported byte string escape")
    return bytes(out)


def rust_magic(relative, name, root=None):
    """The exactly-one `const NAME: &[u8; 8] = b"...";` definition in a Rust source file."""
    text = ((ROOT if root is None else Path(root)) / relative).read_text()
    pattern = r'^\s*(?:pub(?:\([a-z]+\))?\s+)?const\s+%s\s*:\s*&\[u8;\s*(\d+)\]\s*=\s*b"((?:[^"\\]|\\.)*)"\s*;' % re.escape(name)
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"expected one {name} definition in {relative}, found {len(matches)}")
    size, literal = matches[0]
    value = byte_string(literal)
    if int(size) != MAGIC_BYTES or len(value) != MAGIC_BYTES:
        raise ValueError(f"{name} in {relative} is not an {MAGIC_BYTES}-byte magic")
    return value


def snapshot_magic(root=None):
    """The magic every snapshot (and sealed rollback journal) file the gateway writes starts with."""
    return rust_magic(SNAPSHOT_SOURCE, "MAGIC", root)


def journal_magic(root=None):
    """The plaintext magic of a rollback journal."""
    return rust_magic(JOURNAL_SOURCE, "MAGIC", root)


def candidate_journal_magic(root=None):
    """The plaintext magic of a candidate-lane rollback journal."""
    return rust_magic(JOURNAL_SOURCE, "CANDIDATE_MAGIC", root)


if __name__ == "__main__":
    for label, value in (("snapshot", snapshot_magic()), ("journal", journal_magic()),
                         ("candidate_journal", candidate_journal_magic())):
        print(label, value)
