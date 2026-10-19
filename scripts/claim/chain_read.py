"""Read-only L1 access shared by the gateway-free claim tools.

A small JSON-RPC client with a fixed read-only method allowlist, plus ABI word
helpers. It never signs or sends a transaction: the tools print `cast send`
commands for the user to sign with their own wallet. Neither diagnostics nor
printed commands echo the RPC URL (it may carry a provider key in its path or
query) or provider error text: a printed command reads the URL from the shell
variable RPC_URL.
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from claim_withdrawal import keccak256

READ_METHODS = frozenset({
    "eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_call",
    "eth_getLogs", "eth_getTransactionReceipt",
})
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 30
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
DIGEST = re.compile(r"0x[0-9a-fA-F]{64}")


class ChainError(RuntimeError):
    """A locally built diagnostic; never contains provider text or the URL."""


class Reverted(ChainError):
    """An eth_call reverted; `selector` is the 4-byte error selector, if any."""

    def __init__(self, selector):
        super().__init__("call reverted" + (f" ({selector})" if selector else ""))
        self.selector = selector


def plain_rpc(value):
    parts = urllib.parse.urlsplit(value)
    if (parts.scheme not in ("http", "https") or not parts.hostname
            or parts.username or parts.password or parts.fragment):
        raise ValueError("--rpc must be an http(s) URL without user info or fragment")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ChainError("RPC redirects are not followed")


class HttpRPC:
    """`rpc(method, params)` over HTTP JSON-RPC, read-only methods only."""

    def __init__(self, url):
        self.url = plain_rpc(url)
        self.sequence = 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def __call__(self, method, params):
        if method not in READ_METHODS:
            raise ChainError("RPC method outside the read-only allowlist")
        self.sequence += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params})
        request = urllib.request.Request(self.url, data=body.encode(), headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            error.close()
            raise ChainError(f"RPC HTTP status {error.code}") from None
        except ChainError:
            raise
        except Exception as error:
            raise ChainError(f"RPC transport failed ({type(error).__name__})") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ChainError("RPC response exceeds the size limit")
        try:
            value = json.loads(raw)
        except ValueError:
            raise ChainError("RPC returned invalid JSON") from None
        if not isinstance(value, dict) or value.get("jsonrpc") != "2.0" or value.get("id") != self.sequence:
            raise ChainError("invalid JSON-RPC response envelope")
        if "error" in value:
            error = value["error"] if isinstance(value["error"], dict) else {}
            if method == "eth_call" and is_revert(error):
                raise Reverted(revert_selector(error.get("data")))
            raise ChainError(f"RPC error for {method}")
        if "result" not in value:
            raise ChainError("RPC response has no result")
        return value["result"]


def is_revert(error):
    """Whether a JSON-RPC error object reports an EVM revert (not a transport/limit error)."""
    message = error.get("message")
    return (error.get("code") == 3 or revert_selector(error.get("data")) is not None
            or (isinstance(message, str) and message.lower().startswith("execution reverted")))


def revert_selector(data):
    """The 4-byte selector of revert data (a hex string, or {"data": hex}), else None."""
    if isinstance(data, dict):
        data = data.get("data")
    if isinstance(data, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2}){4,}", data):
        return data[:10].lower()
    return None


def selector(signature):
    return "0x" + keccak256(signature.encode()).hex()[:8]


def topic(signature):
    return "0x" + keccak256(signature.encode()).hex()


def error_names(*signatures):
    """{selector: name} for custom errors, for readable revert reports."""
    return {selector(s): s.split("(")[0] for s in signatures}


def word(value):
    """One ABI word (hex, no 0x) for an int, bool, address or bytes32 hex string."""
    if type(value) is bool:
        value = int(value)
    if type(value) is int:
        if not 0 <= value < 1 << 256:
            raise ValueError("value does not fit uint256")
        return format(value, "064x")
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,64}", value):
        return value[2:].lower().rjust(64, "0")
    raise ValueError("unsupported ABI value")


def calldata(signature, *args):
    return selector(signature) + "".join(word(a) for a in args)


def quantity(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        raise ChainError("invalid RPC quantity")
    return int(value, 16)


def data_bytes(value, size=None):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value):
        raise ChainError("invalid RPC data")
    raw = bytes.fromhex(value[2:])
    if size is not None and len(raw) != size:
        raise ChainError("unexpected ABI return size")
    return raw


def words(raw):
    return [raw[i:i + 32] for i in range(0, len(raw), 32)]


def as_address(chunk):
    if chunk[:12] != bytes(12):
        raise ChainError("noncanonical ABI address")
    return "0x" + chunk[12:].hex()


def as_bool(chunk):
    value = int.from_bytes(chunk, "big")
    if value > 1:
        raise ChainError("noncanonical ABI bool")
    return value == 1


class Reader:
    """eth_call helpers pinned to one block for a consistent view."""

    def __init__(self, rpc, block="latest"):
        self.rpc = rpc
        self.block = block

    def call(self, to, signature, *args, size=32, sender=None, value=None):
        tx = {"to": to, "data": calldata(signature, *args)}
        if sender is not None:
            tx["from"] = sender
        if value is not None:
            tx["value"] = hex(value)
        return data_bytes(self.rpc("eth_call", [tx, self.block]), size)

    def uint(self, to, signature, *args):
        return int.from_bytes(self.call(to, signature, *args), "big")

    def address(self, to, signature, *args):
        return as_address(self.call(to, signature, *args))

    def boolean(self, to, signature, *args):
        return as_bool(self.call(to, signature, *args))

    def bytes32(self, to, signature, *args):
        return "0x" + self.call(to, signature, *args).hex()

    def simulate(self, to, signature, *args, sender=None, value=None):
        """None when the call would succeed now, else the revert selector (or "")."""
        tx = {"to": to, "data": calldata(signature, *args)}
        if sender is not None:
            tx["from"] = sender
        if value is not None:
            tx["value"] = hex(value)
        try:
            self.rpc("eth_call", [tx, self.block])
        except Reverted as reverted:
            return reverted.selector or ""
        return None


def pin_latest(rpc):
    """(number, timestamp) of the latest block, as the block the reads use."""
    block = rpc("eth_getBlockByNumber", ["latest", False])
    if not isinstance(block, dict):
        raise ChainError("missing latest block")
    return quantity(block.get("number")), quantity(block.get("timestamp"))


RPC_URL_ARG = '"$RPC_URL"'
RPC_URL_NOTE = ('the commands below read the RPC URL from $RPC_URL and this tool never prints it; '
                'run `export RPC_URL=<your RPC URL>` first')


def cast_send(to, signature, args, rpc_label=None, value=None):
    """A `cast send` line for the user to sign; its RPC URL is `"$RPC_URL"`, read from the shell.

    No URL is ever printed, whatever the caller passes: `rpc_label` is accepted for
    callers that still pass one, and ignored.
    """
    parts = ["cast send", to, f'"{signature}"', *[str(a) for a in args]]
    if value is not None:
        parts += ["--value", str(value)]
    return " ".join(parts + ["--rpc-url", RPC_URL_ARG, "<YOUR_SIGNER>"])


def noting_rpc_url(out):
    """`out` that writes RPC_URL_NOTE once, on the line before the first `cast send`."""
    noted = False

    def write(line):
        nonlocal noted
        if not noted and line.lstrip().startswith("cast send"):
            noted = True
            out("  " + RPC_URL_NOTE)
        out(line)
    return write
