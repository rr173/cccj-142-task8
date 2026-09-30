"""设备可信证明的密码学原语与规范化。

浏览器侧使用 Web Crypto ECDSA P-256/SHA-256，签名为 IEEE P1363 裸 r||s。
服务端保存公钥并在业务事务内核验；测试客户端使用系统 OpenSSL 模拟终端签名。
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess


class TrustError(ValueError):
    pass


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def canonical_bytes(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def canonical_hash(obj) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def request_digest(*, action, resource, role, body_hash, challenge_id, nonce):
    return canonical_hash({
        "alg": "CONSENT-ATTESTATION/v1",
        "action": action,
        "resource": resource,
        "role": role,
        "body_hash": body_hash,
        "challenge_id": challenge_id,
        "nonce": nonce,
    })


def _run(args, input_bytes=None):
    proc = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        raise TrustError("CRYPTO_FAILED")
    return proc.stdout


def _der_int(value: bytes) -> bytes:
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return b"\x02" + bytes([len(value)]) + value


def _der_length(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    out = []
    while n:
        out.append(n & 255)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(reversed(out))


def _der_sequence(content: bytes) -> bytes:
    return b"\x30" + _der_length(len(content)) + content


def p1363_to_der(signature_b64: str) -> bytes:
    raw = b64url_decode(signature_b64)
    if len(raw) != 64:
        raise TrustError("BAD_SIGNATURE")
    return _der_sequence(_der_int(raw[:32]) + _der_int(raw[32:]))


def jwk_coordinates(public_jwk):
    if not isinstance(public_jwk, dict):
        raise TrustError("BAD_PUBLIC_KEY")
    if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
        raise TrustError("BAD_PUBLIC_KEY")
    if "d" in public_jwk:
        raise TrustError("BAD_PUBLIC_KEY")
    try:
        xb = b64url_decode(public_jwk["x"])
        yb = b64url_decode(public_jwk["y"])
    except Exception:
        raise TrustError("BAD_PUBLIC_KEY")
    if len(xb) != 32 or len(yb) != 32:
        raise TrustError("BAD_PUBLIC_KEY")
    return int.from_bytes(xb, "big"), int.from_bytes(yb, "big")


def public_pem_from_jwk(public_jwk) -> bytes:
    jwk_coordinates(public_jwk)
    point = (b"\x04" + b64url_decode(public_jwk["x"]) +
             b64url_decode(public_jwk["y"]))
    spki = (b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
            b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00" + point)
    pem = (b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(spki) +
           b"-----END PUBLIC KEY-----\n")
    # 让 OpenSSL 完整校验曲线点与 SPKI 结构。
    _run(["openssl", "pkey", "-pubin", "-inform", "PEM", "-noout"], pem)
    return pem


def generate_private_pem() -> bytes:
    pem = _run(["openssl", "genpkey", "-algorithm", "EC",
                "-pkeyopt", "ec_paramgen_curve:P-256"])
    return _run(["openssl", "pkcs8", "-topk8", "-nocrypt"], pem)


def public_jwk_from_private_pem(private_pem: bytes):
    public_pem = _run(["openssl", "pkey", "-pubout"], private_pem)
    text = _run(["openssl", "pkey", "-pubin", "-text", "-noout"], public_pem).decode()
    match = re.search(r"pub:\s*(.*?)\s*ASN1 OID", text, re.S)
    if not match:
        raise TrustError("BAD_PUBLIC_KEY")
    hx = re.sub(r"[\s:]+", "", match.group(1))
    point = bytes.fromhex(hx)
    if len(point) != 65 or point[0] != 4:
        raise TrustError("BAD_PUBLIC_KEY")
    return {
        "kty": "EC", "crv": "P-256",
        "x": b64url_encode(point[1:33]),
        "y": b64url_encode(point[33:65]),
    }


# 兼容测试里“整数私钥”的旧调用形态：值本身是 PEM 字节/字符串。
def public_jwk_from_scalar(priv):
    if isinstance(priv, str):
        priv = priv.encode()
    return public_jwk_from_private_pem(priv)


def verify_ecdsa(public_jwk, message: bytes, signature_b64: str) -> bool:
    try:
        public_pem = public_pem_from_jwk(public_jwk)
        der_sig = p1363_to_der(signature_b64)
        import tempfile
        with tempfile.NamedTemporaryFile() as msg_f, \
                tempfile.NamedTemporaryFile() as sig_f, \
                tempfile.NamedTemporaryFile() as key_f:
            msg_f.write(message); msg_f.flush()
            sig_f.write(der_sig); sig_f.flush()
            key_f.write(public_pem); key_f.flush()
            proc = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", key_f.name,
                 "-signature", sig_f.name, msg_f.name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return proc.returncode == 0 and proc.stdout.strip() == b"Verified OK"
    except Exception:
        return False


def verify_object(public_jwk, obj, signature_b64: str) -> bool:
    return verify_ecdsa(public_jwk, canonical_bytes(obj), signature_b64)


def sign_object(private_pem, obj) -> str:
    """用 PEM 私钥对规范对象生成 P1363 r||s 签名，供测试模拟浏览器。"""
    if isinstance(private_pem, str):
        private_pem = private_pem.encode()
    import tempfile
    with tempfile.NamedTemporaryFile() as key_f, \
            tempfile.NamedTemporaryFile() as msg_f, \
            tempfile.NamedTemporaryFile() as sig_f:
        key_f.write(private_pem); key_f.flush()
        msg_f.write(canonical_bytes(obj)); msg_f.flush()
        _run(["openssl", "pkeyutl", "-sign", "-inkey", key_f.name,
              "-rawin", "-digest", "sha256", "-in", msg_f.name,
              "-out", sig_f.name])
        sig_f.seek(0)
        der_sig = sig_f.read()
    return der_to_p1363(der_sig)


def der_to_p1363(der: bytes) -> str:
    def read_tlv(data, offset):
        if data[offset] != 0x30:
            raise TrustError("BAD_SIGNATURE")
        offset += 1
        length = der[offset]; offset += 1
        if length & 0x80:
            n = length & 0x7f
            length = int.from_bytes(data[offset:offset + n], "big")
            offset += n
        return offset, length

    def read_int(data, offset):
        if data[offset] != 0x02:
            raise TrustError("BAD_SIGNATURE")
        offset += 1
        length = data[offset]; offset += 1
        value = data[offset:offset + length]
        return value.lstrip(b"\0").rjust(32, b"\0"), offset + length

    off, _ = read_tlv(der, 0)
    r, off = read_int(der, off)
    s, _ = read_int(der, off)
    if len(r) != 32 or len(s) != 32:
        raise TrustError("BAD_SIGNATURE")
    return b64url_encode(r + s)
