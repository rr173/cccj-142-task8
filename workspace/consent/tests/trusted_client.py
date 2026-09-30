"""可信设备 HTTP 测试客户端：模拟浏览器 P-256 终端的登记、挑战与证明。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import trust  # noqa: E402
from client import call, BASE  # noqa: E402


def body_hash(body):
    return trust.canonical_hash({k: v for k, v in (body or {}).items()
                                 if k != "idempotency_key"})


_KEY_CACHE = {}


def make_key(seed):
    if seed not in _KEY_CACHE:
        _KEY_CACHE[seed] = trust.generate_private_pem().decode()
    return _KEY_CACHE[seed]


class TrustedClient:
    def __init__(self, token, user, private_seed=None, hardware=None):
        self.token = token
        self.user = user
        self.private = make_key(private_seed or ("key:" + user["id"]))
        self.public_jwk = trust.public_jwk_from_scalar(self.private)
        self.hardware_id = hardware or ("HW-" + user["id"] + "-" + (private_seed or "default"))
        self.credential_id = None

    def raw(self, method, path, body=None, idem=None):
        return call(method, path, body, self.token, idem)

    def register(self, admin_token=None):
        code, r = call("POST", "/api/admin/device-enrollments",
                       {"user_id": self.user["id"]}, admin_token or self.token)
        assert code == 201, r
        csr = {
            "alg": "CONSENT-REGISTER-CSR/v1",
            "enrollment_code": r["enrollment_code"],
            "hardware_id": self.hardware_id,
            "device_label": f"测试终端-{self.user['login']}",
            "public_jwk": self.public_jwk,
        }
        code, reg = call("POST", "/api/devices/register", {
            "enrollment_code": r["enrollment_code"],
            "hardware_id": self.hardware_id,
            "device_label": csr["device_label"],
            "public_jwk": self.public_jwk,
            "csr_sig": trust.sign_object(self.private, csr),
        }, self.token)
        assert code == 201, reg
        self.credential_id = reg["credential_id"]
        return reg

    def raw_challenge(self, action, resource, payload, *, role=None, witness_token=None):
        req = {
            "credential_id": self.credential_id,
            "action": action,
            "resource": resource,
            "role": role,
            "body_hash": body_hash(payload),
            "witness_token": witness_token,
        }
        return call("POST", "/api/devices/challenge", req, self.token)

    def challenge(self, action, resource, payload, *, role=None, witness_token=None):
        code, ch = self.raw_challenge(
            action, resource, payload, role=role, witness_token=witness_token)
        assert code == 201, ch
        digest = body_hash(payload)
        req_hash = trust.request_digest(
            action=action, resource=resource, role=role,
            body_hash=digest, challenge_id=ch["challenge_id"], nonce=ch["nonce"])
        attestation = {
            "challenge_id": ch["challenge_id"],
            "nonce": ch["nonce"],
            "credential_id": self.credential_id,
            "role": role,
            "request_hash": req_hash,
            "terminal_signature": trust.sign_object(
                self.private, {"alg": "CONSENT-ATTESTATION/v1", "request_hash": req_hash}),
        }
        return attestation

    def __call__(self, method, path, body=None, idem=None, *, action=None, resource=None,
                 role=None, witness_token=None, attestation=None, raw_attestation=None):
        if method != "POST" or not action:
            return call(method, path, body, self.token, idem)
        payload = dict(body or {})
        if idem is not None:
            payload["idempotency_key"] = idem
        if attestation is None and raw_attestation is None:
            attestation = self.challenge(
                action, resource or path, payload, role=role, witness_token=witness_token)
        att = raw_attestation if raw_attestation is not None else attestation
        header_att = __import__("base64").urlsafe_b64encode(
            json.dumps(att, separators=(",", ":")).encode()).rstrip(b"=").decode()
        import urllib.request
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json",
                   "X-Device-Attestation": header_att}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if idem is None and "idempotency_key" not in payload:
            idem = "auto-" + __import__("secrets").token_hex(8)
            payload["idempotency_key"] = idem
        req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
        import urllib.error
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


class WitnessTrustedClient(TrustedClient):
    def __init__(self, session_id, witness_token, enrollment_code, seed):
        super().__init__(None, {"id": "witness", "login": "witness"}, seed, "HW-WIT-" + seed)
        self.session_id = session_id
        self.witness_token = witness_token
        self.enrollment_code = enrollment_code

    def register(self):
        csr = {
            "alg": "CONSENT-REGISTER-CSR/v1",
            "enrollment_code": self.enrollment_code,
            "hardware_id": self.hardware_id,
            "device_label": "见证测试终端",
            "public_jwk": self.public_jwk,
        }
        code, reg = call("POST", "/api/devices/register", {
            "enrollment_code": self.enrollment_code,
            "hardware_id": self.hardware_id,
            "device_label": csr["device_label"],
            "public_jwk": self.public_jwk,
            "csr_sig": trust.sign_object(self.private, csr),
        })
        assert code == 201, reg
        self.credential_id = reg["credential_id"]
        return reg

    def sign(self, name, idem=None):
        payload = {"role": "witness", "signer_name": name, "token": self.witness_token}
        if idem:
            payload["idempotency_key"] = idem
        att = self.challenge("sign", self.session_id, payload, role="witness",
                             witness_token=self.witness_token)
        return self(f"POST /api/sessions/{self.session_id}/sign",
                    None) if False else self(
            "POST", f"/api/sessions/{self.session_id}/sign", payload, idem=idem,
            action="sign", resource=self.session_id, role="witness",
            witness_token=self.witness_token, attestation=att)
