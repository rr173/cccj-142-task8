#!/usr/bin/env python3
"""签名事件包的库外核对工具（不依赖平台数据库）。

用途：订阅方/审计方拿到平台公布的验证材料（公钥集 + 链锚点）后，在平台
之外核对事件包的 序号连续性、正文摘要、哈希链、签发版本与 Ed25519 签名。

用法：
  # 1) 校验单个事件包文件
  python -m rts.verify_events event.json --materials materials.json

  # 2) 校验一批按 seq 命名的事件包（校验整条链 + 与链锚点一致）
  python -m rts.verify_events events/*.json --materials materials.json --chain

  # 3) 从在线平台直接取材料（带外渠道之一），再核对本地事件包
  curl http://host:8000/api/verify-materials -o materials.json

materials.json 可由 GET /api/verify-materials 取得；它只含公钥，绝不含私钥。
退出码：0 全部通过；2 存在校验失败；1 用法/读取错误。
"""
from __future__ import annotations

import argparse
import base64
import glob
import json
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .events import EVENT_ALG, canonical_json, sha256_hex


def _signed_header(envelope: dict[str, Any]) -> dict[str, Any]:
    """重算签名时使用的头：取包头字段并**去掉 sign_key_id**
    （签名只覆盖固定头集合，sign_key_id 仅用于选择公钥）。"""
    h = dict(envelope["header"])
    h.pop("sign_key_id", None)
    return {
        "algorithm": EVENT_ALG,
        "event_id": h["event_id"], "seq": h["seq"], "kind": h["kind"],
        "center_code": h["center_code"], "actor_role": h["actor_role"],
        "body_digest": h["body_digest"], "prev_digest": h["prev_digest"],
        "event_digest": h["event_digest"], "sub_version": h["sub_version"],
        "created_at": h["created_at"],
    }


def verify_one(envelope: dict[str, Any], materials: dict[str, Any]) -> dict[str, Any]:
    """只凭事件包 + 公布材料核对一条事件。返回逐项检查结果。"""
    checks = {"format": False, "signature": False, "body_digest": False,
              "event_digest": False, "known_key": False}
    fail = lambda why: {"ok": False, "checks": checks, "reason": why}
    try:
        h = envelope.get("header")
        body = envelope.get("body")
        sig = envelope.get("signature")
        if not h or sig is None or body is None or h.get("algorithm") != EVENT_ALG:
            return fail("事件包格式不被支持")
        checks["format"] = True

        # 正文摘要：证明正文未被改动
        checks["body_digest"] = sha256_hex(canonical_json(body)) == h["body_digest"]
        if not checks["body_digest"]:
            return fail("正文摘要不一致：事件正文已被改动")

        # 事件摘要：重算头部链摘要
        recomputed = sha256_hex(canonical_json({
            "seq": h["seq"], "event_id": h["event_id"], "kind": h["kind"],
            "center_code": h["center_code"], "actor_role": h["actor_role"],
            "body_digest": h["body_digest"], "prev_digest": h["prev_digest"],
            "sub_version": h["sub_version"], "created_at": h["created_at"],
        }))
        checks["event_digest"] = recomputed == h["event_digest"]
        if not checks["event_digest"]:
            return fail("事件摘要不一致：序号/链/签发版本等头部被改动")

        # 用公布材料中对应 key_id 的公钥验签
        key_id = h.get("sign_key_id")
        km = next((k for k in materials.get("keys", []) if k["key_id"] == key_id), None)
        if not km:
            return fail(f"签发版本 {key_id} 不在公布的验证材料中（未知签发版本）")
        checks["known_key"] = True
        pub = serialization.load_pem_public_key(km["public_pem"].encode())
        try:
            pub.verify(base64.b64decode(sig),
                       canonical_json(_signed_header(envelope)).encode())
        except InvalidSignature:
            return fail("签名验证失败：事件包非本平台签发或被篡改")
        checks["signature"] = True
        return {"ok": True, "checks": checks, "seq": h["seq"],
                "event_id": h["event_id"], "kind": h["kind"],
                "sub_version": h["sub_version"], "sign_key_id": key_id}
    except Exception as exc:  # 结构异常也算校验失败（不吞掉，给出原因类型）
        return fail(f"校验过程异常: {type(exc).__name__}")


def verify_chain(envelopes: list[dict[str, Any]]) -> dict[str, Any]:
    """核对一批事件的序号连续与哈希链；并与材料中的链锚点比对（若给出）。"""
    ordered = sorted(envelopes, key=lambda e: e["header"]["seq"])
    problems: list[str] = []
    prev = "GENESIS"
    expected = 1
    for env in ordered:
        h = env["header"]
        if h["seq"] != expected:
            problems.append(f"序号不连续：期望 {expected}，实际 {h['seq']}")
        if h["prev_digest"] != prev:
            problems.append(f"事件 {h['seq']} 的 prev_digest 与前序不一致")
        prev = h["event_digest"]
        expected = h["seq"] + 1
    return {"ok": not problems, "problems": problems,
            "tail": {"seq": ordered[-1]["header"]["seq"],
                     "event_digest": ordered[-1]["header"]["event_digest"]}
            if ordered else None}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="库外核对平台签名事件包")
    ap.add_argument("events", nargs="+", help="事件包 JSON 文件（支持 glob）")
    ap.add_argument("--materials", required=True, help="公布的验证材料 JSON")
    ap.add_argument("--chain", action="store_true", help="同时核对整链与链锚点")
    args = ap.parse_args(argv)

    try:
        materials = json.load(open(args.materials, encoding="utf-8"))
        paths: list[str] = []
        for pat in args.events:
            paths.extend(sorted(glob.glob(pat)) or [pat])
        envelopes = []
        for p in paths:
            envelopes.append(json.load(open(p, encoding="utf-8")))
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "reason": f"读取失败: {type(exc).__name__}"},
                         ensure_ascii=False))
        return 1

    results = [verify_one(e, materials) for e in envelopes]
    ok = all(r["ok"] for r in results)
    report: dict[str, Any] = {"ok": ok, "count": len(results), "results": results}

    if args.chain and envelopes:
        chain = verify_chain(envelopes)
        head = materials.get("chain_head")
        if head and chain["tail"] and chain["tail"]["seq"] == head["seq"]:
            if chain["tail"]["event_digest"] != head["event_digest"]:
                chain["ok"] = False
                chain["problems"].append("链尾摘要与公布的 chain_head 不一致")
        report["chain"] = chain
        ok = ok and chain["ok"]
        report["ok"] = ok

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
