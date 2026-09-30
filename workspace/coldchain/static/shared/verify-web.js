/**
 * 浏览器端"库外"凭据校验：只依赖 WebCrypto（SubtleCrypto）与纯函数引擎，
 * 不调用任何需要登录的接口。模块公钥可在线获取（/api/public-key）或粘贴带外取得的 JWK。
 *
 * 校验项与 src/credential.js 的 verifyCredential 完全一致：
 *   验签 → 片段集合摘要重算 → 用凭据内规则重跑时间线分析 → 决定链摘要重算。
 */
import { analyzeTimeline, canonicalJSON, normalizeFragment } from '/vendor/engine.js';

const ALG = 'CC-EVIDENCE-ED25519-SHA256/v1';

async function sha256Hex(data) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function fragmentsSetDigest(fragments) {
  const rows = fragments.map((f) => {
    const nf = normalizeFragment(f);
    return { fragment_no: nf.fragment_no, content_hash: null, _nf: nf };
  });
  for (const r of rows) {
    r.content_hash = await sha256Hex(canonicalJSON({
      interval_start: r._nf.interval_start,
      interval_end: r._nf.interval_end,
      points: r._nf.points.map((p) => [Math.trunc(p[0]), p[1]]),
    }));
    delete r._nf;
  }
  rows.sort((a, b) => a.fragment_no.localeCompare(b.fragment_no));
  return sha256Hex(canonicalJSON({ fragments: rows }));
}

async function analysisDigest(analysis) {
  return sha256Hex(canonicalJSON(analysis));
}

async function decisionChainDigest(versions) {
  const chain = versions
    .map((d) => ({
      revision: d.revision, disposition: d.disposition, reason: d.reason,
      decided_by: d.decided_by, decided_at: d.decided_at,
      revokes_revision: d.revokes_revision ?? null, analysis_digest: d.analysis_digest,
    }))
    .sort((a, b) => a.revision - b.revision);
  return sha256Hex(canonicalJSON({ chain }));
}

export async function verifyInBrowser(envelope, publicJwk) {
  const checks = { signature: false, fragments_digest: false,
    analysis_recompute: false, decision_chain_digest: false };
  const fail = (reason) => ({ ok: false, checks, reason });
  try {
    if (!envelope || envelope.algorithm !== ALG || !envelope.payload || !envelope.signature) {
      return fail('凭据格式不被支持');
    }
    const p = envelope.payload;

    // 1) Ed25519 签名
    const key = await crypto.subtle.importKey(
      'jwk', publicJwk, { name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['verify']);
    const sig = Uint8Array.from(atob(envelope.signature), (c) => c.charCodeAt(0));
    checks.signature = await crypto.subtle.verify(
      'Ed25519', key, sig, new TextEncoder().encode(canonicalJSON(p)));
    if (!checks.signature) return fail('签名校验失败：凭据被改动或非本模块签发');

    // 2) 片段集合摘要
    const fsDigest = await fragmentsSetDigest(p.fragments);
    checks.fragments_digest = fsDigest === p.fragments_set_digest;
    if (!checks.fragments_digest) return fail('片段集合摘要不一致：片段正文已被改动');

    // 3) 重跑时间线分析并与凭据声明逐项比对
    const t = p.waybill.temperature_rule;
    const recomputed = analyzeTimeline(p.waybill, {
      temp_min_c: t.temp_min_c, temp_max_c: t.temp_max_c,
      max_breach_sec: t.max_breach_sec, calib_offset_c: t.calib_offset_c,
    }, p.fragments);
    const subset = (a) => ({
      complete: a.complete, n_breaches: a.n_breaches,
      suggested_disposition: a.suggested_disposition, n_points: a.n_points,
      gaps: a.gaps, events: a.events, point_conflicts: a.point_conflicts,
    });
    checks.analysis_recompute = canonicalJSON(subset(recomputed)) ===
      canonicalJSON(subset(p.analysis)) &&
      (await analysisDigest(recomputed)) === p.analysis_digest;
    if (!checks.analysis_recompute) return fail('计算明细重算不一致：规则版本或分析结果被改动');

    // 4) 决定链摘要
    checks.decision_chain_digest =
      (await decisionChainDigest(p.decision_versions)) === p.decision_chain_digest;
    if (!checks.decision_chain_digest) return fail('决定链摘要不一致：最终决定或历史版本被改动');

    const current = p.decision_versions.find((d) => d.revision === p.current_revision);
    return {
      ok: true, checks, waybill_no: p.waybill.waybill_no,
      rule_version: t.version, final_disposition: current.disposition,
      revision: current.revision, complete: recomputed.complete,
    };
  } catch (e) {
    return fail('校验过程异常: ' + e.message);
  }
}
