/**
 * 不可变处置凭据：构造、签名与库外重算校验。
 *
 * 凭据是一个自描述 JSON 信封：
 *   { algorithm:'CC-EVIDENCE-ED25519-SHA256/v1', payload:{...}, signature }
 * payload 内嵌：运单中性标识、规则版本与全部参数、片段集合（含逐点正文）、
 *   时间线分析结果、决定版本链（含被撤销的前版本）、片段集与决定链的摘要。
 *
 * 校验不依赖本数据库：
 *   1. 用模块公钥验证 Ed25519 签名（防伪造）；
 *   2. 用内嵌片段正文重算 片段集合哈希（证明片段未被改动）；
 *   3. 用内嵌规则参数重跑 analyzeTimeline（证明缺口/越界/建议与凭据声明一致）；
 *   4. 重算决定链哈希（证明最终决定及前后版本未被改动）。
 * 任一步失败即 VERIFICATION_FAILED，并给出不通过的具体检查项。
 */
import crypto from 'node:crypto';
import {
  analyzeTimeline, canonicalJSON, fragmentContentHash, normalizeFragment,
} from './engine.js';

export const CRED_ALG = 'CC-EVIDENCE-ED25519-SHA256/v1';

function publicJwkFromPrivate(jwk) {
  const priv = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  return crypto.createPublicKey(priv).export({ format: 'jwk' });
}

export function keyFromJwk(jwk) {
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

/** 从数据库中持久化的完整 JWK 构造 KeyObject。 */
export function privateKeyFromStored(jwkOrObj) {
  const jwk = typeof jwkOrObj === 'string' ? JSON.parse(jwkOrObj) : jwkOrObj;
  return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
}

export function publicKeyFromStored(jwkObj) {
  return keyFromJwk(jwkObj);
}

/** 片段集合哈希：先逐片段算 content_hash，再按片段号排序后串接哈希（与到达顺序无关）。 */
export function fragmentsSetDigest(fragments) {
  const rows = fragments.map((f) => {
    const nf = normalizeFragment(f);
    return { fragment_no: nf.fragment_no, content_hash: fragmentContentHash(nf) };
  });
  rows.sort((a, b) => a.fragment_no.localeCompare(b.fragment_no));
  return crypto.createHash('sha256')
    .update(canonicalJSON({ fragments: rows }))
    .digest('hex');
}

/** 决定链哈希：把全部版本（含已撤销）按 revision 排序串起来；任何版本被改都会变。 */
export function decisionChainDigest(decisionVersions) {
  const chain = decisionVersions
    .map((d) => ({
      revision: d.revision,
      disposition: d.disposition,
      reason: d.reason,
      decided_by: d.decided_by,
      decided_at: d.decided_at,
      revokes_revision: d.revokes_revision ?? null,
      analysis_digest: d.analysis_digest,
    }))
    .sort((a, b) => a.revision - b.revision);
  return crypto.createHash('sha256')
    .update(canonicalJSON({ chain }))
    .digest('hex');
}

export function analysisDigest(analysis) {
  return crypto.createHash('sha256').update(canonicalJSON(analysis)).digest('hex');
}

/**
 * 构造已签名凭据信封。
 * @param data {
 *   waybill: {waybill_no, sensor_no, expected_start, expected_end,
 *             rule_version, rule_min_c, rule_max_c, rule_breach_sec, rule_offset_c},
 *   fragments: [normalizeFragment 可识别的原始片段],
 *   analysis:  analyzeTimeline 的结果（当前决定所依据的快照），
 *   decision_versions: [{revision, disposition, reason, decided_by, decided_at,
 *                        revokes_revision, analysis_digest}],
 *   issued_by, issued_at
 * }
 */
export function buildCredential(data, privateKey) {
  const frags = data.fragments.map(normalizeFragment);
  const fsDigest = fragmentsSetDigest(frags);
  const aDigest = analysisDigest(data.analysis);
  const versions = data.decision_versions.map((d) =>
    ({ ...d, analysis_digest: d.analysis_digest || aDigest }));
  const dDigest = decisionChainDigest(versions);
  const current = versions.reduce((m, d) => (d.revision > m.revision ? d : m));

  const payload = {
    algorithm: CRED_ALG,
    cred_no: data.cred_no,
    issued_at: data.issued_at,
    issued_by: data.issued_by,
    waybill: {
      waybill_no: data.waybill.waybill_no,
      sensor_no: data.waybill.sensor_no,
      expected_start: data.waybill.expected_start,
      expected_end: data.waybill.expected_end,
      temperature_rule: {
        version: data.waybill.rule_version,
        temp_min_c: data.waybill.rule_min_c,
        temp_max_c: data.waybill.rule_max_c,
        max_breach_sec: data.waybill.rule_breach_sec,
        calib_offset_c: data.waybill.rule_offset_c,
      },
    },
    fragments: frags.map((f) => ({
      fragment_no: f.fragment_no,
      interval_start: f.interval_start,
      interval_end: f.interval_end,
      points: f.points,
    })),
    fragments_set_digest: fsDigest,
    analysis: data.analysis,
    analysis_digest: aDigest,
    decision_versions: versions,
    decision_chain_digest: dDigest,
    current_revision: current.revision,
    final_disposition: current.disposition,
  };

  const sig = crypto.sign(null, Buffer.from(canonicalJSON(payload), 'utf8'), privateKey);
  return {
    algorithm: CRED_ALG,
    payload,
    signature: sig.toString('base64'),
  };
}

/**
 * 库外校验凭据。只需要信封 + 模块公钥。
 * @returns {{ok:boolean, checks:object, reason?:string}}
 */
export function verifyCredential(envelope, publicKeyOrJwk) {
  const checks = { signature: false, fragments_digest: false, analysis_recompute: false,
    decision_chain_digest: false };
  const fail = (reason) => ({ ok: false, checks, reason });
  try {
    if (!envelope || envelope.algorithm !== CRED_ALG || !envelope.payload || !envelope.signature) {
      return fail('凭据格式不被支持');
    }
    const p = envelope.payload;
    const key = publicKeyOrJwk?.type === 'public'
      ? publicKeyOrJwk : keyFromJwk(publicKeyOrJwk);

    // 1) 签名
    const sigBuf = Buffer.from(envelope.signature, 'base64');
    checks.signature = crypto.verify(
      null, Buffer.from(canonicalJSON(p), 'utf8'), key, sigBuf);
    if (!checks.signature) return fail('签名校验失败：凭据被改动或非本模块签发');

    // 2) 片段集合摘要
    const fsDigest = fragmentsSetDigest(p.fragments);
    checks.fragments_digest = fsDigest === p.fragments_set_digest;
    if (!checks.fragments_digest) return fail('片段集合摘要不一致：片段正文已被改动');

    // 3) 用凭据内规则重跑分析，与凭据声明逐项比对
    const rule = {
      temp_min_c: p.waybill.temperature_rule.temp_min_c,
      temp_max_c: p.waybill.temperature_rule.temp_max_c,
      max_breach_sec: p.waybill.temperature_rule.max_breach_sec,
      calib_offset_c: p.waybill.temperature_rule.calib_offset_c,
    };
    const recomputed = analyzeTimeline(p.waybill, rule, p.fragments);
    const expected = {
      complete: recomputed.complete,
      n_breaches: recomputed.n_breaches,
      suggested_disposition: recomputed.suggested_disposition,
      n_points: recomputed.n_points,
      gaps: recomputed.gaps,
      events: recomputed.events,
      point_conflicts: recomputed.point_conflicts,
    };
    const claimed = {
      complete: p.analysis.complete,
      n_breaches: p.analysis.n_breaches,
      suggested_disposition: p.analysis.suggested_disposition,
      n_points: p.analysis.n_points,
      gaps: p.analysis.gaps,
      events: p.analysis.events,
      point_conflicts: p.analysis.point_conflicts,
    };
    checks.analysis_recompute = canonicalJSON(expected) === canonicalJSON(claimed)
      && analysisDigest(recomputed) === p.analysis_digest;
    if (!checks.analysis_recompute) {
      return fail('计算明细重算不一致：规则版本或分析结果被改动');
    }

    // 4) 决定链摘要与最终决定一致性
    checks.decision_chain_digest = decisionChainDigest(p.decision_versions) === p.decision_chain_digest;
    if (!checks.decision_chain_digest) return fail('决定链摘要不一致：最终决定或历史版本被改动');
    const maxRev = p.decision_versions.reduce((m, d) => Math.max(m, d.revision), 0);
    if (maxRev !== p.current_revision) return fail('current_revision 与决定链不一致');

    const current = p.decision_versions.find((d) => d.revision === p.current_revision);
    return {
      ok: true,
      checks,
      waybill_no: p.waybill.waybill_no,
      rule_version: p.waybill.temperature_rule.version,
      final_disposition: current.disposition,
      revision: current.revision,
      complete: recomputed.complete,
    };
  } catch (e) {
    return fail('校验过程异常: ' + e.message);
  }
}

/** 导出模块公钥 JWK（凭据校验方通过带外渠道取得后可在库外使用）。 */
export function exportPublicJwk(privateJwk) {
  return publicJwkFromPrivate(
    typeof privateJwk === 'string' ? JSON.parse(privateJwk) : privateJwk);
}
