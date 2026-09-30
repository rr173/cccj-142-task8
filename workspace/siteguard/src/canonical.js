/**
 * 规范化 JSON（RFC 8785 风格，仅本模块使用的稳定子集）。
 *
 * 终端与服务端对同一份对象必须算出完全相同的字节，才能核对摘要/签名：
 *   - 对象键按 UTF-16 码位排序（与浏览器端 shared/canonical-web.js 保持一致）；
 *   - 不允许出现 undefined / 函数 / symbol（出现即抛错，拒绝含糊）；
 *   - 数字仅允许安全整数，避免浮点歧义；
 *   - 输出无多余空白。
 */
import { createHash } from 'node:crypto';

export function canonicalize(value) {
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new TypeError('仅支持安全整数与非数字类型，避免浮点规范化歧义');
    }
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map((v) => {
      if (v === undefined) throw new TypeError('数组内不允许 undefined');
      return canonicalize(v);
    }).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
  }
  throw new TypeError('不支持的类型: ' + typeof value);
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}

/**
 * 对规范化对象或原始字符串计算 SHA-256，返回十六进制。
 * 与浏览器 sg-web.js 约定一致：字符串按 UTF-8 原文字节（不加引号），
 * 对象/数组按 canonicalize 后的字节。
 */
export function digestHexSync(value) {
  const buf = typeof value === 'string'
    ? Buffer.from(value, 'utf8')
    : canonicalBytes(value);
  return createHash('sha256').update(buf).digest('hex');
}
