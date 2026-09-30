#!/usr/bin/env node
/**
 * 凭据库外重算校验（CLI）。
 *
 * 用法：
 *   node src/verify.js <凭据文件.json> [--public-key pub.jwk]
 *
 * 不给 --public-key 时默认读取本模块公钥（data 相邻库的 app_meta 走不到，
 * 因为本工具的意义就是"数据库之外"，所以校验方应通过带外渠道取得公钥）。
 * 可以先用  curl localhost:8080/api/public-key -o pub.jwk  导出。
 *
 * 退出码：0 = 校验通过；2 = 凭据被改动/签名失败；1 = 用法错误。
 */
import fs from 'node:fs';
import { verifyCredential } from './credential.js';

const args = process.argv.slice(2);
const credFile = args.find((a) => !a.startsWith('--'));
const keyIdx = args.indexOf('--public-key');
if (!credFile) {
  console.error('用法: node src/verify.js <credential.json> [--public-key pub.jwk]');
  process.exit(1);
}
const envelope = JSON.parse(fs.readFileSync(credFile, 'utf8'));

let jwk;
if (keyIdx >= 0) {
  jwk = JSON.parse(fs.readFileSync(args[keyIdx + 1], 'utf8'));
} else {
  const guessUrl = process.env.PUBLIC_KEY_URL;
  if (!guessUrl) {
    console.error('需要 --public-key <pub.jwk>（库外校验不得依赖数据库）');
    process.exit(1);
  }
  jwk = JSON.parse(fs.readFileSync(guessUrl, 'utf8'))?.public_jwk;
}

const result = verifyCredential(envelope, jwk);
console.log(JSON.stringify(result, null, 2));
process.exit(result.ok ? 0 : 2);
