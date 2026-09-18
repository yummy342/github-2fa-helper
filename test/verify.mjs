/**
 * 核心算法验算脚本
 *
 * 思路：index.html 里的 SHA-1 / HMAC-SHA1 / TOTP 是自己实现的，
 *       正确性必须由外部独立来源背书，不能自己验自己。
 *       这里用 Node 内置的 OpenSSL 实现做对照，再叠加 RFC 6238
 *       官方测试向量。
 *
 * 跑法：node test/verify.mjs
 */

import { readFileSync } from "node:fs";
import { createHash, createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, "..", "index.html"), "utf8");

/* 从 index.html 里抠出被标记的核心算法段，保证测的就是发布的那份代码，
   而不是另抄一份出来测 */
const marked = html.match(/\/\* ===CORE-START=== \*\/([\s\S]*?)\/\* ===CORE-END=== \*\//);
if (!marked) {
  console.error("找不到核心算法段，index.html 里的 CORE 标记被改坏了");
  process.exit(1);
}

const core = new Function(
  marked[1] + "\nreturn { sha1, hmacSha1, base32Decode, totp, parseOtpauthInput };"
)();
const { sha1, hmacSha1, base32Decode, totp, parseOtpauthInput } = core;

let pass = 0, fail = 0;
const failures = [];

function check(name, actual, expected) {
  const a = String(actual), e = String(expected);
  if (a === e) { pass++; return; }
  fail++;
  failures.push(`${name}\n    期望 ${e}\n    实际 ${a}`);
}

const hex = (u8) => Buffer.from(u8).toString("hex");

/* ============================================================
 * 一、SHA-1 对照 OpenSSL
 * 覆盖空串、跨块边界（55/56/64 字节是填充逻辑的转折点）、长输入
 * ============================================================ */
console.log("\n[1] SHA-1 vs OpenSSL");

const sha1Cases = [
  new Uint8Array(0),
  Buffer.from("abc", "utf8"),
  Buffer.from("a".repeat(55), "utf8"),
  Buffer.from("a".repeat(56), "utf8"),
  Buffer.from("a".repeat(63), "utf8"),
  Buffer.from("a".repeat(64), "utf8"),
  Buffer.from("a".repeat(65), "utf8"),
  Buffer.from("a".repeat(1000), "utf8"),
  Buffer.from([0x00, 0xff, 0x80, 0x7f]),
];

for (const input of sha1Cases) {
  const want = createHash("sha1").update(Buffer.from(input)).digest("hex");
  check(`sha1(${input.length} 字节)`, hex(sha1(new Uint8Array(input))), want);
}

// 随机长度随机内容，压一遍
for (let i = 0; i < 200; i++) {
  const n = Math.floor(Math.random() * 300);
  const b = Buffer.from(Array.from({ length: n }, () => Math.floor(Math.random() * 256)));
  check(`sha1(随机 ${n} 字节)`, hex(sha1(new Uint8Array(b))),
        createHash("sha1").update(b).digest("hex"));
}

/* ============================================================
 * 二、HMAC-SHA1 对照 OpenSSL
 * 重点压密钥长度：>64 字节要触发"先哈希密钥"那条分支
 * ============================================================ */
console.log("[2] HMAC-SHA1 vs OpenSSL");

const hmacCases = [
  [Buffer.alloc(0), Buffer.from("msg")],
  [Buffer.from("key"), Buffer.from("The quick brown fox jumps over the lazy dog")],
  [Buffer.from("k".repeat(63)), Buffer.from("boundary")],
  [Buffer.from("k".repeat(64)), Buffer.from("boundary")],
  [Buffer.from("k".repeat(65)), Buffer.from("boundary")],
  [Buffer.from("k".repeat(200)), Buffer.from("long key")],
  [base32Decode("JBSWY3DPEHPK3PXP"), Buffer.from("1234567890")],
];

for (const [k, m] of hmacCases) {
  const want = createHmac("sha1", k).update(m).digest("hex");
  check(`hmac(key=${k.length}, msg=${m.length})`,
        hex(hmacSha1(new Uint8Array(k), new Uint8Array(m))), want);
}

// 随机对照，密钥长度横跨 64 字节分界
for (let i = 0; i < 200; i++) {
  const k = Buffer.from(Array.from({ length: Math.floor(Math.random() * 150) },
                                   () => Math.floor(Math.random() * 256)));
  const m = Buffer.from(Array.from({ length: Math.floor(Math.random() * 100) },
                                   () => Math.floor(Math.random() * 256)));
  check(`hmac(随机 key=${k.length}, msg=${m.length})`,
        hex(hmacSha1(new Uint8Array(k), new Uint8Array(m))),
        createHmac("sha1", k).update(m).digest("hex"));
}

/* ============================================================
 * 三、Base32 解码
 * ============================================================ */
console.log("[3] Base32 解码");

check("JBSWY3DPEHPK3PXP", hex(base32Decode("JBSWY3DPEHPK3PXP")), "48656c6c6f21deadbeef");
check("小写输入", hex(base32Decode("jbswy3dpehpk3pxp")), "48656c6c6f21deadbeef");
check("带空格和连字符", hex(base32Decode("JBSW Y3DP-EHPK 3PXP")), "48656c6c6f21deadbeef");
check("带填充等号", hex(base32Decode("JBSWY3DPEHPK3PXP====")), "48656c6c6f21deadbeef");
check("MFRGG===", hex(base32Decode("MFRGG===")), "616263");

// 非法字符必须报错，不能静默吞掉
for (const bad of ["JBSW1Y3DP", "ABC!", "0189"]) {
  let threw = false;
  try { base32Decode(bad); } catch { threw = true; }
  check(`拒绝非法输入 "${bad}"`, threw, true);
}

/* ============================================================
 * 四、TOTP —— RFC 6238 官方测试向量
 * 密钥固定为 ASCII "12345678901234567890"，8 位输出
 * ============================================================ */
console.log("[4] TOTP vs RFC 6238 测试向量");

const rfcKey = new Uint8Array(Buffer.from("12345678901234567890", "utf8"));
const rfcVectors = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

for (const [t, want] of rfcVectors) {
  check(`T=${t}`, totp(rfcKey, t * 1000, 30, 8), want);
}

/* ============================================================
 * 五、TOTP 随机对照 OpenSSL
 * 自己实现整条链路，再用 OpenSSL 把同一条链路重走一遍比对
 * ============================================================ */
console.log("[5] TOTP 随机对照");

function referenceTotp(key, timestampMs, period, digits) {
  const counter = Math.floor(timestampMs / 1000 / period);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 4294967296), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const mac = createHmac("sha1", key).update(buf).digest();
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) |
              (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % Math.pow(10, digits)).padStart(digits, "0");
}

for (let i = 0; i < 300; i++) {
  const keyLen = 10 + Math.floor(Math.random() * 30);
  const key = Buffer.from(Array.from({ length: keyLen }, () => Math.floor(Math.random() * 256)));
  const period = [30, 60, 15][Math.floor(Math.random() * 3)];
  const digits = [6, 8][Math.floor(Math.random() * 2)];
  const ts = Math.floor(Math.random() * 4_000_000_000) * 1000;
  check(`totp(随机 key=${keyLen} period=${period} digits=${digits})`,
        totp(new Uint8Array(key), ts, period, digits),
        referenceTotp(key, ts, period, digits));
}

/* ============================================================
 * 六、输入解析
 * ============================================================ */
console.log("[6] 输入解析");

const plain = parseOtpauthInput("JBSWY3DPEHPK3PXP");
check("裸密钥 → 解码", hex(plain.key), "48656c6c6f21deadbeef");
check("裸密钥 → 默认 6 位", plain.digits, 6);
check("裸密钥 → 默认 30 秒", plain.period, 30);

const uri = parseOtpauthInput(
  "otpauth://totp/GitHub:someone%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub");
check("链接 → 发行方", uri.issuer, "GitHub");
check("链接 → 账号", uri.account, "someone@example.com");
check("链接 → 密钥", hex(uri.key), "48656c6c6f21deadbeef");
check("链接 → 算法可用", uri.algorithmOk, true);

const noIssuer = parseOtpauthInput("otpauth://totp/someone?secret=JBSWY3DPEHPK3PXP");
check("链接无 issuer → 账号仍正确", noIssuer.account, "someone");
check("链接无 issuer → 发行方为空", noIssuer.issuer, "");

const sha256 = parseOtpauthInput(
  "otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256");
check("SHA256 必须被标为不可用", sha256.algorithmOk, false);

const custom = parseOtpauthInput(
  "otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&digits=8&period=60");
check("自定义位数", custom.digits, 8);
check("自定义周期", custom.period, 60);

// 算法写法：SHA1 与 SHA-1 等价，带连字符的不该被当成不支持
check("algorithm=SHA-1 应被接受",
      parseOtpauthInput("otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&algorithm=SHA-1").algorithmOk,
      true);
check("algorithm=sha1 小写也应被接受",
      parseOtpauthInput("otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&algorithm=sha1").algorithmOk,
      true);

// 密钥字符数：手敲掉一位照样出码，靠这个数字用户才能自己发现
check("裸密钥字符数", plain.secretChars, 16);
check("链接密钥字符数", uri.secretChars, 16);
check("带空格连字符仍算 16 个字符",
      parseOtpauthInput("JBSW Y3DP-EHPK 3PXP").secretChars, 16);

// 越界参数必须被标记出来，不能静默回落成默认值
check("默认参数不带警告", plain.paramsOk, true);
check("越界位数被标记",
      parseOtpauthInput("otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&digits=5").paramsOk,
      false);
check("越界周期被标记",
      parseOtpauthInput("otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&period=999999999999").paramsOk,
      false);
check("合法位数不误报",
      parseOtpauthInput("otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&digits=8").paramsOk,
      true);
check("合法周期不误报",
      parseOtpauthInput("otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&period=60").paramsOk,
      true);

// 应报错的输入
const badInputs = [
  ["otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP", "HOTP 类型"],
  ["otpauth://totp/X?issuer=GitHub", "缺 secret"],
  ["", "空输入"],
  ["!!!not base32!!!", "非法字符"],
];
for (const [input, label] of badInputs) {
  let threw = false;
  try { parseOtpauthInput(input); } catch { threw = true; }
  check(`拒绝 ${label}`, threw, true);
}

/* ============================================================
 * 结果
 * ============================================================ */
console.log("");
if (fail === 0) {
  console.log(`全部通过：${pass} 项`);
  process.exit(0);
} else {
  console.error(`失败 ${fail} 项 / 共 ${pass + fail} 项\n`);
  for (const f of failures.slice(0, 20)) console.error("  ✗ " + f + "\n");
  if (failures.length > 20) console.error(`  ... 另有 ${failures.length - 20} 项\n`);
  process.exit(1);
}
