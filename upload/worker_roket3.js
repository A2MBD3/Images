/**
 * worker_roket3.js — Rocket Mods 3 (roket3 ELF) sinkhole — Cloudflare Worker
 * ===========================================================================
 * Domain: x.delet.workers.dev   (base path: /rok)
 *
 * কেন Cloudflare Workers (Task 13, user-এর নির্দেশ্য):
 *   - roket3 ELF-এ TLS নেই, port 80 hardcoded — অর্থাৎ সব request প্লেইন HTTP-তে যায়
 *   - Render প্লেইন :80-এ 301 redirect দেয় → ELF ফলো করতে পারে না → "Server config error"
 *   - workers.dev প্লেইন :80-এ সরাসরি উত্তর দেয় (লাইভ যাচাইকৃত) — আর fixed-size body
 *     হলে Content-Length হেডারও নিজে থেকেই বসায়, chunked হয় না
 *   - URL string-এ https:// থাকলেও ELF সবসময় প্লেইন :80-তেই যায় (URL splitter host
 *     আলাদা করে) — তাই https:// রাখা নিরাপদ, আসল সার্ভারও তাই করত
 *
 * Response প্রোটোকল (ELF disassembly + live capture ground truth):
 *   প্রতিটা endpoint দেয়  base64( XOR(json, "ruman123") )  — text/plain
 *   ভেতরের JSON অবশ্যই compact (কোনো space নয়!) — ELF substring স্ক্যান করে:
 *     config    : পুরো JSON ভ্যালিডেট হয় (signature/canary/nonce_sig/file_hash watchdog-এ)
 *     login     : '"status":true' পেলে → Login Success
 *     heartbeat : '"status":true'
 *     update    : '"has_update":true' না পেলে → no update
 *
 * এই worker এ সব কিছু log হয় (login key, device_id সহ):
 *   Dashboard → Workers → x.delet → Logs   অথবা   `wrangler tail x.delet`
 *
 * ডেপ্লয় (৩ ধাপ):
 *   ১) dash.cloudflare.com → Workers & Pages → x.delet → Edit code
 *   ২) পুরনো কোড মুছে এই পুরো ফাইল পেস্ট করো → Deploy
 *   ৩) নিচের curl টেস্টগুলো চালাও (README.md-তে আছে)
 */

// ---- config wire (scripts/forge_config.py জেনারেটেড, constant) --------------
// এটাই /rok/config.php থেকে সার্ভ হবে — ভেতরের config:
//   login     https://x.delet.workers.dev/rok/login
//   heartbeat https://x.delet.workers.dev/rok/heartbeat.php
//   update    https://x.delet.workers.dev/rok/update.php
//   signature 6F322825 | canary 63377456 | nonce_sig 14649CD0 | file_hash 382679CC
const WIRE_CONFIG = "CVcbBBxCW1wcV1dDXx8CHUZXQUMCXlVaHCoYEwITCBEaARkRHQsdHApbCQQCVEYdBRofCgtDQR0WEBtOHF5ZHB4aCggAEx4RGhAMExpTV1IGKhgTAhMIERoBGREdCx0cClsJBAJURh0FGh8KC0NBHRYQG04cXlkcGhAMExpTV1IGWx0JHhMeEQcFCQAaVG1GABlPW0xZRkcCBldOQUkcVxcZCBVARl1BGRAfEkBVV0VdBwIKQURCVxMBCE8eWUIRXlcACABuRFYABgQOABMIEUNbXU9eEx4RFBofAgtuR0MWFBkETAtUUh4GCE1MWltfHioeFgdFUVtQTwsAAkJXH1AGBAYAUEZGABBPW0wHdABAR1VTWxMeEREUAwAcSBAJUENeUlkGBgZEV0FDHVRARRcHMg8BX1FWUE9cVlcDBgBBRF1XQhNcXBwWCD4dWFURSFdcVVgFC3A2RU9NTFdbXxcqBQAdWRAJUEZVU1gGC3AxVxA=";

// ---- XOR + envelope helper: base64( XOR(json, "ruman123") ) ------------------
const XOR_KEY = new TextEncoder().encode("ruman123");
function env(jsonStr) {
  const raw = new TextEncoder().encode(jsonStr);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw[i] ^ XOR_KEY[i % XOR_KEY.length];
  let bin = "";
  for (const b of out) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ---- response templates (compact JSON contracts from the ELF) ---------------
const RESP_LOGIN_SUCCESS = env('{"status":true,"message":"Login Success!"}');
const RESP_HEARTBEAT = env('{"status":true}');
const RESP_UPDATE = env('{"status":"success","has_update":false,"maintenance_mode":false,"update_message":""}');

// ---- plain response sender (string body => CF নিজেই Content-Length বসায়) -----
function raw(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/{2,}/g, "/"); // normalize double slashes
    const ip = request.headers.get("cf-connecting-ip") || "?";
    const ua = request.headers.get("user-agent") || "?";

    // ১) config — প্যাচড ELF সবার আগে এখানেই আসে (GET /rok/config.php?t=<ms>)
    if (path === "/rok/config.php") {
      console.log(`[app_config] t=${url.searchParams.get("t")} ip=${ip} ua=${ua}`);
      return raw(WIRE_CONFIG);
    }

    // ২) login — যেকোনো key-তে SUCCESS (প্রতিটা key + device_id log-এ ধরা পড়বে)
    if (path === "/rok/login") {
      console.log(`[LOGIN] key=${url.searchParams.get("key")} device_id=${url.searchParams.get("device_id")} ip=${ip} ua=${ua}`);
      return raw(RESP_LOGIN_SUCCESS);
    }

    // ৩) heartbeat — সেশন বাঁচিয়ে রাখে
    if (path === "/rok/heartbeat.php") {
      console.log(`[heartbeat] ${url.search} ip=${ip}`);
      return raw(RESP_HEARTBEAT);
    }

    // ৪) update check — "no update" রিপোর্ট
    if (path === "/rok/update.php") {
      console.log(`[update] ${url.search} ip=${ip}`);
      return raw(RESP_UPDATE);
    }

    // বাকি সব কিছু log + 404 (অপ্রত্যাশিত ট্রাফিক ধরার জন্য)
    console.log(`[other] ${request.method} ${path}${url.search} ip=${ip} ua=${ua}`);
    return raw("Not Found", 404);
  },
};

// ----------------------------------------------------------------------------
// সার্ভার-সাইড decode helper (log-এর envelope পড়তে চাইলে):
//   function deenv(b64) {
//     const b = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
//     for (let i = 0; i < b.length; i++) b[i] ^= XOR_KEY[i % XOR_KEY.length];
//     return new TextDecoder().decode(b);
//   }
// ----------------------------------------------------------------------------
