const cheerio = require("cheerio");
const dns = require("dns").promises;
const net = require("net");
const { Readable } = require("stream");

const PROXY = "/api/proxy?url=";

/* ---------- SSRF対策: プライベートIPを拒否 ---------- */
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === "::1" || l === "::") return true;
    if (l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80")) return true;
    if (l.startsWith("::ffff:")) return isPrivateIp(l.slice(7));
  }
  return false;
}

async function assertPublic(urlObj) {
  if (!/^https?:$/.test(urlObj.protocol)) throw new Error("http/https only");
  const host = urlObj.hostname.replace(/^\[|\]$/g, "");
  const addrs = net.isIP(host)
    ? [{ address: host }]
    : await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateIp(a.address)))
    throw new Error("blocked address");
}

/* ---------- URL書き換え ---------- */
const SKIP = /^(data:|blob:|javascript:|mailto:|tel:|about:|#)/i;

function rw(u, base) {
  if (!u) return u;
  u = u.trim();
  if (SKIP.test(u)) return u;
  try {
    return PROXY + encodeURIComponent(new URL(u, base).href);
  } catch {
    return u;
  }
}

function rwSrcset(v, base) {
  return v
    .split(",")
    .map(part => {
      const [u, ...rest] = part.trim().split(/\s+/);
      return [rw(u, base), ...rest].join(" ");
    })
    .join(", ");
}

function rwCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => `url(${q}${rw(u, base)}${q})`)
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => `@import ${q}${rw(u, base)}${q}`);
}

/* ---------- ブラウザ側で動的リクエストを書き換えるスクリプト ---------- */
function clientScript(base) {
  return `<script>(function(){
var BASE=${JSON.stringify(base).replace(/</g, "\\u003c")},P=${JSON.stringify(PROXY)};
var SKIP=/^(data:|blob:|javascript:|mailto:|tel:|about:|#)/i;
function px(u){
  if(typeof u!=="string"||!u||SKIP.test(u)||u.indexOf("/api/proxy?url=")===0) return u;
  try{return P+encodeURIComponent(new URL(u,BASE).href)}catch(e){return u}
}
var of=window.fetch;
window.fetch=function(i,o){
  if(typeof i==="string") i=px(i);
  else if(i&&i.url) i=new Request(px(i.url),i);
  return of.call(this,i,o);
};
var ox=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){
  arguments[1]=px(String(u));return ox.apply(this,arguments);
};
var sa=Element.prototype.setAttribute;
Element.prototype.setAttribute=function(n,v){
  if(/^(src|href|poster)$/i.test(n)) v=px(String(v));
  return sa.call(this,n,v);
};
[[HTMLImageElement,"src"],[HTMLScriptElement,"src"],[HTMLMediaElement,"src"],
 [HTMLSourceElement,"src"],[HTMLLinkElement,"href"],[HTMLIFrameElement,"src"]].forEach(function(p){
  var d=Object.getOwnPropertyDescriptor(p[0].prototype,p[1]);
  if(!d||!d.set) return;
  Object.defineProperty(p[0].prototype,p[1],{
    get:d.get,set:function(v){d.set.call(this,px(String(v)))}
  });
});

var H=new URL(BASE).hostname.toLowerCase();
var cd=Object.getOwnPropertyDescriptor(Document.prototype,"cookie");
if(cd&&cd.get){Object.defineProperty(document,"cookie",{configurable:true,
get:function(){
  var out=[];
  cd.get.call(document).split(/;\\s*/).forEach(function(c){
    var i=c.indexOf("=");if(i<0)return;
    var m=c.slice(0,i).match(/^__px_(.+?)__(.+)$/);
    if(m&&(H===m[1]||H.endsWith("."+m[1]))) out.push(m[2]+c.slice(i));
  });
  return out.join("; ");
},
set:function(v){
  var parts=String(v).split(";"),nv=parts.shift().trim(),eq=nv.indexOf("=");
  if(eq<1)return;
  var dom=H,rest=[];
  parts.forEach(function(p){
    var t=p.trim();
    if(/^domain=/i.test(t)){var d=t.slice(7).replace(/^\\./,"").toLowerCase();if(H===d||H.endsWith("."+d))dom=d;}
    else if(/^(path|samesite)=/i.test(t)||/^secure$/i.test(t)){}
    else if(t)rest.push(t);
  });
  cd.set.call(document,"__px_"+dom+"__"+nv.slice(0,eq)+"="+nv.slice(eq+1)+"; path=/; SameSite=Lax; Secure"+(rest.length?"; "+rest.join("; "):""));
}});}
var wo=window.open;
window.open=function(u){arguments[0]=px(u);return wo.apply(this,arguments)};
})();</script>`;
}

/* ---------- HTML書き換え ---------- */
function rewriteHtml(html, base) {
  const $ = cheerio.load(html);
  const b = $("base[href]").attr("href");
  if (b) {
    try { base = new URL(b, base).href; } catch {}
    $("base").remove();
  }
  $('meta[http-equiv="Content-Security-Policy" i]').remove();
  $("[integrity]").removeAttr("integrity");
  $("[crossorigin]").removeAttr("crossorigin");
  $("[nonce]").removeAttr("nonce");

  const attrs = ["src", "href", "poster", "data-src", "data-href", "data-poster"];
  $("*").each((_, el) => {
    for (const a of attrs) {
      const v = $(el).attr(a);
      if (v != null) $(el).attr(a, rw(v, base));
    }
    const ss = $(el).attr("srcset");
    if (ss) $(el).attr("srcset", rwSrcset(ss, base));
    const ds = $(el).attr("data-srcset");
    if (ds) $(el).attr("data-srcset", rwSrcset(ds, base));
    const st = $(el).attr("style");
    if (st) $(el).attr("style", rwCss(st, base));
  });

  $("form").each((_, el) => {
    const f = $(el);
    const a = f.attr("action");
    if (a && SKIP.test(a)) return;
    let u;
    try { u = new URL(a || "", base); } catch { u = new URL(base); }
    if ((f.attr("method") || "get").toLowerCase() === "post") {
      f.attr("action", PROXY + encodeURIComponent(u.href));
    } else {
      u.search = ""; u.hash = "";
      f.attr("action", "/api/proxy");
      f.prepend($('<input type="hidden" name="__purl">').attr("value", u.href));
    }
  });
  $("style").each((_, el) => {
    $(el).text(rwCss($(el).text(), base));
  });
  $("head").prepend(clientScript(base));
  if (!$("head").length) $.root().prepend(clientScript(base));
  return $.html();
}


/* ---------- Cookie中継 (サイトごとに名前へプレフィックスを付けて衝突を防ぐ) ---------- */
function buildCookie(req, host) {
  const out = [];
  (req.headers.cookie || "").split(/;\s*/).forEach(c => {
    const i = c.indexOf("=");
    if (i < 0) return;
    const m = c.slice(0, i).match(/^__px_(.+?)__(.+)$/);
    if (m && (host === m[1] || host.endsWith("." + m[1]))) out.push(m[2] + c.slice(i));
  });
  return out.join("; ");
}

function convertSetCookie(sc, host) {
  const parts = sc.split(";").map(x => x.trim());
  const first = parts.shift();
  const eq = first.indexOf("=");
  if (eq < 1) return null;
  let dom = host;
  const attrs = [];
  for (const p of parts) {
    const [k, ...r] = p.split("=");
    const key = k.toLowerCase();
    const v = r.join("=");
    if (key === "domain") {
      const d = v.replace(/^\./, "").toLowerCase();
      if (host === d || host.endsWith("." + d)) dom = d;
    } else if (key === "expires" || key === "max-age") attrs.push(k + "=" + v);
    else if (key === "httponly") attrs.push("HttpOnly");
  }
  return `__px_${dom}__${first.slice(0, eq)}=${first.slice(eq + 1)}; Path=/; SameSite=Lax; Secure` +
    (attrs.length ? "; " + attrs.join("; ") : "");
}

/* ---------- ハンドラ ---------- */
module.exports = async (req, res) => {
  try {
    const sp = new URL(req.url, "http://localhost").searchParams;
    let raw = sp.get("url");
    const purl = sp.get("__purl"); // GETフォーム送信
    if (purl) {
      try {
        const t = new URL(purl);
        for (const [k, v] of sp) if (k !== "__purl") t.searchParams.append(k, v);
        raw = t.href;
      } catch { return res.status(400).send("invalid form url"); }
    }
    if (!raw) return res.status(400).send("url parameter required");

    let target;
    try { target = new URL(raw); } catch { return res.status(400).send("invalid url"); }
    await assertPublic(target);

    const method = ["POST", "HEAD"].includes(req.method) ? req.method : "GET";
    const headers = {
      "user-agent": req.headers["user-agent"] || "Mozilla/5.0",
      accept: req.headers.accept || "*/*",
      "accept-language": req.headers["accept-language"] || "ja,en;q=0.8",
      referer: target.origin + "/",
    };
    if (req.headers.range) headers.range = req.headers.range; // mp4のシーク用
    const ck = buildCookie(req, target.hostname.toLowerCase());
    if (ck) headers.cookie = ck;

    let body;
    if (method === "POST") {
      const ct = req.headers["content-type"] || "";
      headers["content-type"] = ct;
      headers.origin = target.origin;
      if (Buffer.isBuffer(req.body) || typeof req.body === "string") body = req.body;
      else if (req.body && /urlencoded/i.test(ct)) body = new URLSearchParams(req.body).toString();
      else if (req.body) body = JSON.stringify(req.body);
    }

    const upstream = await fetch(target.href, { method, headers, body, redirect: "manual" });

    // Set-Cookie をブラウザへ中継
    const rawCookies = upstream.headers.getSetCookie ? upstream.headers.getSetCookie() : [];
    const cookies = rawCookies.map(c => convertSetCookie(c, target.hostname.toLowerCase())).filter(Boolean);
    if (cookies.length) res.setHeader("Set-Cookie", cookies);

    // リダイレクトもプロキシ経由に
    if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.get("location")) {
      res.setHeader("Location", rw(upstream.headers.get("location"), target.href));
      return res.status(upstream.status).end();
    }

    const type = upstream.headers.get("content-type") || "";
    res.status(upstream.status);
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (type) res.setHeader("Content-Type", type);

    if (/text\/html/i.test(type)) {
      const html = rewriteHtml(await upstream.text(), target.href);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.send(html);
    }
    if (/text\/css/i.test(type)) {
      const css = rwCss(await upstream.text(), target.href);
      res.setHeader("Content-Type", "text/css; charset=utf-8");
      return res.send(css);
    }

    // 画像 / JS / mp4 など: ストリーミング転送
    const encoded = upstream.headers.get("content-encoding");
    for (const h of ["content-range", "accept-ranges", "cache-control", "etag", "last-modified"]) {
      const v = upstream.headers.get(h);
      if (v) res.setHeader(h, v);
    }
    const len = upstream.headers.get("content-length");
    if (len && !encoded) res.setHeader("Content-Length", len);

    if (!upstream.body || method === "HEAD") return res.end();
    Readable.fromWeb(upstream.body).on("error", () => res.end()).pipe(res);
  } catch (e) {
    res.status(502).send("Proxy error: " + e.message);
  }
};
