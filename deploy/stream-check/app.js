#!/usr/bin/env node
"use strict";
// stream-check — server-side end-to-end verifier for the XHTTP VLESS node.
// Pure Node (no dependencies). Implements a minimal VLESS + XHTTP packet-up
// client matching deploy/stream-node/app.js protocol:
//   POST <XPATH>/<session>/<seq>  (seq 0 carries the VLESS header)
//   GET  <XPATH>/<session>        (downlink; body = 2-byte VLESS response
//                                 header + proxied bytes)
// Endpoints:
//   GET /        -> runs check: proxies generate_204 (expect 204) and
//                   ipv4.ip.sb/ip through the node, returns JSON.
//   GET /b64     -> base64 of the VLESS URL built from env (SUB_BODY source).
//   GET /health  -> "ok"
// Env: NODE_HOST, NODE_UUID, NODE_XPATH, PORT.

const http = require("http");
const https = require("https");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 8080);
const NODE_HOST = process.env.NODE_HOST || "";
const NODE_UUID = process.env.NODE_UUID || "";
const NODE_XPATH = process.env.NODE_XPATH || "";
const LEG_MS = 45000;

function vlessHeader(host, port) {
  const h = Buffer.from(host, "utf8");
  const b = Buffer.alloc(1 + 16 + 1 + 1 + 2 + 1 + 1 + h.length);
  let o = 0;
  b[o++] = 0x00; // version
  Buffer.from(NODE_UUID.replaceAll("-", ""), "hex").copy(b, o); o += 16;
  b[o++] = 0x00; // addon length
  b[o++] = 0x01; // command: TCP
  b.writeUInt16BE(port, o); o += 2;
  b[o++] = 0x02; // address type: domain
  b[o++] = h.length;
  h.copy(b, o);
  return b;
}

function vlessUrl() {
  const host = NODE_HOST;
  return (
    "vless://" + NODE_UUID + "@" + host + ":443" +
    "?encryption=none&security=tls&sni=" + host +
    "&alpn=h2%2Chttp%2F1.1&fp=chrome&allowInsecure=1" +
    "&type=xhttp&host=" + host +
    "&path=" + encodeURIComponent(NODE_XPATH) +
    "&mode=packet-up#LightCloud-BE"
  );
}

function postPacket(path, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: NODE_HOST, port: 443, path, method: "POST",
        headers: { "Content-Type": "application/octet-stream", "Content-Length": body.length },
      },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); res.on("error", reject); }
    );
    req.on("error", reject);
    req.setTimeout(LEG_MS, () => req.destroy(new Error("uplink POST timeout")));
    req.end(body);
  });
}

function getDownlink(path) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname: NODE_HOST, port: 443, path, method: "GET" },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
        res.on("error", reject);
      }
    );
    req.on("error", reject);
    req.setTimeout(LEG_MS, () => req.destroy(new Error("downlink GET timeout")));
    req.end();
  });
}

// Proxies one plain-HTTP request through the node and returns the raw
// response bytes (after the 2-byte VLESS response header).
async function proxiedFetch(targetHost, targetPort, httpRequest) {
  if (!NODE_HOST || !NODE_UUID || !NODE_XPATH) {
    throw new Error("NODE_HOST/NODE_UUID/NODE_XPATH env not set");
  }
  const session = crypto.randomUUID().replaceAll("-", "");
  const base = NODE_XPATH.replace(/\/+$/, "");
  const first = Buffer.concat([vlessHeader(targetHost, targetPort), Buffer.from(httpRequest, "utf8")]);
  const up = await postPacket(base + "/" + session + "/0", first);
  if (up !== 200) throw new Error("uplink POST returned " + up);
  const down = await getDownlink(base + "/" + session);
  if (down.status !== 200) throw new Error("downlink GET returned " + down.status);
  if (down.body.length < 2) throw new Error("downlink body too short");
  return down.body.subarray(2);
}

function statusOf(raw) {
  const line = raw.subarray(0, raw.indexOf("\r\n")).toString("latin1");
  const m = line.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/);
  return m ? Number(m[1]) : null;
}

function bodyOf(raw) {
  const i = raw.indexOf("\r\n\r\n");
  return i >= 0 ? raw.subarray(i + 4).toString("utf8").trim() : "";
}

async function runCheck() {
  const t0 = Date.now();
  const g204raw = await proxiedFetch(
    "clients3.google.com", 80,
    "GET http://clients3.google.com/generate_204 HTTP/1.1\r\n" +
    "Host: clients3.google.com\r\nUser-Agent: stream-check/1.0\r\nConnection: close\r\n\r\n"
  );
  const g204 = statusOf(g204raw);
  let exitIp = null;
  try {
    const ipRaw = await proxiedFetch(
      "ipv4.ip.sb", 80,
      "GET http://ipv4.ip.sb/ip HTTP/1.1\r\n" +
      "Host: ipv4.ip.sb\r\nUser-Agent: stream-check/1.0\r\nConnection: close\r\n\r\n"
    );
    exitIp = bodyOf(ipRaw) || null;
  } catch (e) {
    exitIp = "error: " + (e && e.message ? e.message : String(e));
  }
  return {
    ok: g204 === 204,
    node: NODE_HOST,
    generate_204: g204,
    exit_ip: exitIp,
    ms: Date.now() - t0,
  };
}

const server = http.createServer((req, res) => {
  const url = (req.url || "").split("?")[0];
  if (url === "/health" || url === "/healthz") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok\n");
    return;
  }
  if (url === "/b64") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(Buffer.from(vlessUrl(), "utf8").toString("base64") + "\n");
    return;
  }
  if (url === "/" || url === "/check") {
    runCheck().then(
      (r) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(r, null, 2) + "\n"); },
      (e) => {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, node: NODE_HOST, error: String((e && e.message) || e) }) + "\n");
      }
    );
    return;
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found\n");
});

server.listen(PORT, () => console.log("stream-check listening on " + PORT));
