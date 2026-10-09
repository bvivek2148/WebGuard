import type { Plugin, ViteDevServer } from "vite";
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

// ============================================================================
// WebGuard AI WAF — Dynamic Reverse Proxy & Security Inspection Middleware
// Fully dynamic target routing (no hardcoded URLs), recursive redirect follower,
// deep OWASP CRS signature inspection (SQLi, XSS, RCE, LFI, SSRF), and frame-unblocking.
// ============================================================================

interface ThreatDetection {
  isMalicious: boolean;
  threatType?: "SQL_INJECTION" | "XSS" | "COMMAND_INJECTION" | "PATH_TRAVERSAL" | "SSRF" | "CRLF";
  ruleId?: string;
  matchedPattern?: string;
  threatScore?: number;
}

function inspectPayload(rawContent: string): ThreatDetection {
  if (!rawContent || typeof rawContent !== "string") return { isMalicious: false };

  let decoded = rawContent;
  try {
    decoded = decodeURIComponent(rawContent);
  } catch (e) {}
  try {
    decoded = decodeURIComponent(decoded);
  } catch (e) {}

  const textToScan = `${rawContent} ${decoded}`;

  // 1. SQL Injection Patterns (Comprehensive OWASP CRS Coverage)
  const sqliPatterns = [
    /('|\%27)\s*([\-\-]|#|\/\*)/i,                                             // ' -- or ' # or ' /*
    /('|\%27)\s*(or|and)\s*('|\%27|\d+|\w+)\s*(=|like)\s*('|\%27|\d+|\w+)/i, // ' or 1=1, ' or 'a'='a
    /('|\%27)\s*(or|and)\s+true/i,                                             // ' or true
    /('|\%27)\s*(or|and)\s*('|\%27)\s*=\s*('|\%27)/i,                          // ' or ''='
    /\b(admin|user|test|root)('|\%27)\s*(\-\-|#|\/\*)/i,                        // admin'--
    /\b(union(\s+all)?\s+select)\b/i,                                          // union select
    /\b(select\s+.+\s+from)\b/i,                                               // select ... from
    /\b(insert\s+into|delete\s+from|drop\s+table|update\s+.+\s+set)\b/i,
    /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
    /(\%27|\')\s*\)\s*(or|and)/i,                                              // ') or
    /\b(or|and)\s+1\s*=\s*1\b/i,                                               // or 1=1
    /\b(or|and)\s+0\s*=\s*0\b/i,
    /\bor\s+true\b/i,
    /''\s*=\s*''/i,
    /"\s*or\s*"1"\s*=\s*"1"/i,
    /"\s*or\s*""\s*=\s*""/i,
  ];

  for (const pattern of sqliPatterns) {
    const match = textToScan.match(pattern);
    if (match) {
      return {
        isMalicious: true,
        threatType: "SQL_INJECTION",
        ruleId: "OWASP-CRS-942-SQLI",
        matchedPattern: match[0],
        threatScore: 98,
      };
    }
  }

  // 2. Cross-Site Scripting (XSS) Patterns
  const xssPatterns = [
    /<script[\s\S]*?>/i,
    /<\/script>/i,
    /javascript\s*:/i,
    /onerror\s*=/i,
    /onload\s*=/i,
    /onclick\s*=/i,
    /<img[^>]+src\s*=\s*['"]?x/i,
    /<svg[^>]+onload/i,
    /<iframe[\s\S]*?>/i,
    /alert\s*\(/i,
    /document\.cookie/i,
  ];

  for (const pattern of xssPatterns) {
    const match = textToScan.match(pattern);
    if (match) {
      return {
        isMalicious: true,
        threatType: "XSS",
        ruleId: "OWASP-CRS-941-XSS",
        matchedPattern: match[0],
        threatScore: 94,
      };
    }
  }

  // 3. Remote OS Command Execution
  const cmdiPatterns = [
    /(;|\||`|\$\()\s*(whoami|cat\s+\/etc|id|uname|dir|ls|netstat|powershell|bash|sh|nc|curl|wget)/i,
    /\b(cat\s+\/etc\/passwd|cat\s+\/etc\/shadow)\b/i,
  ];
  for (const pattern of cmdiPatterns) {
    const match = textToScan.match(pattern);
    if (match) {
      return {
        isMalicious: true,
        threatType: "COMMAND_INJECTION",
        ruleId: "OWASP-CRS-932-RCE",
        matchedPattern: match[0],
        threatScore: 99,
      };
    }
  }

  // 4. Path Traversal / LFI
  const traversalPatterns = [
    /(\.\.[\/\\]){2,}/i,
    /(\%2e\%2e[\/\\]){2,}/i,
    /etc[\/\\](passwd|shadow|hosts)/i,
    /win\.ini|boot\.ini/i,
  ];
  for (const pattern of traversalPatterns) {
    const match = textToScan.match(pattern);
    if (match) {
      return {
        isMalicious: true,
        threatType: "PATH_TRAVERSAL",
        ruleId: "OWASP-CRS-930-LFI",
        matchedPattern: match[0],
        threatScore: 95,
      };
    }
  }

  // 5. SSRF to cloud metadata
  if (/169\.254\.169\.254|127\.0\.0\.1|localhost/i.test(textToScan) && /meta|latest|token|secret|admin/i.test(textToScan)) {
    return {
      isMalicious: true,
      threatType: "SSRF",
      ruleId: "OWASP-CRS-934-SSRF",
      matchedPattern: "SSRF_METADATA_ATTEMPT",
      threatScore: 96,
    };
  }

  return { isMalicious: false };
}

function generateWafBlockHtml(detection: ThreatDetection, targetUrl: string, clientIp: string) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden — WebGuard AI WAF</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #090d16;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 24px;
      box-sizing: border-box;
    }
    .card {
      background: #111827;
      border: 1px solid #ef4444;
      border-radius: 16px;
      padding: 32px;
      max-width: 580px;
      width: 100%;
      box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.25);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border: 1px solid rgba(239, 68, 68, 0.4);
    }
    h1 {
      font-size: 22px;
      font-weight: 800;
      margin: 16px 0 8px 0;
      color: #ffffff;
    }
    p {
      color: #94a3b8;
      font-size: 14px;
      line-height: 1.5;
      margin: 0 0 20px 0;
    }
    .details {
      background: #030712;
      border: 1px solid #1f2937;
      border-radius: 12px;
      padding: 16px;
      font-family: monospace;
      font-size: 12px;
      margin-bottom: 24px;
    }
    .row {
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid #111827;
    }
    .row:last-child { border-bottom: none; }
    .label { color: #6b7280; }
    .val { color: #38bdf8; font-weight: 600; }
    .val.alert { color: #f87171; font-weight: bold; }
    .footer {
      font-size: 11px;
      color: #6b7280;
      text-align: center;
      border-top: 1px solid #1f2937;
      padding-top: 16px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">🛡️ WebGuard Edge Interceptor</div>
    <h1>403 Forbidden — Malicious Attack Blocked</h1>
    <p>Your request was analyzed and dropped at the edge before reaching the target application. An exploit payload violating OWASP Core Rules was detected.</p>
    
    <div class="details">
      <div class="row"><span class="label">Triggered Rule:</span><span class="val alert">${detection.ruleId || "OWASP-CRS-GENERIC"}</span></div>
      <div class="row"><span class="label">Attack Type:</span><span class="val alert">${detection.threatType || "INJECTION_ATTACK"}</span></div>
      <div class="row"><span class="label">Threat Score:</span><span class="val alert">${detection.threatScore || 98}/100</span></div>
      <div class="row"><span class="label">Matched Signature:</span><span class="val" style="color:#fbbf24">${detection.matchedPattern ? encodeURIComponent(detection.matchedPattern).slice(0, 40) : "SIGNATURE_DETECTED"}</span></div>
      <div class="row"><span class="label">Target Origin:</span><span class="val">${targetUrl}</span></div>
      <div class="row"><span class="label">Client IP:</span><span class="val">${clientIp}</span></div>
    </div>

    <div class="footer">
      WebGuard Next-Gen AI Web Application Firewall & Security Operations Center
    </div>
  </div>
</body>
</html>`;
}

import zlib from "node:zlib";

// Persistent Connection Pooling for ultra-low latency subresource fetching
const httpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 100,
  maxFreeSockets: 20,
  timeout: 30000,
});

const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 100,
  maxFreeSockets: 20,
  timeout: 30000,
  rejectUnauthorized: false, // allow testing local/staging self-signed targets
});

// Helper to decompress buffer based on content-encoding
function decompressBuffer(buffer: Buffer, encoding?: string): Promise<Buffer> {
  if (!buffer || buffer.length === 0 || !encoding) {
    return Promise.resolve(buffer);
  }
  const enc = encoding.toLowerCase().trim();
  return new Promise((resolve) => {
    if (enc.includes("gzip") || enc.includes("x-gzip")) {
      zlib.gunzip(buffer, (err, decompressed) => {
        resolve(err ? buffer : decompressed);
      });
    } else if (enc.includes("deflate")) {
      zlib.inflate(buffer, (err, decompressed) => {
        resolve(err ? buffer : decompressed);
      });
    } else if (enc.includes("br")) {
      zlib.brotliDecompress(buffer, (err, decompressed) => {
        resolve(err ? buffer : decompressed);
      });
    } else {
      resolve(buffer);
    }
  });
}

// Helper to execute request with automatic HTTP redirect following & connection reuse
function executeProxyRequest(
  targetUrlObj: URL,
  method: string,
  headers: Record<string, string>,
  bodyBuffer: Buffer,
  maxRedirects: number = 5
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: Buffer; finalUrl: URL }> {
  return new Promise((resolve, reject) => {
    const isHttps = targetUrlObj.protocol === "https:";
    const clientModule = isHttps ? https : http;
    const path = (targetUrlObj.pathname || "/") + (targetUrlObj.search || "");

    const clientHeaders = { ...headers };
    clientHeaders["Host"] = targetUrlObj.host;
    // Request compressed content for high throughput
    clientHeaders["Accept-Encoding"] = "gzip, deflate, br";

    const req = clientModule.request(
      {
        protocol: targetUrlObj.protocol,
        hostname: targetUrlObj.hostname,
        port: targetUrlObj.port || (isHttps ? 443 : 80),
        method,
        path,
        headers: clientHeaders,
        agent: isHttps ? httpsAgent : httpAgent,
        timeout: 12000,
      },
      (res) => {
        const statusCode = res.statusCode || 200;

        // Check for redirects (301, 302, 303, 307, 308)
        if ([301, 302, 303, 307, 308].includes(statusCode) && res.headers.location && maxRedirects > 0) {
          const redirectUrl = new URL(res.headers.location, targetUrlObj.href);
          res.resume(); // consume response data to free socket back to pool
          return resolve(executeProxyRequest(redirectUrl, method, headers, bodyBuffer, maxRedirects - 1));
        }

        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", async () => {
          const rawBody = Buffer.concat(chunks);
          const encoding = res.headers["content-encoding"] as string | undefined;
          const decompressedBody = await decompressBuffer(rawBody, encoding);

          // Return response with decompressed body and cleaned content-encoding
          const cleanHeaders = { ...res.headers };
          delete cleanHeaders["content-encoding"];

          resolve({
            statusCode,
            headers: cleanHeaders,
            body: decompressedBody,
            finalUrl: targetUrlObj,
          });
        });
      }
    );

    req.on("error", (err) => reject(err));
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request to target origin timed out"));
    });

    if (bodyBuffer.length > 0) {
      req.write(bodyBuffer);
    }
    req.end();
  });
}

export function webguardWafProxyPlugin(): Plugin {
  return {
    name: "vite-plugin-webguard-waf-proxy",
    configureServer(server: ViteDevServer) {
      server.middlewares.use(async (req, res, next) => {
        const reqUrl = req.url || "";

        // Only handle requests starting with /api/waf-proxy
        if (!reqUrl.startsWith("/api/waf-proxy")) {
          return next();
        }

        try {
          const parsedUrl = new URL(reqUrl, `http://${req.headers.host || "localhost:5173"}`);
          const targetParam = parsedUrl.searchParams.get("url");
          const wafParam = parsedUrl.searchParams.get("waf"); // "1" = blocking, "0" = off
          const isWafBlocking = wafParam !== "0";

          if (!targetParam) {
            res.statusCode = 400;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ error: "Missing 'url' query parameter in /api/waf-proxy" }));
            return;
          }

          let normalizedTarget = targetParam.trim();
          if (!normalizedTarget.startsWith("http://") && !normalizedTarget.startsWith("https://")) {
            normalizedTarget = `https://${normalizedTarget}`;
          }

          // Strip hash fragments (like #/) from origin requests
          const targetUrlObj = new URL(normalizedTarget);
          const targetOrigin = targetUrlObj.origin;

          // Read body if POST/PUT/PATCH
          const chunks: Buffer[] = [];
          for await (const chunk of req) {
            chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
          }
          const bodyBuffer = Buffer.concat(chunks);
          const bodyString = bodyBuffer.toString("utf-8");

          // Inspect for threats across path, query params, body and headers
          const contentToInspect = `${parsedUrl.pathname} ${parsedUrl.search} ${targetUrlObj.pathname} ${targetUrlObj.search} ${bodyString} ${JSON.stringify(req.headers)}`;
          const threat = inspectPayload(contentToInspect);

          // If WAF is ON (BLOCK mode) and malicious payload detected -> DROP AT EDGE WITH 403
          if (isWafBlocking && threat.isMalicious) {
            res.statusCode = 403;
            res.setHeader("X-WebGuard-Protection", "ACTIVE");
            res.setHeader("X-WebGuard-Action", "BLOCKED_AT_EDGE");
            res.setHeader("X-WebGuard-Rule", threat.ruleId || "OWASP-CRS-BLOCK");
            res.setHeader("X-WebGuard-Threat-Score", String(threat.threatScore || 98));

            const acceptHeader = String(req.headers["accept"] || "");
            if (acceptHeader.includes("application/json") && !acceptHeader.includes("text/html")) {
              res.setHeader("Content-Type", "application/json");
              res.end(
                JSON.stringify({
                  error: "403 Forbidden",
                  message: "Request blocked by WebGuard AI WAF.",
                  threatType: threat.threatType,
                  ruleTriggered: threat.ruleId,
                  threatScore: threat.threatScore,
                  targetOrigin,
                  action: "BLOCKED_BEFORE_ORIGIN",
                })
              );
            } else {
              res.setHeader("Content-Type", "text/html; charset=utf-8");
              res.end(generateWafBlockHtml(threat, targetOrigin, String(req.socket.remoteAddress || "127.0.0.1")));
            }
            return;
          }

          // Prepare headers for proxying to target
          const clientHeaders: Record<string, string> = {};
          for (const [k, v] of Object.entries(req.headers)) {
            if (!v) continue;
            const keyLower = k.toLowerCase();
            if (keyLower === "host" || keyLower === "accept-encoding" || keyLower === "connection") continue;
            clientHeaders[k] = Array.isArray(v) ? v.join(", ") : v;
          }
          clientHeaders["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WebGuard-Proxy/2.0";

          // Execute request with automatic redirect following
          const proxyResult = await executeProxyRequest(
            targetUrlObj,
            req.method || "GET",
            clientHeaders,
            bodyBuffer
          );

          res.statusCode = proxyResult.statusCode;

          // Copy response headers, stripping all frame blockers and CSP restrictions
          for (const [key, value] of Object.entries(proxyResult.headers)) {
            if (!value) continue;
            const lower = key.toLowerCase();
            if (
              lower === "x-frame-options" ||
              lower === "content-security-policy" ||
              lower === "content-security-policy-report-only" ||
              lower === "frame-ancestors" ||
              lower === "content-length"
            ) {
              continue;
            }
            res.setHeader(key, value);
          }

          res.setHeader("X-Frame-Options", "ALLOWALL");
          res.setHeader("Access-Control-Allow-Origin", "*");
          res.setHeader("Access-Control-Allow-Headers", "*");
          res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
          res.setHeader("X-WebGuard-Proxy-Target", proxyResult.finalUrl.origin);

          const contentType = String(proxyResult.headers["content-type"] || "");

          // If response is HTML, inject base href, rewrite root-relative assets and inject bridge script
          if (contentType.includes("text/html")) {
            let html = proxyResult.body.toString("utf-8");
            const finalOrigin = proxyResult.finalUrl.origin;

            // 1. Force base tag so relative assets resolve directly to final target origin
            const baseTag = `<base href="${finalOrigin}/">`;
            if (/<base\s+[^>]*>/i.test(html)) {
              html = html.replace(/<base\s+[^>]*>/i, baseTag);
            } else if (/<head[^>]*>/i.test(html)) {
              html = html.replace(/(<head[^>]*>)/i, `$1\n  ${baseTag}`);
            } else {
              html = `${baseTag}\n${html}`;
            }

            // 2. Rewrite root-relative links, stylesheets, scripts, and images so they resolve directly to final origin
            html = html
              .replace(/(<link\b[^>]*?\bhref=["'])\/([^/][^"']*?["'])/gi, `$1${finalOrigin}/$2`)
              .replace(/(<script\b[^>]*?\bsrc=["'])\/([^/][^"']*?["'])/gi, `$1${finalOrigin}/$2`)
              .replace(/(<img\b[^>]*?\bsrc=["'])\/([^/][^"']*?["'])/gi, `$1${finalOrigin}/$2`)
              .replace(/(<source\b[^>]*?\bsrc=["'])\/([^/][^"']*?["'])/gi, `$1${finalOrigin}/$2`)
              .replace(/(<source\b[^>]*?\bsrcset=["'])\/([^/][^"']*?["'])/gi, `$1${finalOrigin}/$2`);

            // 3. In-frame bridge script to route fetch/XHR through WAF and post telemetry
            const bridgeScript = `
<script>
  (function() {
    window.__WEBGARD_ACTIVE__ = true;
    var targetOrigin = "${finalOrigin}";
    var isWaf = "${isWafBlocking ? "1" : "0"}";

    function reportPacket(method, url, status, body) {
      try {
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({
            type: "WEBGARD_INTERCEPTED_TRAFFIC",
            method: method || "GET",
            url: url,
            status: status || 200,
            body: body ? String(body).slice(0, 500) : "",
            timestamp: Date.now()
          }, "*");
        }
      } catch(e) {}
    }

    // Intercept fetch
    var origFetch = window.fetch;
    if (origFetch) {
      window.fetch = function(input, init) {
        var url = typeof input === "string" ? input : (input && input.url ? input.url : "");
        var method = (init && init.method) || (input && input.method) || "GET";
        var reqBody = (init && init.body) || "";
        
        var finalProxyUrl = url;
        if (url.startsWith("/")) {
          if (!url.startsWith("/api/waf-proxy")) {
            finalProxyUrl = "/api/waf-proxy?url=" + encodeURIComponent(targetOrigin + url) + "&waf=" + isWaf;
          }
        } else if (url.startsWith(targetOrigin)) {
          finalProxyUrl = "/api/waf-proxy?url=" + encodeURIComponent(url) + "&waf=" + isWaf;
        }

        if (typeof input === "string") {
          input = finalProxyUrl;
        } else if (input && input.url) {
          input = new Request(finalProxyUrl, init || input);
        }

        return origFetch.call(this, input, init).then(function(res) {
          reportPacket(method, url, res.status, reqBody);
          return res;
        }).catch(function(err) {
          reportPacket(method, url, 500, reqBody);
          throw err;
        });
      };
    }

    // Intercept XMLHttpRequest
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
      this._wg_method = method;
      this._wg_orig_url = url;
      var finalUrl = url;
      if (typeof url === "string") {
        if (url.startsWith("/")) {
          if (!url.startsWith("/api/waf-proxy")) {
            finalUrl = "/api/waf-proxy?url=" + encodeURIComponent(targetOrigin + url) + "&waf=" + isWaf;
          }
        } else if (url.startsWith(targetOrigin)) {
          finalUrl = "/api/waf-proxy?url=" + encodeURIComponent(url) + "&waf=" + isWaf;
        }
      }
      this._wg_url = finalUrl;
      return origOpen.call(this, method, finalUrl, async !== undefined ? async : true, user, pass);
    };

    XMLHttpRequest.prototype.send = function(body) {
      var self = this;
      this.addEventListener("load", function() {
        reportPacket(self._wg_method || "GET", self._wg_orig_url || self._wg_url || "", self.status || 200, body);
      });
      return origSend.call(this, body);
    };

    console.log("[WebGuard] Real-Time WAF proxy bridge active for: " + targetOrigin);
  })();
</script>`;
            if (/<\/head>/i.test(html)) {
              html = html.replace(/<\/head>/i, `${bridgeScript}\n</head>`);
            } else if (/<\/body>/i.test(html)) {
              html = html.replace(/<\/body>/i, `${bridgeScript}\n</body>`);
            } else {
              html = `${html}\n${bridgeScript}`;
            }

            const modifiedBuffer = Buffer.from(html, "utf-8");
            res.setHeader("Content-Length", modifiedBuffer.length);
            res.end(modifiedBuffer);
          } else {
            res.end(proxyResult.body);
          }
        } catch (error: any) {
          console.error("[WebGuard Proxy Error]", error);
          res.statusCode = 502;
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          res.end(`
            <div style="font-family:sans-serif;padding:32px;background:#090d16;color:#f8fafc;min-height:100vh;">
              <h2 style="color:#f87171;margin-top:0;">502 Bad Gateway — WebGuard Proxy</h2>
              <p>Could not reach target origin: <strong>${reqUrl}</strong></p>
              <p style="color:#94a3b8;font-size:12px;">Error detail: ${error?.message || "Connection refused"}</p>
            </div>
          `);
        }
      });
    },
  };
}
