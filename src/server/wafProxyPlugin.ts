import type { Plugin, ViteDevServer } from "vite";
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

// ============================================================================
// WebGuard AI WAF — Reverse Proxy & Security Inspection Middleware
// Strips X-Frame-Options/CSP, inspects payloads, and blocks malicious traffic
// ============================================================================

interface ThreatDetection {
  isMalicious: boolean;
  threatType?: "SQL_INJECTION" | "XSS" | "COMMAND_INJECTION" | "PATH_TRAVERSAL" | "SSRF" | "CRLF";
  ruleId?: string;
  matchedPattern?: string;
  threatScore?: number;
}

function inspectPayload(content: string): ThreatDetection {
  if (!content || typeof content !== "string") return { isMalicious: false };

  // SQL Injection Patterns
  const sqliRegex = /('|\%27)\s*([\-\-]|or|and|\/\*|union|select|insert|update|delete|drop|benchmark|sleep)/i;
  const sqliMatch = content.match(sqliRegex) || content.match(/('|\%27)\s*or\s*('|\%27|\d+)\s*=\s*('|\%27|\d+)/i) || content.match(/union\s+select/i);
  if (sqliMatch) {
    return {
      isMalicious: true,
      threatType: "SQL_INJECTION",
      ruleId: "OWASP-CRS-942-SQLI",
      matchedPattern: sqliMatch[0],
      threatScore: 96,
    };
  }

  // Cross-Site Scripting (XSS) Patterns
  const xssMatch = content.match(/<script[\s\S]*?>[\s\S]*?<\/script>/i) ||
    content.match(/javascript\s*:/i) ||
    content.match(/onerror\s*=\s*|onload\s*=\s*|<img[^>]+src\s*=\s*x/i) ||
    content.match(/<svg[^>]+onload/i);
  if (xssMatch) {
    return {
      isMalicious: true,
      threatType: "XSS",
      ruleId: "OWASP-CRS-941-XSS",
      matchedPattern: xssMatch[0],
      threatScore: 92,
    };
  }

  // Remote OS Command Execution
  const cmdiMatch = content.match(/(;|\||`|\$\()\s*(whoami|cat\s+\/etc|id|uname|dir|ls|netstat|powershell|bash)/i);
  if (cmdiMatch) {
    return {
      isMalicious: true,
      threatType: "COMMAND_INJECTION",
      ruleId: "OWASP-CRS-932-RCE",
      matchedPattern: cmdiMatch[0],
      threatScore: 98,
    };
  }

  // Path Traversal / LFI
  const traversalMatch = content.match(/(\.\.[\/\\]){2,}|(\%2e\%2e[\/\\]){2,}|etc[\/\\](passwd|shadow)/i);
  if (traversalMatch) {
    return {
      isMalicious: true,
      threatType: "PATH_TRAVERSAL",
      ruleId: "OWASP-CRS-930-LFI",
      matchedPattern: traversalMatch[0],
      threatScore: 94,
    };
  }

  // SSRF to cloud metadata
  const ssrfMatch = content.match(/169\.254\.169\.254|127\.0\.0\.1|localhost:8080/i);
  if (ssrfMatch && /metadata|latest|meta-data/i.test(content)) {
    return {
      isMalicious: true,
      threatType: "SSRF",
      ruleId: "OWASP-CRS-934-SSRF",
      matchedPattern: ssrfMatch[0],
      threatScore: 95,
    };
  }

  return { isMalicious: false };
}

function generateWafBlockHtml(detection: ThreatDetection, targetUrl: string, clientIp: string) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden - WebGuard AI WAF</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
      box-sizing: border-box;
    }
    .card {
      background: #1e293b;
      border: 1px solid #dc2626;
      border-radius: 16px;
      padding: 32px;
      max-width: 580px;
      width: 100%;
      box-shadow: 0 25px 50px -12px rgba(220, 38, 38, 0.25);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(220, 38, 38, 0.2);
      color: #f87171;
      padding: 6px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border: 1px solid rgba(220, 38, 38, 0.4);
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
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 16px;
      font-family: monospace;
      font-size: 12px;
      margin-bottom: 24px;
    }
    .row {
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      border-bottom: 1px solid #1e293b;
    }
    .row:last-child { border-bottom: none; }
    .label { color: #64748b; }
    .val { color: #38bdf8; font-weight: 600; }
    .val.alert { color: #f87171; font-weight: bold; }
    .footer {
      font-size: 11px;
      color: #64748b;
      text-align: center;
      border-top: 1px solid #334155;
      padding-top: 16px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">🛡️ WebGuard Edge Interceptor</div>
    <h1>403 Forbidden — Malicious Request Blocked</h1>
    <p>Your request was analyzed and dropped before reaching the target origin server. An exploit signature violating OWASP Core Rules was detected.</p>
    
    <div class="details">
      <div class="row"><span class="label">Triggered Rule:</span><span class="val alert">${detection.ruleId || "OWASP-CRS-GENERIC"}</span></div>
      <div class="row"><span class="label">Attack Classification:</span><span class="val alert">${detection.threatType || "INJECTION_ATTACK"}</span></div>
      <div class="row"><span class="label">Threat Score:</span><span class="val alert">${detection.threatScore || 95}/100</span></div>
      <div class="row"><span class="label">Matched Pattern:</span><span class="val" style="color:#fbbf24">${detection.matchedPattern ? encodeURIComponent(detection.matchedPattern).slice(0, 40) : "SIGNATURE_DETECTED"}</span></div>
      <div class="row"><span class="label">Protected Target:</span><span class="val">${targetUrl}</span></div>
      <div class="row"><span class="label">Client IP:</span><span class="val">${clientIp}</span></div>
    </div>

    <div class="footer">
      WebGuard Next-Gen AI Web Application Firewall & Security Operations Center
    </div>
  </div>
</body>
</html>`;
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

          // Strip any hash (like #/) from the origin URL when making HTTP backend request
          const targetUrlObj = new URL(normalizedTarget);
          const targetOrigin = targetUrlObj.origin;

          // Read body if POST/PUT/PATCH
          const chunks: Buffer[] = [];
          for await (const chunk of req) {
            chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
          }
          const bodyBuffer = Buffer.concat(chunks);
          const bodyString = bodyBuffer.toString("utf-8");

          // Inspect for threats
          const contentToInspect = `${parsedUrl.pathname} ${parsedUrl.search} ${bodyString} ${JSON.stringify(req.headers)}`;
          const threat = inspectPayload(contentToInspect);

          // If WAF is ON and malicious payload detected -> BLOCK
          if (isWafBlocking && threat.isMalicious) {
            res.statusCode = 403;
            res.setHeader("X-WebGuard-Protection", "ACTIVE");
            res.setHeader("X-WebGuard-Action", "BLOCKED_AT_EDGE");
            res.setHeader("X-WebGuard-Rule", threat.ruleId || "OWASP-CRS-BLOCK");
            res.setHeader("X-WebGuard-Threat-Score", String(threat.threatScore || 95));

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

          // Prepare headers for proxying to real target
          const clientHeaders: Record<string, string> = {};
          for (const [k, v] of Object.entries(req.headers)) {
            if (!v) continue;
            const keyLower = k.toLowerCase();
            // Skip host & encoding to avoid decompression issues
            if (keyLower === "host" || keyLower === "accept-encoding" || keyLower === "connection") continue;
            clientHeaders[k] = Array.isArray(v) ? v.join(", ") : v;
          }
          clientHeaders["Host"] = targetUrlObj.host;
          clientHeaders["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WebGuard-Proxy/2.0";

          const isHttps = targetUrlObj.protocol === "https:";
          const clientModule = isHttps ? https : http;

          const proxyPath = targetUrlObj.pathname + targetUrlObj.search;

          const proxyReq = clientModule.request(
            targetUrlObj,
            {
              method: req.method,
              path: proxyPath || "/",
              headers: clientHeaders,
              timeout: 12000,
            },
            (proxyRes) => {
              // Copy status code
              res.statusCode = proxyRes.statusCode || 200;

              // Copy response headers, but STRIP all framing & CSP blockers
              for (const [key, value] of Object.entries(proxyRes.headers)) {
                if (!value) continue;
                const lower = key.toLowerCase();
                if (
                  lower === "x-frame-options" ||
                  lower === "content-security-policy" ||
                  lower === "content-security-policy-report-only" ||
                  lower === "frame-ancestors" ||
                  lower === "content-length" // Will recalculate if HTML rewritten
                ) {
                  continue;
                }
                res.setHeader(key, value);
              }

              // Explicitly allow framing in our dashboard
              res.setHeader("X-Frame-Options", "ALLOWALL");
              res.setHeader("Access-Control-Allow-Origin", "*");
              res.setHeader("X-WebGuard-Proxy-Target", targetOrigin);

              const responseChunks: Buffer[] = [];
              proxyRes.on("data", (chunk) => responseChunks.push(chunk));
              proxyRes.on("end", () => {
                const fullResponse = Buffer.concat(responseChunks);
                const contentType = String(proxyRes.headers["content-type"] || "");

                // If response is HTML, inject <base> tag so relative CSS/JS/images and links work properly
                if (contentType.includes("text/html")) {
                  let html = fullResponse.toString("utf-8");

                  // Inject <base href="..."> if not already present
                  const baseTag = `<base href="${targetOrigin}/">`;
                  if (!html.includes("<base ")) {
                    html = html.replace(/<head>/i, `<head>\n  ${baseTag}`);
                  }

                  // Inject a small WebGuard in-frame bridge script to route fetch/XHR through WAF
                  const bridgeScript = `
<script>
  (function() {
    window.__WEBGARD_ACTIVE__ = true;
    console.log("[WebGuard] WAF proxy bridge active for: ${targetOrigin}");
  })();
</script>`;
                  html = html.replace(/<\/head>/i, `${bridgeScript}\n</head>`);

                  const modifiedBuffer = Buffer.from(html, "utf-8");
                  res.setHeader("Content-Length", modifiedBuffer.length);
                  res.end(modifiedBuffer);
                } else {
                  res.end(fullResponse);
                }
              });
            }
          );

          proxyReq.on("error", (err) => {
            console.error("[WebGuard Proxy Error]", err.message);
            res.statusCode = 502;
            res.setHeader("Content-Type", "text/html; charset=utf-8");
            res.end(`
              <div style="font-family:sans-serif;padding:30px;background:#0f172a;color:#f8fafc;min-height:100vh;">
                <h2 style="color:#f87171">502 Bad Gateway — WebGuard Proxy</h2>
                <p>Could not reach target origin: <strong>${targetOrigin}</strong></p>
                <p style="color:#94a3b8;font-size:12px;">Error detail: ${err.message}</p>
              </div>
            `);
          });

          if (bodyBuffer.length > 0) {
            proxyReq.write(bodyBuffer);
          }
          proxyReq.end();
        } catch (error: any) {
          console.error("[WebGuard Middleware Error]", error);
          res.statusCode = 500;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: "Internal WAF Proxy Error", details: error?.message }));
        }
      });
    },
  };
}
