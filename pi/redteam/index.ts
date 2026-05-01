import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "typebox";
import { spawn } from "child_process";

// System prompt - now focused on ANALYSIS only, not execution
const REDTEAM_SYSTEM_PROMPT = `
## 🔴 RED TEAM ANALYST MODE

You are a security analyst reviewing penetration testing results. Your role is to:
- Analyze tool output and identify vulnerabilities
- Recommend next steps based on findings
- Document findings using the \`record_finding\` tool
- Prioritize issues by severity

You do NOT execute commands - the extension handles that automatically.
Focus on analysis, interpretation, and recommendations.
`;

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
  // QUICK REDTEAM - DIRECT EXECUTION
  // ============================================================

  pi.registerCommand("redteam-quick", {
    description: "🚀 Quick Red Team - Parallel nmap, nikto, nuclei, gobuster scans",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /redteam <target>", "error");
        return;
      }

      const target = args.trim();
      state.target = target;
      state.startTime = Date.now();
      state.toolsUsed.push("nmap", "whatweb", "nikto", "nuclei", "gobuster");
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`🚀 Starting full red team engagement on ${target}...`, "info");

      const allResults: Record<string, string> = {};

      // Run scans in parallel using Promise.all
      ctx.ui.notify("Running parallel scans: nmap, whatweb, nikto, gobuster...", "info");

      const scanPromises = [
        // Port scan
        (async () => {
          const result = await execCommand(`nmap -sS -sV -sC -T4 --top-ports 1000 ${target} 2>/dev/null`, 300);
          allResults["nmap"] = result.output;
          ctx.ui.notify("✅ nmap complete", "info");
        })(),

        // Web tech
        (async () => {
          const result = await execCommand(`whatweb -a 3 http://${target} https://${target} 2>/dev/null`, 60);
          allResults["whatweb"] = result.output;
          ctx.ui.notify("✅ whatweb complete", "info");
        })(),

        // Nikto
        (async () => {
          const result = await execCommand(`nikto -h http://${target} -Tuning x 2>/dev/null | head -80`, 180);
          allResults["nikto"] = result.output;
          ctx.ui.notify("✅ nikto complete", "info");
        })(),

        // Directory enum
        (async () => {
          const result = await execCommand(
            `gobuster dir -u http://${target} -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 -q 2>/dev/null || ` +
            `dirb http://${target} /usr/share/dirb/wordlists/common.txt -S 2>/dev/null | head -50`,
            180
          );
          allResults["dirs"] = result.output;
          ctx.ui.notify("✅ directory scan complete", "info");
        })(),

        // Nuclei
        (async () => {
          const result = await execCommand(`nuclei -u http://${target} -severity critical,high,medium -silent 2>/dev/null | head -30`, 300);
          allResults["nuclei"] = result.output;
          ctx.ui.notify("✅ nuclei complete", "info");
        })(),

        // DNS
        (async () => {
          const result = await execCommand(`dig ${target} ANY +short 2>/dev/null; dig ${target} MX +short; dig ${target} NS +short`, 30);
          allResults["dns"] = result.output;
          ctx.ui.notify("✅ DNS enumeration complete", "info");
        })(),
      ];

      await Promise.all(scanPromises);

      // Store results
      state.scanResults = { ...state.scanResults, ...allResults };
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify("✅ All scans complete. Sending to LLM for analysis...", "info");

      // Build report
      const sections = [
        allResults["nmap"] && `## Nmap Scan\n\`\`\`\n${truncateOutput(allResults["nmap"], 150)}\n\`\`\``,
        allResults["whatweb"] && `## Web Technologies\n\`\`\`\n${truncateOutput(allResults["whatweb"], 50)}\n\`\`\``,
        allResults["nikto"] && `## Nikto Web Scanner\n\`\`\`\n${truncateOutput(allResults["nikto"], 80)}\n\`\`\``,
        allResults["dirs"] && `## Directory Enumeration\n\`\`\`\n${truncateOutput(allResults["dirs"], 50)}\n\`\`\``,
        allResults["nuclei"] && `## Nuclei Vulnerabilities\n\`\`\`\n${truncateOutput(allResults["nuclei"], 30)}\n\`\`\``,
        allResults["dns"] && `## DNS Records\n\`\`\`\n${truncateOutput(allResults["dns"], 20)}\n\`\`\``,
      ].filter(Boolean).join("\n\n");

      pi.sendUserMessage(
        `## 🚀 Red Team Engagement Results - ${target}

The following scans were executed in parallel. Analyze ALL results comprehensively.

${sections}

---

## Your Analysis Tasks:

1. **Attack Surface Summary**: List all open ports, services, and web technologies found
2. **Vulnerabilities**: Identify ALL security issues and use \`record_finding\` for each one
3. **Risk Assessment**: Prioritize findings by severity and exploitability  
4. **Recommended Next Steps**: Suggest specific attacks or deeper testing
5. **Quick Wins**: Highlight any easily exploitable issues

Be thorough - this is the foundation of the VAPT report.`,
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
      severity: Type.Union([
        Type.Literal("critical"),
        Type.Literal("high"),
        Type.Literal("medium"),
        Type.Literal("low"),
        Type.Literal("info"),
      ]),
      title: Type.String({ description: "Brief title of the vulnerability" }),
      asset: Type.String({ description: "Affected asset (IP, URL, service)" }),
      description: Type.String({ description: "What the vulnerability is" }),
      evidence: Type.String({ description: "Proof of the vulnerability" }),
      impact: Type.String({ description: "Potential impact if exploited" }),
      remediation: Type.String({ description: "How to fix the vulnerability" }),
      cvss: Type.Optional(Type.String({ description: "CVSS score if known" })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
      const finding: Finding = {
        severity: params.severity,
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
            text: `${SEVERITY_EMOJI[params.severity]} Finding recorded: [${params.severity.toUpperCase()}] ${params.title}

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
- Findings: ${state.findings.length}`,
          },
        ],
        details: { state },
      };
    },
  });

  // ============================================================
  // TERRAIN-STYLE COMPREHENSIVE ASSESSMENT
  // ============================================================

  pi.registerCommand("redteam", {
    description: "🎯 Full Terrain-style security assessment - subdomains, infrastructure, services, endpoints, CORS",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /redteam <domain>", "error");
        return;
      }

      const target = args.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      const workDir = `/tmp/redteam-${target}`;
      
      state.target = target;
      state.startTime = Date.now();
      state.toolsUsed = [];
      state.scanResults = {};
      pi.appendEntry("redteam-state", state);

      ctx.ui.notify(`🎯 Starting Terrain-style assessment on ${target}...`, "info");
      ctx.ui.notify(`Output directory: ${workDir}`, "info");

      // Create working directory
      await execCommand(`mkdir -p ${workDir}`);

      const allResults: Record<string, string> = {};

      // ============================================================
      // PHASE 1: DNS & SUBDOMAIN ENUMERATION (Parallel)
      // ============================================================
      ctx.ui.notify("📡 Phase 1: DNS & Subdomain Enumeration...", "info");
      
      const dnsPromises = [
        // DNS records
        (async () => {
          const dns = await execCommand(`
            echo "=== A Records ==="
            dig +short ${target} A
            echo "=== MX Records ==="
            dig +short ${target} MX
            echo "=== NS Records ==="
            dig +short ${target} NS
            echo "=== TXT Records ==="
            dig +short ${target} TXT
            echo "=== CNAME Records ==="
            dig +short ${target} CNAME
          `, 60);
          allResults["dns"] = dns.output;
          await execCommand(`echo '${dns.output.replace(/'/g, "'\\''")}' > ${workDir}/dns-records.txt`);
          ctx.ui.notify("✅ DNS records collected", "info");
        })(),

        // Subdomain enumeration (subfinder)
        (async () => {
          const subfinder = await execCommand(
            `subfinder -d ${target} -silent 2>/dev/null | head -100 || echo "subfinder not available"`,
            180
          );
          allResults["subdomains-passive"] = subfinder.output;
          await execCommand(`echo '${subfinder.output.replace(/'/g, "'\\''")}' > ${workDir}/subdomains-passive.txt`);
          ctx.ui.notify("✅ Passive subdomain enumeration complete", "info");
        })(),

        // Certificate transparency
        (async () => {
          const crt = await execCommand(
            `curl -s "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sort -u | head -50 || echo "crt.sh query failed"`,
            60
          );
          allResults["subdomains-crt"] = crt.output;
          await execCommand(`echo '${crt.output.replace(/'/g, "'\\''")}' > ${workDir}/subdomains-crt.txt`);
          ctx.ui.notify("✅ Certificate transparency search complete", "info");
        })(),

        // Common subdomain brute force
        (async () => {
          const bruteforce = await execCommand(`
            for sub in admin api app staging dev test internal grafana kibana jenkins gitlab status docs login auth sso cdn static assets mail smtp vpn portal dashboard billing payments; do
              result=$(dig +short $sub.${target} A 2>/dev/null)
              if [ -n "$result" ]; then
                echo "$sub.${target} -> $result"
              fi
            done
          `, 120);
          allResults["subdomains-brute"] = bruteforce.output;
          await execCommand(`echo '${bruteforce.output.replace(/'/g, "'\\''")}' > ${workDir}/subdomains-brute.txt`);
          ctx.ui.notify("✅ Subdomain brute force complete", "info");
        })(),
      ];

      await Promise.all(dnsPromises);
      state.toolsUsed.push("dig", "subfinder", "crt.sh");

      // Combine subdomains
      await execCommand(`cat ${workDir}/subdomains-*.txt 2>/dev/null | grep -v "not available\|failed" | cut -d' ' -f1 | sort -u > ${workDir}/all-subdomains.txt`);

      // ============================================================
      // PHASE 2: INFRASTRUCTURE FINGERPRINTING (Parallel)
      // ============================================================
      ctx.ui.notify("🏗️ Phase 2: Infrastructure Fingerprinting...", "info");

      const infraPromises = [
        // IP and cloud detection
        (async () => {
          const infra = await execCommand(`
            ip=$(dig +short ${target} A | head -1)
            echo "Primary IP: $ip"
            if [ -n "$ip" ]; then
              echo "Reverse DNS: $(dig +short -x $ip)"
              whois $ip 2>/dev/null | grep -i "orgname\\|netname\\|descr" | head -3
              # Cloud provider detection
              case "$ip" in
                3.*|18.*|34.*|35.*|52.*|54.*|99.*|100.*) echo "Cloud: AWS (IP range)" ;;
                35.*|34.*|104.*|130.*|142.*) echo "Cloud: Possibly GCP" ;;
              esac
            fi
          `, 30);
          allResults["infrastructure"] = infra.output;
          await execCommand(`echo '${infra.output.replace(/'/g, "'\\''")}' > ${workDir}/infrastructure.txt`);
          ctx.ui.notify("✅ Infrastructure fingerprinting complete", "info");
        })(),

        // CDN and headers
        (async () => {
          const headers = await execCommand(`
            curl -sI https://${target} 2>/dev/null | head -30
          `, 30);
          allResults["headers-main"] = headers.output;
          await execCommand(`echo '${headers.output.replace(/'/g, "'\\''")}' > ${workDir}/headers-main.txt`);
          
          // CDN detection
          let cdn = "";
          if (headers.output.toLowerCase().includes("cloudfront") || headers.output.includes("x-amz-cf")) {
            cdn = "CloudFront";
          } else if (headers.output.toLowerCase().includes("cf-ray") || headers.output.toLowerCase().includes("cloudflare")) {
            cdn = "Cloudflare";
          } else if (headers.output.toLowerCase().includes("akamai")) {
            cdn = "Akamai";
          }
          if (cdn) allResults["cdn"] = cdn;
          ctx.ui.notify("✅ Response headers collected", "info");
        })(),

        // S3 bucket enumeration
        (async () => {
          const buckets = await execCommand(`
            domain="${target}"
            base=$(echo $domain | cut -d. -f1)
            for pattern in "$base" "${target//./-}"; do
              for suffix in "" "-assets" "-static" "-uploads" "-backup" "-exports"; do
                bucket="$pattern$suffix"
                code=$(curl -s -o /dev/null -w "%{http_code}" "https://$bucket.s3.amazonaws.com" --connect-timeout 3 2>/dev/null)
                if [ "$code" = "403" ] || [ "$code" = "200" ]; then
                  echo "S3: $bucket ($code)"
                fi
              done
            done
          `, 60);
          allResults["s3-buckets"] = buckets.output;
          await execCommand(`echo '${buckets.output.replace(/'/g, "'\\''")}' > ${workDir}/s3-buckets.txt`);
          ctx.ui.notify("✅ S3 bucket enumeration complete", "info");
        })(),
      ];

      await Promise.all(infraPromises);
      state.toolsUsed.push("whois", "curl");

      // ============================================================
      // PHASE 3: THIRD-PARTY SERVICE DETECTION
      // ============================================================
      ctx.ui.notify("🔌 Phase 3: Third-Party Service Detection...", "info");

      const servicesPromises = [
        // TXT record service detection
        (async () => {
          const txt = allResults["dns"] || "";
          const services: string[] = [];
          if (txt.includes("google-site-verification")) services.push("Google Workspace");
          if (txt.includes("stripe-verification")) services.push("Stripe");
          if (txt.includes("rippling")) services.push("Rippling HR");
          if (txt.includes("hubspot")) services.push("HubSpot");
          if (txt.includes("MS=")) services.push("Microsoft 365");
          if (txt.includes("spf1")) services.push("SPF Configured");
          allResults["services-dns"] = services.join(", ");
        })(),

        // Header-based service detection
        (async () => {
          const headers = allResults["headers-main"] || "";
          const services: string[] = [];
          if (headers.toLowerCase().includes("x-datadog") || headers.toLowerCase().includes("x-dd-")) services.push("Datadog APM");
          if (headers.toLowerCase().includes("x-newrelic")) services.push("New Relic");
          if (headers.toLowerCase().includes("sentry")) services.push("Sentry");
          allResults["services-headers"] = services.join(", ");
        })(),

        // Frontend JS analysis
        (async () => {
          const js = await execCommand(`
            curl -s https://${target} 2>/dev/null > /tmp/homepage.html
            curl -s https://app.${target} 2>/dev/null >> /tmp/homepage.html
            
            # Extract and download JS
            grep -oE 'src="[^"]*.js[^"]*"' /tmp/homepage.html | cut -d'"' -f2 | head -10 > /tmp/js-urls.txt
            
            # Download JS files
            for js in $(cat /tmp/js-urls.txt); do
              if echo "$js" | grep -qE "^/"; then
                curl -s "https://${target}$js" 2>/dev/null
              elif echo "$js" | grep -qE "^http"; then
                curl -s "$js" 2>/dev/null
              fi
            done > /tmp/all-js.txt
            
            # Detect services
            services=""
            grep -qiE "posthog|ph-" /tmp/all-js.txt && services="$services PostHog"
            grep -qiE "intercom|INTERCOM" /tmp/all-js.txt && services="$services Intercom"
            grep -qiE "mixpanel" /tmp/all-js.txt && services="$services Mixpanel"
            grep -qiE "stripe|pk_live_|pk_test_" /tmp/all-js.txt && services="$services Stripe"
            grep -qiE "sentry|SENTRY" /tmp/all-js.txt && services="$services Sentry"
            grep -qiE "auth0|AUTH0" /tmp/all-js.txt && services="$services Auth0"
            grep -qiE "firebase|FIREBASE" /tmp/all-js.txt && services="$services Firebase"
            grep -qiE "supabase|SUPABASE" /tmp/all-js.txt && services="$services Supabase"
            grep -qiE "gtag|GA_" /tmp/all-js.txt && services="$services GoogleAnalytics"
            echo "$services"
          `, 120);
          allResults["services-js"] = js.output;
          ctx.ui.notify("✅ Frontend JS analysis complete", "info");
        })(),

        // Auth0/OIDC discovery
        (async () => {
          const oidc = await execCommand(`
            for host in login.${target} auth.${target} sso.${target}; do
              result=$(curl -s "https://$host/.well-known/openid-configuration" --connect-timeout 5 2>/dev/null)
              if echo "$result" | grep -q "issuer"; then
                echo "OIDC discovered at $host"
                echo "$result" | jq -r '.authorization_endpoint, .token_endpoint' 2>/dev/null
              fi
            done
          `, 30);
          allResults["oidc"] = oidc.output;
          if (oidc.output.includes("OIDC discovered")) {
            ctx.ui.notify("✅ OIDC configuration discovered", "info");
          }
        })(),
      ];

      await Promise.all(servicesPromises);

      // ============================================================
      // PHASE 4: API ENDPOINT DISCOVERY
      // ============================================================
      ctx.ui.notify("🔍 Phase 4: API Endpoint Discovery...", "info");

      const endpointPromises = [
        // Common endpoint brute force
        (async () => {
          const endpoints = await execCommand(`
            for endpoint in /api /api/v1 /api/v2 /graphql /swagger /docs /openapi.json /users /users/ /user /auth /login /admin /admin/ /health /status /metrics /.well-known/openid-configuration; do
              code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.${target}$endpoint" --connect-timeout 3 2>/dev/null)
              [ "$code" != "000" ] && [ "$code" != "404" ] && echo "$endpoint -> $code"
            done
          `, 120);
          allResults["endpoints-api"] = endpoints.output;
          await execCommand(`echo '${endpoints.output.replace(/'/g, "'\\''")}' > ${workDir}/endpoints-api.txt`);
          ctx.ui.notify("✅ API endpoint discovery complete", "info");
        })(),

        // User dashboard / admin endpoints (Terrain-specific)
        (async () => {
          const dashboard = await execCommand(`
            for endpoint in /user_dashboard/users /user_dashboard/users/ /user_dashboard/logs /user_dashboard/logs/ /user_dashboard/usage /user_dashboard/rotate_token /user_dashboard/notification_emails /tenants/payments/purchase /tenants/payments/purchases /tenants/payments/packages /tenants/slack/webhook /internal /internal/users /authentication/userinfo; do
              code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.${target}$endpoint" --connect-timeout 3 2>/dev/null)
              [ "$code" != "000" ] && echo "$endpoint -> $code"
            done
          `, 120);
          allResults["endpoints-dashboard"] = dashboard.output;
          await execCommand(`echo '${dashboard.output.replace(/'/g, "'\\''")}' > ${workDir}/endpoints-dashboard.txt`);
          ctx.ui.notify("✅ Dashboard endpoint discovery complete", "info");
        })(),
      ];

      await Promise.all(endpointPromises);

      // ============================================================
      // PHASE 5: CORS TESTING
      // ============================================================
      ctx.ui.notify("🌐 Phase 5: CORS Testing...", "info");

      const cors = await execCommand(`
        for origin in "https://evil.com" "null" "http://localhost"; do
          echo "Testing origin: $origin"
          response=$(curl -sI "https://api.${target}" -H "Origin: $origin" 2>/dev/null)
          acao=$(echo "$response" | grep -i "access-control-allow-origin")
          acac=$(echo "$response" | grep -i "access-control-allow-credentials")
          [ -n "$acao" ] && echo "  ACAO: $acao"
          [ -n "$acac" ] && echo "  ACAC: $acac"
          if echo "$acao" | grep -qi "$origin"; then
            if echo "$acac" | grep -qi "true"; then
              echo "  ⚠️ CRITICAL: Origin reflected with credentials!"
            else
              echo "  ⚠️ Origin reflected (no credentials)"
            fi
          fi
        done
      `, 60);
      allResults["cors"] = cors.output;
      await execCommand(`echo '${cors.output.replace(/'/g, "'\\''")}' > ${workDir}/cors-test.txt`);
      state.toolsUsed.push("cors-test");
      ctx.ui.notify("✅ CORS testing complete", "info");

      // ============================================================
      // PHASE 6: SECURITY HEADERS
      // ============================================================
      ctx.ui.notify("🔒 Phase 6: Security Header Analysis...", "info");

      const secHeaders = await execCommand(`
        echo "=== Security Headers Check ==="
        headers=$(curl -sI "https://${target}" 2>/dev/null)
        
        echo "$headers" | grep -qi "strict-transport-security" && echo "✓ HSTS present" || echo "✗ Missing: HSTS"
        echo "$headers" | grep -qi "x-frame-options" && echo "✓ X-Frame-Options present" || echo "✗ Missing: X-Frame-Options"
        echo "$headers" | grep -qi "content-security-policy" && echo "✓ CSP present" || echo "✗ Missing: CSP"
        echo "$headers" | grep -qi "x-content-type-options" && echo "✓ X-Content-Type-Options present" || echo "✗ Missing: X-Content-Type-Options"
        
        echo ""
        echo "=== Information Leaks ==="
        echo "$headers" | grep -iE "x-datadog|x-dd-|x-trace|x-request-id|x-powered-by|server:" | head -10
      `, 30);
      allResults["security-headers"] = secHeaders.output;
      await execCommand(`echo '${secHeaders.output.replace(/'/g, "'\\''")}' > ${workDir}/security-headers.txt`);
      ctx.ui.notify("✅ Security header analysis complete", "info");

      // ============================================================
      // STORE ALL RESULTS
      // ============================================================
      state.scanResults = allResults;
      pi.appendEntry("redteam-state", state);

      // Calculate duration
      const duration = Math.round((Date.now() - state.startTime) / 60000);

      ctx.ui.notify(`✅ Full assessment complete in ${duration} minutes.`, "info");
      ctx.ui.notify(`Results saved to ${workDir}/`, "info");

      // ============================================================
      // SEND TO LLM FOR ANALYSIS
      // ============================================================
      const summaryParts = [];

      if (allResults["dns"]) {
        summaryParts.push(`## DNS Records\n\`\`\`\n${truncateOutput(allResults["dns"], 30)}\n\`\`\``);
      }

      // Combine subdomains
      const subdomains = [
        allResults["subdomains-passive"],
        allResults["subdomains-crt"],
        allResults["subdomains-brute"]
      ].filter(Boolean).join("\n");
      if (subdomains) {
        summaryParts.push(`## Subdomains Discovered\n\`\`\`\n${truncateOutput(subdomains, 40)}\n\`\`\``);
      }

      if (allResults["infrastructure"]) {
        summaryParts.push(`## Infrastructure\n\`\`\`\n${truncateOutput(allResults["infrastructure"], 20)}\n\`\`\``);
      }

      if (allResults["s3-buckets"]) {
        summaryParts.push(`## S3 Buckets\n\`\`\`\n${allResults["s3-buckets"]}\n\`\`\``);
      }

      // Third-party services
      const services = [
        allResults["services-dns"],
        allResults["services-headers"],
        allResults["services-js"]
      ].filter(Boolean).join(", ");
      if (services) {
        summaryParts.push(`## Third-Party Services\n${services}`);
      }

      if (allResults["oidc"]) {
        summaryParts.push(`## OIDC/OAuth Discovery\n\`\`\`\n${allResults["oidc"]}\n\`\`\``);
      }

      if (allResults["endpoints-api"]) {
        summaryParts.push(`## API Endpoints\n\`\`\`\n${truncateOutput(allResults["endpoints-api"], 30)}\n\`\`\``);
      }

      if (allResults["endpoints-dashboard"]) {
        summaryParts.push(`## Dashboard/Admin Endpoints\n\`\`\`\n${truncateOutput(allResults["endpoints-dashboard"], 30)}\n\`\`\``);
      }

      if (allResults["cors"]) {
        summaryParts.push(`## CORS Testing\n\`\`\`\n${truncateOutput(allResults["cors"], 30)}\n\`\`\``);
      }

      if (allResults["security-headers"]) {
        summaryParts.push(`## Security Headers\n\`\`\`\n${truncateOutput(allResults["security-headers"], 20)}\n\`\`\``);
      }

      pi.sendUserMessage(
        `## 🎯 Terrain-Style Security Assessment - ${target}

**Duration:** ${duration} minutes
**Output Directory:** ${workDir}

${summaryParts.join("\n\n")}

---

## Analysis Tasks:

1. **Create Surface Area Table**: List all discovered hosts, their purpose, and how they were found
2. **Document Infrastructure**: Cloud provider, CDN, compute platform, storage
3. **List Third-Party Services**: All detected services with their exposure level
4. **Identify Critical Findings**: Use \`record_finding\` for each vulnerability
5. **Check for CORS Issues**: If origin is reflected with credentials, this is CRITICAL
6. **Note Missing Security Headers**: Each missing header is a finding
7. **Analyze Accessible Endpoints**: Any 200 responses on dashboard/admin endpoints are concerning
8. **Generate Terrain-Style Report**: Executive summary, surface area, test results, findings

Be thorough - match the quality of a professional security assessment report.`,
        { deliverAs: "followUp" }
      );
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
      `, 30);

      ctx.ui.notify("✅ Tool check complete.", "info");

      pi.sendUserMessage(
        `## Red Team Tool Availability\n\n${check.output}\n\n**To install missing tools:**\n\`\`\`bash\n# Arch Linux\nyay -S subfinder httpx nuclei nmap nikto gobuster sqlmap hydra\n\n# Debian/Ubuntu/Kali\nsudo apt install nmap nikto gobuster sqlmap hydra\ngo install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\ngo install github.com/projectdiscovery/httpx/cmd/httpx@latest\ngo install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\`\`\``,
        { deliverAs: "followUp" }
      );
    },
  });
}
