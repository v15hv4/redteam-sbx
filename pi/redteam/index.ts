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
  // PARALLEL REDTEAM - DIRECT EXECUTION
  // ============================================================

  pi.registerCommand("redteam", {
    description: "🚀 Full Red Team - Parallel execution of all scans",
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
}
