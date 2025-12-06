import { spawnSync } from "child_process";
import { dirname, join } from "path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";

// Get the root directory of the workspace
const rootDir = join(dirname(dirname(import.meta.path)), "..", "..");
const expectedResultsPath = join(rootDir, "test", "expectedResults.json");
const reportPath = join(rootDir, "TEST_REPORT.md");

const expectedResults = JSON.parse(readFileSync(expectedResultsPath, "utf-8"));

type ScanResult = {
  port: string;
  label: string;
  expect_vuln: boolean;
  nmap_output: string;
  detected_vuln: boolean;
  listening: boolean;
  app_path: string;
};


function parseListening(nmapOutput: string, port: string): boolean {
  // Look for a line like '3000/tcp open'
  const regex = new RegExp(`^${port}/tcp\\s+open`, 'm');
  return regex.test(nmapOutput);
}


function runNmap(port: string): string {
  const result = spawnSync("nmap", [
    "-v",
    "--script",
    join(rootDir, "nse", "detect_react2shell.nse"),
    "-p",
    port,
    "localhost",
  ]);
  const stdout = result.stdout.toString();
  const stderr = result.stderr ? result.stderr.toString() : "";
  if (result.status !== 0) {
    console.error(`nmap scan on port ${port} failed with status ${result.status}`);
    if (stderr) console.error(`stderr: ${stderr}`);
  }
  // Debug output for every scan
  console.log(`nmap stdout for port ${port}:
${stdout}`);
  if (stderr) console.log(`nmap stderr for port ${port}:
${stderr}`);
  return stdout;
}

function parseVuln(nmapOutput: string): boolean {
  return nmapOutput.includes("VULNERABLE") || nmapOutput.includes("React2Shell");
}

const results: ScanResult[] = [];

for (const port of Object.keys(expectedResults)) {
  const { label, expect_vuln, path: app_path } = expectedResults[port];
  // Placeholder: Start app if needed (could use spawnSync for pnpm or npm)
  // For now, assume apps are running
  const nmap_output = runNmap(port);
  const listening = parseListening(nmap_output, port);
  const detected_vuln = parseVuln(nmap_output);
  results.push({ port, label, expect_vuln, nmap_output, detected_vuln, listening, app_path });
}

function generateMarkdownReport(results: ScanResult[]): string {
  let md = `# React2Shell NSE Test Report\n\n`;
  md += `| Port | App | Expected Vulnerable | Detected Vulnerable | Listening |\n`;
  md += `|------|-----|--------------------|--------------------|-----------|\n`;
  for (const r of results) {
    md += `| ${r.port} | ${r.label} | ${r.expect_vuln ? "✅" : "❌"} | ${r.detected_vuln ? "✅" : "❌"} | ${r.listening ? "✅" : "❌"} |\n`;
  }
  md += `\n## Detailed Nmap Output\n`;
  for (const r of results) {
    md += `\n### Port ${r.port} (${r.label})\n\n`;
    md += "```\n" + r.nmap_output + "\n```\n";
  }
  return md;
}

const report = generateMarkdownReport(results);
writeFileSync(reportPath, report);
console.log(`Test report written to ${reportPath}`);