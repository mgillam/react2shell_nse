local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Detects CVE-2025-55182 and CVE-2025-66478 (React2Shell) vulnerabilities in 
React Server Components (RSC) and Next.js applications.

These vulnerabilities allow remote code execution through prototype pollution 
in the server action handling. This script uses a safe side-channel detection 
method that does not execute arbitrary code on the target.

References:
* https://nvd.nist.gov/vuln/detail/CVE-2025-55182
* https://nvd.nist.gov/vuln/detail/CVE-2025-66478
]]

author = "By Mic Whitehorn (mgillam), Based on Python PoC by liyander (CyberGhost05)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = function(host, port)
  return port.state == "open"
end


local function build_safe_payload()
  local boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
  local body = 
    "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" ..
    'Content-Disposition: form-data; name="1"\r\n\r\n' ..
    "{}\r\n" ..
    "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" ..
    'Content-Disposition: form-data; name="0"\r\n\r\n' ..
    '["$1:aa:aa"]\r\n' ..
    "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
  local content_type = "multipart/form-data; boundary=" .. boundary
  return body, content_type
end

local function is_vulnerable(response)
  if response.status ~= 500 then
    return false
  end
  if not response.body or not string.find(response.body, 'E{"digest"', 1, true) then
    return false
  end
  local server_header = response.header["server"] or ""
  server_header = string.lower(server_header)
  local has_netlify_vary = response.header["netlify-vary"] ~= nil
  local is_mitigated = has_netlify_vary or 
                       server_header == "netlify" or 
                       server_header == "vercel"
  return not is_mitigated
end

local function test_path(host, port, path, timeout)
  local body, content_type = build_safe_payload()
  local options = {
    header = {
      ["User-Agent"] = "Mozilla/5.0 (compatible; Nmap Scripting Engine; +https://nmap.org/book/nse.html)",
      ["Next-Action"] = "x",
      ["X-Nextjs-Request-Id"] = "b5dce965",
      ["Content-Type"] = content_type,
      ["X-Nextjs-Html-Request-Id"] = "SSTMXm7OJ_g0Ncx6jpQt9",
    },
    timeout = timeout * 1000,
    redirect_ok = false
  }
  stdnse.debug1("Testing path: %s", path)
  local response = http.post(host, port, path, options, nil, body)
  if not response then
    return false, "Request failed"
  end
  if is_vulnerable(response) then
    return true, "Vulnerable (status: " .. response.status .. ")"
  end
  return false, "Not vulnerable (status: " .. (response.status or "unknown") .. ")"
end

action = function(host, port)
  local timeout = 10
  local verbose = stdnse.get_script_args("detect_react2shell.verbose")
  local vuln_table = {
    title = "React2Shell RCE (CVE-2025-55182, CVE-2025-66478)",
    IDS = {
      CVE = "CVE-2025-55182",
      CVE = "CVE-2025-66478"
    },
    risk_factor = "Critical",
    scores = {
      CVSSv3 = "9.8 (CRITICAL) AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    description = [[
React Server Components and Next.js applications are vulnerable to remote
code execution through prototype pollution in server action handling.
The vulnerability allows attackers to execute arbitrary code on the server
by manipulating prototype chains in multipart form data.]],
    references = {
      'https://nvd.nist.gov/vuln/detail/CVE-2025-55182',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-66478'
    },
    dates = {
      disclosure = {year = '2025', month = '01', day = '15'}
    }
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vulnerable, status = test_path(host, port, "/", timeout)
  stdnse.debug1("Root path result: %s - %s", tostring(vulnerable), status)
  if vulnerable then
    vuln_table.state = vulns.STATE.VULN
    vuln_table.extra_info = "Tested path: /"
    local output = vuln_report:make_output(vuln_table)
    return output or "VULNERABLE: React2Shell detected!"
  elseif verbose then
    vuln_table.state = vulns.STATE.NOT_VULN
    vuln_table.check_results = status
    local output = vuln_report:make_output(vuln_table)
    return output or ("Not vulnerable: " .. status)
  else
    return nil -- suppress output for non-vulnerable hosts
  end
end