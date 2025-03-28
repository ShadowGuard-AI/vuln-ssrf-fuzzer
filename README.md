# vuln-SSRF-Fuzzer
A command-line tool that takes a URL as input and fuzzes potential Server-Side Request Forgery (SSRF) parameters within the URL or request body. It attempts to elicit responses from internal IP addresses or blocked external sites to identify SSRF vulnerabilities. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-ssrf-fuzzer`

## Usage
`./vuln-ssrf-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: List of parameters to fuzz in the URL. If not provided, fuzz all query parameters.
- `-d`: No description provided
- `-H`: Custom headers to include in the request (e.g., 
- `-m`: No description provided
- `-t`: No description provided
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ
