# vuln-SSRF-Fuzzer
A command-line tool that takes a URL as input and fuzzes potential Server-Side Request Forgery (SSRF) parameters within the URL or request body. It attempts to elicit responses from internal IP addresses to identify SSRF vulnerabilities. The full default payload list is: http://127.0.0.1, http://localhost, http://169.254.169.254, http://metadata.google.internal, and http://0.0.0.0. No external payload is sent by default: http://example.com is sent only when the operator passes --include-external, and an operator supplied list passed with -P replaces the default set. Each run fetches an unmodified baseline first and prints a summary of requests sent, completed, and failed when it ends. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-ssrf-fuzzer`

## Usage
`./vuln-ssrf-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: List of parameters to fuzz in the URL. If not provided, fuzz all query parameters.
- `-d`: Request body data to fuzz, with a PAYLOAD marker where the payload goes.
- `-H`: Custom headers to include in the request, honored in both modes (e.g., 
- `-m`: HTTP method to use (default: GET). Honored in both URL parameter and body modes.
- `-t`: Request timeout in seconds (default: 5).
- `-v`: Enable verbose output (debug logging).

- `-P`: Operator supplied payload list to use instead of the default set.
- `--include-external`: Also send the external payload http://example.com. Off by default.

## License
Copyright (c) ShadowStrikeHQ
