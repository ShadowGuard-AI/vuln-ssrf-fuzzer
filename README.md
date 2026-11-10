# vuln-SSRF-Fuzzer
A command-line tool that takes a URL as input and fuzzes potential Server-Side Request Forgery (SSRF) parameters within the URL or request body. It attempts to elicit responses from internal IP addresses to identify SSRF vulnerabilities. The full default payload list is: http://127.0.0.1, http://localhost, http://169.254.169.254, http://metadata.google.internal, and http://0.0.0.0. No external payload is sent by default: http://example.com is sent only when the operator passes --include-external, and an operator supplied list passed with -P replaces the default set. Each run fetches an unmodified baseline first and prints a summary of requests sent, completed, and failed when it ends. The target URL must start with http:// or https://, and the tool exits with status 1 when no fuzz request completed.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-ssrf-fuzzer`

Then install the dependencies: `pip install -r requirements.txt`

## Usage
`python main.py <url> [options]`

## Parameters
- `url`: The target URL to fuzz (positional, required).
- `-h`: Show help message and exit
- `-p`: List of parameters to fuzz in the URL. If not provided, fuzz all query parameters.
- `-d`: Request body data to fuzz, with a PAYLOAD marker where the payload goes.
- `-H`: Custom headers to include in the request, honored in both modes (e.g., 'Content-Type: application/json').
- `-m`: HTTP method to use (default: GET). Honored in both URL parameter and body modes.
- `-t`: Request timeout in seconds (default: 5). Must be greater than 0.
- `-v`: Enable verbose output (debug logging).
- `-P`: Operator supplied payload list to use instead of the default set.
- `--include-external`: Also send the external payload http://example.com. Off by default.

## License
MIT License. See the LICENSE file for the full text.
