#!/usr/bin/env python3
import argparse
import logging
import requests
import sys
import urllib.parse
from typing import List, Dict, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default SSRF payloads: loopback and internal metadata destinations only.
# These are the stated purpose of an SSRF fuzzer and are listed in full in
# the README. Nothing outside loopback and internal shapes is in the
# default set: reaching an external host requires the operator to name it,
# either with --payloads or with --include-external.
SSRF_PAYLOADS: List[str] = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",  # AWS Metadata
    "http://metadata.google.internal", # GCP Metadata
    "http://0.0.0.0"
]

# External payloads, sent only when the operator passes --include-external.
EXTERNAL_PAYLOADS: List[str] = [
    "http://example.com"
]

# Body substrings treated as possible SSRF evidence only when they appear
# in a fuzzed response and were absent from the baseline response.
SSRF_MARKERS = ["Example Domain", "127.0.0.1"]


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the vuln-SSRF-Fuzzer tool.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="SSRF Fuzzer - Detect Server-Side Request Forgery vulnerabilities.")
    parser.add_argument("url", help="The target URL to fuzz.")
    parser.add_argument("-p", "--params", nargs='+', help="List of parameters to fuzz in the URL. If not provided, fuzz all query parameters.")
    parser.add_argument("-d", "--data", help="Request body data (e.g., JSON or form data) to fuzz.  Specify a parameter to fuzz with the PAYLOAD marker, e.g., '{\"param1\": \"PAYLOAD\", \"param2\": \"value2\"}'")
    parser.add_argument("-H", "--headers", nargs='+', help="Custom headers to include in the request (e.g., 'Content-Type: application/json').")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method to use (default: GET).")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout in seconds (default: 5).")
    parser.add_argument("-P", "--payloads", nargs='+', default=None, help="Operator supplied payload list to use instead of the default set.")
    parser.add_argument("--include-external", action="store_true", help="Also send the external payload set (http://example.com). Off by default: external destinations are sent only when the operator names them.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser


def analyze_response(response, baseline_text) -> int:
    """
    Analyze one received response. Error responses are analyzed like any
    other response, since they carry SSRF evidence. A body marker counts
    only when it was absent from the baseline response, so a page that
    merely contains the marker text is not a finding.

    Returns:
        int: The number of indicator warnings raised for this response.
    """
    indicators = 0
    if response.status_code != 200:
        logging.warning(f"Non-200 status code received.  Possible SSRF Indicator. Status Code: {response.status_code}")
        indicators += 1
    for marker in SSRF_MARKERS:
        # The nested test makes the outer one stricter than it reads: with
        # no baseline, a marker passes the outer condition and then counts
        # for nothing, because the inner branch requires a baseline. Only
        # the non 200 warning above can fire on a baseline free run.
        if marker in response.text and (baseline_text is None or marker not in baseline_text):
            if baseline_text is not None:
                logging.warning(f"{marker} found in the fuzzed response but not in the baseline. Possible SSRF Indicator.")
                indicators += 1
    return indicators


def fetch_baseline_url(url, method, headers, timeout):
    """Fetch the unmodified target URL as the baseline. Returns body text or None."""
    try:
        response = requests.request(method, url, headers=headers, timeout=timeout)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.warning(f"Baseline request failed: {e}. Marker findings require a baseline and will not be reported.")
        return None


def fuzz_url_params(url: str, params_to_fuzz: List[str] = None, timeout: int = 5,
                    method: str = "GET", headers: Dict[str, str] = None,
                    payloads: List[str] = None) -> Tuple[int, int, int]:
    """
    Fuzzes URL parameters with SSRF payloads, honoring the method and
    headers the operator supplied.

    Returns:
        tuple: (sent, completed, indicators) counts for the run summary.
    """
    if payloads is None:
        payloads = SSRF_PAYLOADS
    sent = completed = indicators = 0
    parsed_url = urllib.parse.urlparse(url)
    # parse_qs drops blank values, as in the other scanners: a parameter
    # written ?next= with nothing after it cannot be fuzzed from the URL
    # mode, and naming it with -p filters it out as not found.
    query_params = urllib.parse.parse_qs(parsed_url.query)

    if not query_params:
        logging.info("No query parameters found in the URL.")
        return sent, completed, indicators

    if params_to_fuzz:
        params_to_fuzz = [param.strip() for param in params_to_fuzz]
        params_to_fuzz = [param for param in params_to_fuzz if param in query_params]
        if not params_to_fuzz:
            logging.warning("Specified parameters not found in URL. Exiting.")
            return sent, completed, indicators
    else:
        params_to_fuzz = list(query_params.keys())  # Fuzz all if none provided.

    baseline_text = fetch_baseline_url(url, method, headers, timeout)

    for param in params_to_fuzz:
        for payload in payloads:
            fuzzed_query_params = query_params.copy()
            fuzzed_query_params[param] = [payload]
            encoded_query_string = urllib.parse.urlencode(fuzzed_query_params, doseq=True)
            fuzzed_url = parsed_url._replace(query=encoded_query_string).geturl()

            logging.info(f"Fuzzing URL: {fuzzed_url}")
            sent += 1
            try:
                # No raise_for_status: error responses are analyzed too.
                response = requests.request(method, fuzzed_url, headers=headers, timeout=timeout)
                completed += 1
                logging.info(f"Response Status Code: {response.status_code}")
                indicators += analyze_response(response, baseline_text)
            except requests.exceptions.RequestException as e:
                logging.error(f"Request failed: {e}")
    return sent, completed, indicators


def fuzz_request_body(url: str, data: str, method: str = "POST", headers: Dict[str, str] = None,
                      timeout: int = 5, payloads: List[str] = None) -> Tuple[int, int, int]:
    """
    Fuzzes the request body with SSRF payloads.  Looks for the "PAYLOAD" marker.
    The fuzzed data is sent as the request body for both GET and POST.

    Returns:
        tuple: (sent, completed, indicators) counts for the run summary.
    """
    if payloads is None:
        payloads = SSRF_PAYLOADS
    sent = completed = indicators = 0
    if "PAYLOAD" not in data:
        logging.error("The request body does not contain the 'PAYLOAD' marker. Exiting.")
        return sent, completed, indicators

    # The body baseline sends the data with the PAYLOAD word still in it.
    # If the server echoes that request body, the literal marker text is
    # what later responses are compared against, not a clean page.
    baseline_text = None
    try:
        baseline = requests.request(method, url, data=data, headers=headers, timeout=timeout)
        baseline_text = baseline.text
    except requests.exceptions.RequestException as e:
        logging.warning(f"Baseline request failed: {e}. Marker findings require a baseline and will not be reported.")

    for payload in payloads:
        # replace() takes every occurrence, so a body that uses PAYLOAD
        # twice, once as a decoy, sends the payload in both places.
        fuzzed_data = data.replace("PAYLOAD", payload)
        logging.info(f"Fuzzing data: {fuzzed_data}")
        sent += 1
        try:
            response = requests.request(method, url, data=fuzzed_data, headers=headers, timeout=timeout)
            completed += 1
            logging.info(f"Response Status Code: {response.status_code}")
            indicators += analyze_response(response, baseline_text)
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
        except Exception as e:
            logging.error(f"An error occurred while fuzzing the request body: {e}")
    return sent, completed, indicators


def parse_headers(headers: List[str]) -> Dict[str, str]:
    """Parses a list of header strings into a dictionary.

    Args:
        headers (List[str]): A list of header strings in the format "Header-Name: Header-Value".

    Returns:
        Dict[str, str]: A dictionary of headers.
    """
    header_dict = {}
    if headers:
        for header in headers:
            try:
                name, value = header.split(":", 1)
                header_dict[name.strip()] = value.strip()
            except ValueError:
                logging.error(f"Invalid header format: {header}. Expected 'Header-Name: Header-Value'. Ignoring.")
    return header_dict


def main():
    """
    Main function of the vuln-SSRF-Fuzzer tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.url.lower().startswith(("http://", "https://")):
        logging.error("Invalid input: URL must start with http:// or https://")
        sys.exit(1)

    if args.timeout <= 0:
        logging.error("Invalid input: --timeout must be greater than 0.")
        sys.exit(1)

    logging.debug(f"Arguments: {args}")

    if args.payloads:
        payloads = list(args.payloads)
    else:
        payloads = list(SSRF_PAYLOADS)
    if args.include_external:
        payloads += EXTERNAL_PAYLOADS

    headers = parse_headers(args.headers) if args.headers else None

    try:
        if args.data:
            sent, completed, indicators = fuzz_request_body(
                args.url, args.data, args.method, headers, args.timeout, payloads)
        else:
            sent, completed, indicators = fuzz_url_params(
                args.url, args.params, args.timeout, args.method, headers, payloads)
    except Exception as e:
        logging.error(f"An unhandled error occurred: {e}")
        sys.exit(1)

    failed = sent - completed
    logging.info(f"Summary: requests sent: {sent}, completed: {completed}, failed: {failed}, indicators: {indicators}")
    if completed == 0:
        logging.error("No fuzz request completed. The run is inconclusive.")
        sys.exit(1)


if __name__ == "__main__":
    main()
