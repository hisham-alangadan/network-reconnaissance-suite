import sys

def check_insecure_mixed_content(headers):
    if 'content-security-policy' in headers and 'block-all-mixed-content' not in headers['content-security-policy']:
        return {
            'name': 'Insecure Mixed Content',
            'description': 'Missing or misconfigured Content-Security-Policy header to block all mixed content.',
            'risk': 'Medium',
            'evidence': 'Content-Security-Policy header does not contain block-all-mixed-content directive.'
        }
    return {
        'name': 'Insecure Mixed Content',
        'description': 'No Insecure Mixed Content vulnerability detected.',
        'risk': 'None',
        'evidence': 'Content-Security-Policy header is properly configured.'
    }

if __name__ == "__main__":
    # This part can be used for testing the function independently
    headers = sys.argv[1]
    vulnerability = check_insecure_mixed_content(headers)
    if vulnerability:
        print("\n")
        print("Insecure Mixed Content Vulnerability Detection Status:")
        print(f"Name: {vulnerability['name']}")
        print(f"Description: {vulnerability['description']}")
        print(f"Risk: {vulnerability['risk']}")
        print(f"Evidence: {vulnerability['evidence']}")