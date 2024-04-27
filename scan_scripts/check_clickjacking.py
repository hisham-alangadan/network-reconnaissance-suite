import sys

def check_clickjacking_vulnerability(headers):
    if 'x-frame-options' not in headers or (headers['x-frame-options'] != 'DENY' and headers['x-frame-options'] != 'SAMEORIGIN'):
        return {
            'name': 'Clickjacking',
            'description': 'Missing or misconfigured X-Frame-Options header.',
            'risk': 'Medium',
            'evidence': 'X-Frame-Options header is not set to DENY or SAMEORIGIN.'
        }
    return {
        'name': 'Clickjacking',
        'description': 'No Clickjacking vulnerability detected.',
        'risk': 'None',
        'evidence': 'X-Frame-Options header is properly configured.'
    }

if __name__ == "__main__":
    headers = sys.argv[1]
    # Check for clickjacking vulnerability
    vulnerability = check_clickjacking_vulnerability(headers)
    
    # Print the result
    if vulnerability:
        print("\n")
        print("Clickjacking Vulnerability Detection Status:")
        print(f"Name: {vulnerability['name']}")
        print(f"Description: {vulnerability['description']}")
        print(f"Risk: {vulnerability['risk']}")
        print(f"Evidence: {vulnerability['evidence']}")
        
