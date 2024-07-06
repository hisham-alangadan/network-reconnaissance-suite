import sys
import ssl
import socket


def check_clickjacking_vulnerability(headers):
    if "x-frame-options" not in headers or (
        headers["x-frame-options"] != "DENY"
        and headers["x-frame-options"] != "SAMEORIGIN"
    ):
        return {
            "name": "Clickjacking",
            "description": "Missing or misconfigured X-Frame-Options header.",
            "risk": "Medium",
            "evidence": "X-Frame-Options header is not set to DENY or SAMEORIGIN.",
        }
    return {
        "name": "Clickjacking",
        "description": "No Clickjacking vulnerability detected.",
        "risk": "None",
        "evidence": "X-Frame-Options header is properly configured.",
    }


def check_insecure_mixed_content(headers):
    if (
        "content-security-policy" in headers
        and "block-all-mixed-content" not in headers["content-security-policy"]
    ):
        return {
            "name": "Insecure Mixed Content",
            "description": "Missing or misconfigured Content-Security-Policy header to block all mixed content.",
            "risk": "Medium",
            "evidence": "Content-Security-Policy header does not contain block-all-mixed-content directive.",
        }
    return {
        "name": "Insecure Mixed Content",
        "description": "No Insecure Mixed Content vulnerability detected.",
        "risk": "None",
        "evidence": "Content-Security-Policy header is properly configured.",
    }


def check_cors_vulnerability(headers):
    if (
        "access-control-allow-origin" in headers
        and headers["access-control-allow-origin"] != "*"
    ):
        return {
            "name": "CORS",
            "description": "Potentially misconfigured Access-Control-Allow-Origin header.",
            "risk": "Medium",
            "evidence": "Access-Control-Allow-Origin header is set to a specific domain instead of wildcard.",
        }
    return {
        "name": "CORS",
        "description": "No CORS vulnerability detected.",
        "risk": "None",
        "evidence": "Access-Control-Allow-Origin header is properly configured.",
    }


def check_hsts_vulnerability(headers):
    if (
        "strict-transport-security" not in headers
        or "includeSubDomains" not in headers["strict-transport-security"]
    ):
        return {
            "name": "HSTS",
            "description": "Missing or misconfigured Strict-Transport-Security header with includeSubDomains directive.",
            "risk": "High",
            "evidence": "Strict-Transport-Security header does not include includeSubDomains directive.",
        }
    return {
        "name": "HSTS",
        "description": "No HSTS vulnerability detected.",
        "risk": "None",
        "evidence": "Strict-Transport-Security header is properly configured.",
    }


def check_reflected_xss_vulnerability(headers):
    if (
        "x-xss-protection" not in headers
        or headers["x-xss-protection"] != "1; mode=block"
    ):
        return {
            "name": "Reflected XSS",
            "description": "Missing or misconfigured X-XSS-Protection header.",
            "risk": "High",
            "evidence": "X-XSS-Protection header is not set to 1; mode=block.",
        }
    return {
        "name": "Reflected XSS",
        "description": "No Reflected XSS vulnerability detected.",
        "risk": "None",
        "evidence": "X-XSS-Protection header is properly configured.",
    }


def check_server_info_vulnerability(headers):
    if "server" in headers or "x-powered-by" in headers or "via" in headers:
        return {
            "name": "Server Information Leakage",
            "description": "Presence of Server, X-Powered-By, or Via headers.",
            "risk": "Low",
            "evidence": "Server, X-Powered-By, or Via headers are present in the response.",
        }
    return {
        "name": "Server Information Leakage",
        "description": "No Server Information Leakage vulnerability detected.",
        "risk": "None",
        "evidence": "Server, X-Powered-By, and Via headers are not present in the response.",
    }


def check_xss_vulnerability(headers):
    if "content-security-policy" in headers:
        csp_header = headers["content-security-policy"]
        if "script-src" not in csp_header:
            return {
                "name": "Cross-site Scripting (XSS)",
                "description": "Missing or misconfigured Content-Security-Policy header for script-src.",
                "risk": "High",
                "evidence": "Content-Security-Policy header does not contain script-src directive.",
            }
    return {
        "name": "Cross-site Scripting (XSS)",
        "description": "No XSS vulnerability detected.",
        "risk": "None",
        "evidence": "Content-Security-Policy header is properly configured.",
    }


def check_cache_control_vulnerability(headers):
    if "cache-control" not in headers or (
        "no-store" not in headers["cache-control"]
        and "no-cache" not in headers["cache-control"]
    ):
        return {
            "name": "Cache Control",
            "description": "Missing or misconfigured Cache-Control header with no-store or no-cache directives.",
            "risk": "Medium",
            "evidence": "Cache-Control header does not include no-store or no-cache directives.",
        }
    return {
        "name": "Cache Control",
        "description": "No Cache Control vulnerability detected.",
        "risk": "None",
        "evidence": "Cache-Control header is properly configured.",
    }


def check_cache_poisoning_vulnerability(headers):
    if "cache-control" in headers and "public" in headers["cache-control"]:
        return {
            "name": "Cache Poisoning",
            "description": "Potentially misconfigured Cache-Control header allowing public caching.",
            "risk": "High",
            "evidence": 'Cache-Control header includes "public" directive.',
        }
    return {
        "name": "Cache Poisoning",
        "description": "No Cache Poisoning vulnerability detected.",
        "risk": "None",
        "evidence": "Cache-Control header is properly configured.",
    }


def ssl_certificate_check(host, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "Issuer": cert.get("issuer"),
                    "Subject": cert.get("subject"),
                    "Expiry Date": cert.get("notAfter"),
                }
    except Exception as e:
        return {
            "Issuer": "N/A",
            "Subject": "N/A",
            "Expiry Date": "N/A",
        }
