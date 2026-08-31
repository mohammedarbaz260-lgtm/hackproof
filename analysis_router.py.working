
import re

from security_analysis import (
    analyze_ip,
    analyze_domain,
    analyze_subdomain,
    analyze_url,
    analyze_port,
    analyze_log,
    analyze_threat
)

def handle_analysis_request(question):
    q = question.strip()

    match = re.match(r"^analyze\s+ip\s+(.+)$", q, re.I)
    if match:
        return analyze_ip(match.group(1))

    match = re.match(r"^analyze\s+domain\s+(.+)$", q, re.I)
    if match:
        return analyze_domain(match.group(1))

    if q.lower().startswith("analyze subdomain "):
        return analyze_subdomain(q[len("analyze subdomain "):].strip())

    if q.lower().startswith("analyze url "):
        return analyze_url(q[len("analyze url "):].strip())

    match = re.match(r"^analyze\s+port\s+(.+)$", q, re.I)
    if match:
        return analyze_port(match.group(1))

    match = re.match(r"^analyze\s+threat\s+(.+)$", q, re.I)
    if match:
        return analyze_threat(match.group(1))

    match = re.match(r"^analyze\s+log\s+(.+)$", q, re.I)
    if match:
        return analyze_log(match.group(1))

    return None
