# HackProof AI — Security

## Purpose

HackProof AI is designed for cybersecurity education, defensive analysis, and authorized security testing.

Use HackProof only on systems, applications, URLs, domains, IP addresses, and data that you own or are explicitly authorized to test.

## Authentication

HackProof uses authenticated sessions to protect security functionality.

Unauthenticated users are redirected to the login page when accessing protected routes.

Security APIs are also protected by authentication.

## Session Security

The application configures:

- SESSION_COOKIE_HTTPONLY = True
- SESSION_COOKIE_SAMESITE = Lax
- Secure cookies can be enabled through HACKPROOF_COOKIE_SECURE

## Secret Management

Sensitive configuration is supplied through environment variables:

- HACKPROOF_SECRET_KEY
- GEMINI_API_KEY
- HACKPROOF_DEBUG
- HACKPROOF_COOKIE_SECURE

The .env file is excluded from Git.

Never commit API keys, passwords, tokens, or other secret values.

## Debug Mode

Debug mode is disabled by default.

Production deployment uses Gunicorn instead of Flask's development server.

## Protected APIs

Important protected APIs include:

- /api/phishing
- /api/unified-threat
- /api/security-intelligence
- /api/threat-correlation

## Database

HackProof uses SQLite.

The active database is stored under:

instance/hackproof.db

The database is excluded from Git.

## Production

Production startup uses:

start_production.sh

The application is served using Gunicorn.

Current configuration:

- Bind: 127.0.0.1:5000
- Workers: 2
- Timeout: 120 seconds

## Authorized Security Testing

HackProof is intended for:

- Cybersecurity education
- Defensive analysis
- Authorized penetration-testing laboratories
- Systems owned by the user
- Systems where explicit authorization exists

Do not use HackProof for unauthorized access, scanning, exploitation, credential theft, or disruption.

## Security Hardening Opportunities

Future improvements may include:

- CSRF protection where applicable
- Stronger API input validation
- Rate limiting
- Centralized security logging
- Automated security tests
- Dependency vulnerability scanning
- HTTPS deployment
- Stronger authorization controls
- Secret rotation

## Validation

The project has been checked for:

- Python syntax
- Dependency consistency
- Gunicorn configuration
- Authentication redirects
- Protected API behavior
- Secret-file exposure
- Git repository cleanliness
