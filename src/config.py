SECRET_PATTERNS = {
    # AWS
    "AWS Access Key ID": r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
    "AWS Secret Key": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
    "AWS MWS Key": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    # Google
    "Google API Key": r"AIza[0-9A-Za-z\-_]{28,}",
    "Google OAuth Token": r"ya29\.[0-9A-Za-z\\-_]+",
    "Google Cloud Platform API Key": r"[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}",

    # Microsoft
    "Azure Storage Account Key": r"DefaultEndpointsProtocol=https;AccountName=[a-z0-9]{3,24};AccountKey=[a-zA-Z0-9+/=]{88}",
    "Microsoft Teams Webhook": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9-@]+",

    # Database
    "PostgreSQL Connection String": r"postgres(ql)?://[^:]+:[^@]+@[^/]+/[^?\s]+",
    "MySQL Password": r"mysql://[^:\s]+:[^@\s]+@[^\s/]+?/[^\s]+",
    "MongoDB URI": r"mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^\s/]+?/[^\s]+",

    # Social Media
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Twitter Bearer Token": r"AAAAAAAAAAAAAAAAAAAA[0-9a-zA-Z%]+",
    "Instagram Access Token": r"[0-9a-f]{32}\.[0-9a-f]{16}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",

    # Payment Processors
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\\-_]{43}",
    "Stripe API Key": r"sk_(live|test)_[0-9a-zA-Z]{20,}",

    # CI/CD
    "CircleCI Token": r"circleci-[a-f0-9]{40}",
    "Travis CI Token": r"(?i)travisci-[a-f0-9]{22}",

    # Cloud Services
    "Heroku API Key": r"[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "DigitalOcean Token": r"dop_v1_[0-9a-f]{64}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",

    # Security/Crypto
    "SSH Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",

    # Generic Secrets
    "API Key": r"(?i)(api|access|secret|token|key)[_-]?key[_-]?[0-9a-z]{16,64}",
    "Basic Auth Credentials": r"(?i)basic [a-z0-9+/=]+",

    # Additional Private Keys & Secrets
    "PKCS8 Private Key": r"-----BEGIN PRIVATE KEY-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "Ed25519 Private Key": r"-----BEGIN ED25519 PRIVATE KEY-----",
    "PKCS1 RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "PKCS8 Encrypted Private Key": r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "Pem Certificate": r"-----BEGIN CERTIFICATE-----",
    "Pem Request": r"-----BEGIN CERTIFICATE REQUEST-----"
}
