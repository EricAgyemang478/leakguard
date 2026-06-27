import type { Rule, FilenameRule } from "./types.js";

/**
 * Content detection rules: 90 provider/format patterns, reconciled from an
 * adversarial design + gap audit. Every rule compiles as a JS RegExp and matches its
 * own example samples; the full set is checked against a decoy corpus (test/corpus.ts).
 */
export const RULES: Rule[] = [
  {
    id: "aws-access-key-id",
    severity: "critical",
    description:
      "AWS Access Key ID (long-term IAM keys begin AKIA, temporary STS keys begin ASIA). 20-char uppercase alphanumeric identifier.",
    regex: new RegExp("\\b((?:AKIA|ASIA)[A-Z0-9]{16})\\b"),
  },
  {
    id: "aws-secret-access-key",
    severity: "critical",
    description:
      "AWS Secret Access Key — 40-char base64-ish string, usually assigned to a variable named aws_secret_access_key or similar.",
    regex: new RegExp(
      "aws_?secret_?(?:access_?)?key[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
      "i",
    ),
  },
  {
    id: "aws-session-token",
    severity: "high",
    description: "AWS temporary session token assigned to aws_session_token — long base64 blob.",
    regex: new RegExp(
      "aws_?session_?token[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9/+=]{100,})[\"']?",
      "i",
    ),
  },
  {
    id: "github-token-classic",
    severity: "high",
    description:
      "GitHub personal access token, OAuth token, user-to-server, server-to-server, or refresh token (ghp_, gho_, ghu_, ghs_, ghr_).",
    regex: new RegExp("\\b(gh[pousr]_[A-Za-z0-9]{30,255})\\b"),
  },
  {
    id: "github-fine-grained-pat",
    severity: "high",
    description: "GitHub fine-grained personal access token (github_pat_ prefix).",
    regex: new RegExp("\\b(github_pat_[A-Za-z0-9]{20,30}_[A-Za-z0-9]{40,85})\\b"),
  },
  {
    id: "gitlab-pat",
    severity: "high",
    description: "GitLab personal access token (glpat- prefix).",
    regex: new RegExp("\\b(glpat-[A-Za-z0-9_-]{20,})\\b"),
  },
  {
    id: "gitlab-other-tokens",
    severity: "high",
    description:
      "GitLab CI/runner/deploy/OAuth tokens (glptt-, GR1348941, glrt-, gldt-, glsoat-, glffct- prefixes).",
    regex: new RegExp(
      "\\b(gl(?:ptt-[0-9a-f]{40}|rt-[A-Za-z0-9_-]{20}|dt-[A-Za-z0-9_-]{20}|soat-[A-Za-z0-9_-]{20}|ffct-[A-Za-z0-9_-]{20})|GR1348941[A-Za-z0-9_-]{20})\\b",
    ),
  },
  {
    id: "google-api-key",
    severity: "high",
    description: "Google / Firebase API key (AIza prefix, 39 chars total).",
    regex: new RegExp("\\b(AIza[0-9A-Za-z_-]{35,40})\\b"),
  },
  {
    id: "google-oauth-client-id",
    severity: "low",
    description: "Google OAuth 2.0 client ID (ends in .apps.googleusercontent.com).",
    regex: new RegExp("\\b([0-9]{10,12}-[a-z0-9]{32}\\.apps\\.googleusercontent\\.com)\\b"),
  },
  {
    id: "google-oauth-client-secret",
    severity: "critical",
    description: "Google OAuth client secret (GOCSPX- prefix for current format).",
    regex: new RegExp("\\b(GOCSPX-[A-Za-z0-9_-]{28})\\b"),
  },
  {
    id: "gcp-service-account-email",
    severity: "low",
    description: "GCP service account email (...@<project>.iam.gserviceaccount.com).",
    regex: new RegExp("\\b([a-z0-9-]+@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com)\\b"),
  },
  {
    id: "slack-token",
    severity: "high",
    description:
      "Slack tokens: bot (xoxb), user (xoxp), app-level (xapp/xoxa), workspace (xoxr), legacy (xoxs).",
    regex: new RegExp("\\b(xox[baprsced]-[0-9A-Za-z-]{10,})\\b"),
  },
  {
    id: "slack-app-token",
    severity: "high",
    description: "Slack app-level token (xapp- prefix).",
    regex: new RegExp("\\b(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[A-Za-z0-9]{32,})\\b"),
  },
  {
    id: "slack-webhook-url",
    severity: "high",
    description: "Slack incoming webhook URL (hooks.slack.com/services/...).",
    regex: new RegExp(
      "https://hooks\\.slack\\.com/(?:services|workflows)/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}",
    ),
  },
  {
    id: "stripe-secret-key",
    severity: "critical",
    description:
      "Stripe live/test secret key (sk_live_, sk_test_) and restricted key (rk_live_, rk_test_).",
    regex: new RegExp("\\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99})\\b"),
  },
  {
    id: "stripe-publishable-key",
    severity: "low",
    description:
      "Stripe publishable key (pk_live_, pk_test_) — public by design but flagged for inventory.",
    regex: new RegExp("\\b(pk_(?:live|test)_[A-Za-z0-9]{24,99})\\b"),
  },
  {
    id: "stripe-webhook-secret",
    severity: "high",
    description: "Stripe webhook signing secret (whsec_ prefix).",
    regex: new RegExp("\\b(whsec_[A-Za-z0-9]{32,})\\b"),
  },
  {
    id: "openai-api-key",
    severity: "critical",
    description: "OpenAI API key — legacy (sk-...) and project-scoped (sk-proj-...).",
    regex: new RegExp("\\b(sk-(?!or-|ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\\b"),
  },
  {
    id: "anthropic-api-key",
    severity: "critical",
    description: "Anthropic Claude API key (sk-ant-api03- and related).",
    regex: new RegExp("\\b(sk-ant-(?:api|sid|admin)[0-9]{2}-[A-Za-z0-9_-]{80,120})\\b"),
  },
  {
    id: "openrouter-api-key",
    severity: "critical",
    description: "OpenRouter API key (sk-or-v1- prefix).",
    regex: new RegExp("\\b(sk-or-v1-[a-f0-9]{64})\\b"),
  },
  {
    id: "cohere-api-key",
    severity: "high",
    description: "Cohere API key — typically a 40-char alphanumeric assigned to COHERE_API_KEY.",
    regex: new RegExp("cohere_?api_?key[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9]{40})[\"']?", "i"),
  },
  {
    id: "huggingface-token",
    severity: "high",
    description: "Hugging Face access token (hf_ prefix).",
    regex: new RegExp("\\b(hf_[A-Za-z0-9]{34,})\\b"),
  },
  {
    id: "twilio-account-sid",
    severity: "medium",
    description:
      "Twilio Account SID (AC + 32 hex). Identifier, not secret, but pairs with auth token.",
    regex: new RegExp("\\b(AC[a-f0-9]{32})\\b"),
  },
  {
    id: "twilio-api-key-sid",
    severity: "high",
    description: "Twilio API Key SID (SK + 32 hex).",
    regex: new RegExp("\\b(SK[a-f0-9]{32})\\b"),
  },
  {
    id: "twilio-auth-token",
    severity: "critical",
    description: "Twilio auth token — 32-char hex assigned to a twilio auth-token variable.",
    regex: new RegExp(
      "twilio[_-]?(?:auth)?[_-]?token[\"']?\\s*[:=]\\s*[\"']?([a-f0-9]{32})[\"']?",
      "i",
    ),
  },
  {
    id: "sendgrid-api-key",
    severity: "critical",
    description: "SendGrid API key (SG. prefix with two dot-separated base64 segments).",
    regex: new RegExp("\\b(SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{40,64})\\b"),
  },
  {
    id: "mailgun-api-key",
    severity: "high",
    description: "Mailgun private API key (key- prefix + 32 hex, or modern hex-hex format).",
    regex: new RegExp("\\b(key-[a-f0-9]{32})\\b"),
  },
  {
    id: "resend-api-key",
    severity: "high",
    description: "Resend API key (re_ prefix).",
    regex: new RegExp("\\b(re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,})\\b"),
  },
  {
    id: "postmark-server-token",
    severity: "high",
    description: "Postmark server API token — UUID format assigned to a postmark variable.",
    regex: new RegExp(
      "postmark[_-]?(?:server|api)?[_-]?token[\"']?\\s*[:=]\\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?",
      "i",
    ),
  },
  {
    id: "npm-access-token",
    severity: "high",
    description: "npm access token (npm_ prefix, 36 chars after prefix).",
    regex: new RegExp("\\b(npm_[A-Za-z0-9]{36,40})\\b"),
  },
  {
    id: "npmrc-auth-token",
    severity: "high",
    description: "_authToken entry in an .npmrc file (registry credential).",
    regex: new RegExp("//[^\\s]+/:_authToken\\s*=\\s*([A-Za-z0-9_./+=-]{16,})", "i"),
  },
  {
    id: "pypi-token",
    severity: "high",
    description: "PyPI upload token (pypi- prefix, base64 body).",
    regex: new RegExp("\\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\\b"),
  },
  {
    id: "datadog-api-key",
    severity: "high",
    description: "Datadog API key — 32-char hex assigned to a datadog API-key variable.",
    regex: new RegExp(
      "(?:datadog|dd)[_-]?api[_-]?key[\"']?\\s*[:=]\\s*[\"']?([a-f0-9]{32})[\"']?",
      "i",
    ),
  },
  {
    id: "datadog-app-key",
    severity: "high",
    description: "Datadog application key — 40-char hex assigned to a datadog app-key variable.",
    regex: new RegExp(
      "(?:datadog|dd)[_-]?app(?:lication)?[_-]?key[\"']?\\s*[:=]\\s*[\"']?([a-f0-9]{40})[\"']?",
      "i",
    ),
  },
  {
    id: "newrelic-license-key",
    severity: "high",
    description: "New Relic license key (40 chars ending in NRAL) or API key (NRAK- prefix).",
    regex: new RegExp("\\b(NRAK-[A-Z0-9]{27}|[a-f0-9]{36}NRAL)\\b"),
  },
  {
    id: "sentry-dsn",
    severity: "medium",
    description: "Sentry DSN with embedded public (and optionally secret) key.",
    regex: new RegExp(
      "https://[a-f0-9]{32}(?::[a-f0-9]{32})?@(?:[a-z0-9.-]+\\.)?(?:ingest\\.)?(?:[a-z0-9-]+\\.)?sentry\\.io/[0-9]+",
    ),
  },
  {
    id: "doppler-token",
    severity: "high",
    description:
      "Doppler tokens: personal (dp.pt.), service (dp.st.), CLI (dp.ct.), service-account (dp.sa.), SCIM (dp.scim.).",
    regex: new RegExp(
      "\\b(dp\\.(?:pt|st|ct|sa|scim|audit)\\.(?:[a-z0-9]+\\.)?[A-Za-z0-9]{36,44})\\b",
    ),
  },
  {
    id: "vercel-token",
    severity: "high",
    description: "Vercel API token — 24-char alphanumeric assigned to a vercel token variable.",
    regex: new RegExp(
      "vercel[_-]?(?:api[_-]?)?token[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9]{24})[\"']?",
      "i",
    ),
  },
  {
    id: "netlify-token",
    severity: "high",
    description:
      "Netlify personal access token — ~40+ char value assigned to a netlify token variable.",
    regex: new RegExp(
      "netlify[_-]?(?:auth[_-]?)?token[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_-]{40,})[\"']?",
      "i",
    ),
  },
  {
    id: "cloudflare-api-token",
    severity: "high",
    description:
      "Cloudflare API token — 40-char base64url value assigned to a cloudflare token variable.",
    regex: new RegExp(
      "(?:cloudflare|cf)[_-]?api[_-]?token[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_-]{40})[\"']?",
      "i",
    ),
  },
  {
    id: "cloudflare-global-api-key",
    severity: "critical",
    description: "Cloudflare Global API Key — 37-char hex assigned to a cloudflare key variable.",
    regex: new RegExp(
      "(?:cloudflare|cf)[_-]?(?:global[_-]?)?api[_-]?key[\"']?\\s*[:=]\\s*[\"']?([a-f0-9]{37})[\"']?",
      "i",
    ),
  },
  {
    id: "digitalocean-token",
    severity: "critical",
    description: "DigitalOcean personal access / OAuth token (dop_v1_, doo_v1_, dor_v1_ prefixes).",
    regex: new RegExp("\\b(do[opr]_v1_[a-f0-9]{64})\\b"),
  },
  {
    id: "heroku-api-key",
    severity: "high",
    description: "Heroku API key — UUID assigned to a heroku key variable.",
    regex: new RegExp(
      "heroku[_-]?(?:api[_-]?)?key[\"']?\\s*[:=]\\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?",
      "i",
    ),
  },
  {
    id: "plaid-token",
    severity: "critical",
    description:
      "Plaid access tokens (access-sandbox-, access-development-, access-production-) with UUID body.",
    regex: new RegExp(
      "\\b(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
    ),
  },
  {
    id: "plaid-client-secret",
    severity: "critical",
    description: "Plaid client secret — 30-char hex assigned to a plaid secret variable.",
    regex: new RegExp(
      "plaid[_-]?(?:client[_-]?)?secret[\"']?\\s*[:=]\\s*[\"']?([a-f0-9]{30})[\"']?",
      "i",
    ),
  },
  {
    id: "shopify-access-token",
    severity: "critical",
    description:
      "Shopify access tokens: app (shpat_), custom-app (shpca_), shared-secret (shpss_), partner OAuth (shppa_).",
    regex: new RegExp("\\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\\b"),
  },
  {
    id: "discord-bot-token",
    severity: "critical",
    description: "Discord bot token — three dot-separated base64 segments (id.timestamp.hmac).",
    regex: new RegExp(
      "\\b([MNO][A-Za-z0-9_-]{23,25}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,38})\\b",
    ),
  },
  {
    id: "discord-webhook-url",
    severity: "high",
    description: "Discord webhook URL (discord.com/api/webhooks/...).",
    regex: new RegExp(
      "https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,80}",
    ),
  },
  {
    id: "telegram-bot-token",
    severity: "high",
    description: "Telegram bot token (numeric id : 35-char base64url).",
    regex: new RegExp("\\b([0-9]{8,10}:[A-Za-z0-9_-]{34,})\\b"),
  },
  {
    id: "algolia-admin-key",
    severity: "critical",
    description:
      "Algolia Admin API key — 32-char hex assigned to an algolia admin/api key variable.",
    regex: new RegExp(
      "algolia[_-]?(?:admin[_-]?)?(?:api[_-]?)?key[\"']?\\s*[:=]\\s*[\"']?([a-f0-9]{32})[\"']?",
      "i",
    ),
  },
  {
    id: "supabase-service-key-jwt",
    severity: "critical",
    description: 'Supabase service_role JWT — JWT whose payload contains "role":"service_role".',
    regex: new RegExp(
      "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]*?(?:c2VydmljZV9yb2xl|role)[A-Za-z0-9_-]*?\\.[A-Za-z0-9_-]{20,}",
    ),
  },
  {
    id: "jwt-generic",
    severity: "medium",
    description: "Generic JSON Web Token (three base64url segments, header begins eyJ).",
    regex: new RegExp("\\b(eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})\\b"),
  },
  {
    id: "private-key-pem",
    severity: "critical",
    description: "PEM-encoded private key block (RSA, EC, DSA, OpenSSH, PGP, or generic PKCS#8).",
    regex: new RegExp(
      "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
    ),
  },
  {
    id: "pgp-private-key-block",
    severity: "critical",
    description: "PGP private key block header.",
    regex: new RegExp("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
  },
  {
    id: "ssh-private-key-putty",
    severity: "critical",
    description: "PuTTY private key file header (.ppk).",
    regex: new RegExp("PuTTY-User-Key-File-[23]:\\s"),
  },
  {
    id: "db-url-with-credentials",
    severity: "high",
    description:
      "Database/broker connection URL with embedded user:password credentials (postgres, postgresql, mysql, mongodb, mongodb+srv, redis, rediss, amqp, amqps).",
    regex: new RegExp(
      "\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis(?:s)?|amqps?)://([^:@/\\s]+):([^@/\\s]+)@[^\\s/\"']+",
      "i",
    ),
  },
  {
    id: "basic-auth-in-url",
    severity: "high",
    description: "HTTP(S) URL with embedded basic-auth credentials (user:password@host).",
    regex: new RegExp("https?://([^:@/\\s]+):([^@/\\s]{3,})@[^\\s/\"']+", "i"),
  },
  {
    id: "generic-api-key-assignment",
    severity: "medium",
    description:
      "Generic assignment of an API key / secret / token / password to a quoted value of sufficient length and entropy.",
    regex: new RegExp(
      "(?:api[_-]?key|apikey|secret[_-]?key|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|token|password|passwd|pwd)[\"']?\\s*[:=]\\s*(?![\"']?(?:process\\.env|import\\.meta|os\\.environ|process\\[|\\$\\{|\\{\\{))(?:[\"']([^\"'\\s]{8,})[\"']|([A-Za-z0-9_\\-./+=@!$%]{16,}))",
      "i",
    ),
  },
  {
    id: "generic-password-assignment-env",
    severity: "medium",
    description:
      "Password assignment in env/ini style (KEY=value) without quotes for common secret keys.",
    regex: new RegExp(
      "\\b(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|ADMIN_PASSWORD|ROOT_PASSWORD|SECRET_KEY|JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY)\\s*=\\s*([^\\s\"'#]{8,})",
      "i",
    ),
  },
  {
    id: "firebase-cloud-messaging-key",
    severity: "high",
    description: "Firebase Cloud Messaging / GCM legacy server key (AAAA prefix, base64url body).",
    regex: new RegExp("\\b(AAAA[A-Za-z0-9_-]{7}:APA91[A-Za-z0-9_-]{100,})\\b"),
  },
  {
    id: "square-access-token",
    severity: "critical",
    description: "Square access token (EAAA prefix) or OAuth secret (sq0csp-, sq0idp-).",
    regex: new RegExp("\\b(EAAA[A-Za-z0-9_-]{58,68}|sq0(?:atp|csp|idp)-[A-Za-z0-9_-]{22,43})\\b"),
  },
  {
    id: "paypal-braintree-token",
    severity: "critical",
    description: "Braintree (PayPal) access token (sandbox or production).",
    regex: new RegExp(
      "\\b(access_token\\$(?:production|sandbox)\\$[a-z0-9]{16}\\$[a-f0-9]{32})\\b",
    ),
  },
  {
    id: "mailchimp-api-key",
    severity: "high",
    description: "Mailchimp API key (32 hex followed by -usXX datacenter suffix).",
    regex: new RegExp("\\b([a-f0-9]{32}-us[0-9]{1,2})\\b"),
  },
  {
    id: "facebook-access-token",
    severity: "high",
    description: "Facebook/Meta Graph API access token (EAA prefix) — long base64 blob.",
    regex: new RegExp("\\b(EAA[A-Za-z0-9]{90,})\\b"),
  },
  {
    id: "linear-api-key",
    severity: "high",
    description: "Linear API key (lin_api_ prefix).",
    regex: new RegExp("\\b(lin_api_[A-Za-z0-9]{40})\\b"),
  },
  {
    id: "databricks-token",
    severity: "high",
    description: "Databricks personal access token (dapi prefix + 32 hex, optional -N suffix).",
    regex: new RegExp("\\b(dapi[a-f0-9]{32}(?:-[0-9]+)?)\\b"),
  },
  {
    id: "pulumi-access-token",
    severity: "high",
    description: "Pulumi access token (pul- prefix).",
    regex: new RegExp("\\b(pul-[a-f0-9]{40})\\b"),
  },
  {
    id: "jfrog-artifactory-token",
    severity: "high",
    description: "JFrog Artifactory reference/identity token (cmVmdGtu / AKCp prefixes).",
    regex: new RegExp("\\b(cmVmdGtuOj[A-Za-z0-9]{60,}|AKCp[A-Za-z0-9]{64,})\\b"),
  },
  {
    id: "grafana-cloud-token",
    severity: "high",
    description: "Grafana service-account or cloud token (glsa_, glc_ prefixes).",
    regex: new RegExp("\\b(gl(?:sa|c)_[A-Za-z0-9_]{32,})\\b"),
  },
  {
    id: "figma-token",
    severity: "high",
    description: "Figma personal access token (figd_, figu_, figoa_ prefixes).",
    regex: new RegExp("\\b(fig(?:d|u|oa)_[A-Za-z0-9_-]{40,})\\b"),
  },
  {
    id: "asana-pat",
    severity: "high",
    description: "Asana personal access token (numeric:hex form or 1/ prefix).",
    regex: new RegExp("\\b([0-9]{1,2}/[0-9]{16}:[a-f0-9]{32})\\b"),
  },
  {
    id: "dropbox-token",
    severity: "high",
    description: "Dropbox access token (sl. prefix, base64url body).",
    regex: new RegExp("\\b(sl\\.[A-Za-z0-9_-]{130,152})\\b"),
  },
  {
    id: "azure-storage-connection-string",
    severity: "critical",
    description: "Azure Storage account connection string with AccountKey.",
    regex: new RegExp(
      "DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=([A-Za-z0-9+/=]{60,100});",
      "i",
    ),
  },
  {
    id: "azure-ad-client-secret",
    severity: "critical",
    description:
      "Azure AD / Entra app client secret (often prefixed with a short code then ~ and base64url, ~40 chars).",
    regex: new RegExp(
      "(?:client[_-]?secret|azure[_-]?client[_-]?secret)[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9~._-]{3}[A-Za-z0-9~._-]{31,40})[\"']?",
      "i",
    ),
  },
  {
    id: "twitch-client-secret",
    severity: "high",
    description:
      "Twitch client ID/secret — 30-char alphanumeric assigned to a twitch secret/client variable.",
    regex: new RegExp(
      "twitch[_-]?(?:client[_-]?)?(?:secret|id)[\"']?\\s*[:=]\\s*[\"']?([a-z0-9]{30})[\"']?",
      "i",
    ),
  },
  {
    id: "rapidapi-key",
    severity: "high",
    description:
      "RapidAPI key — 50-char base64url assigned to an x-rapidapi-key header or variable.",
    regex: new RegExp(
      "(?:x-rapidapi-key|rapidapi[_-]?key)[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9]{50})[\"']?",
      "i",
    ),
  },
  {
    id: "segment-write-key",
    severity: "medium",
    description: "Segment write key — base64 value assigned to a segment write-key variable.",
    regex: new RegExp(
      "segment[_-]?(?:write[_-]?)?key[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9]{32,})[\"']?",
      "i",
    ),
  },
  {
    id: "pagerduty-token",
    severity: "high",
    description: "PagerDuty API token (20-char with +/ allowed) assigned to a pagerduty variable.",
    regex: new RegExp(
      "pager[_-]?duty[_-]?(?:api[_-]?)?(?:token|key)[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9+_=-]{20})[\"']?",
      "i",
    ),
  },
  {
    id: "clojars-deploy-token",
    severity: "high",
    description: "Clojars deploy token (CLOJARS_ prefix).",
    regex: new RegExp("\\b(CLOJARS_[A-Za-z0-9]{60})\\b"),
  },
  {
    id: "basic-auth-header",
    severity: "high",
    description: "HTTP Authorization Basic header with base64-encoded credentials.",
    regex: new RegExp(
      "authorization[\"']?\\s*[:=]\\s*[\"']?Basic\\s+([A-Za-z0-9+/]{16,}={0,2})",
      "i",
    ),
  },
  {
    id: "bearer-token-header",
    severity: "medium",
    description: "HTTP Authorization Bearer header carrying a long opaque/JWT token.",
    regex: new RegExp(
      "authorization[\"']?\\s*[:=]\\s*[\"']?Bearer\\s+([A-Za-z0-9._~+/-]{20,})",
      "i",
    ),
  },
  {
    id: "aws-mws-auth-token",
    severity: "critical",
    description: "Amazon MWS auth token (amzn.mws. prefix + UUID).",
    regex: new RegExp(
      "\\b(amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
    ),
  },
  {
    id: "fastly-api-token",
    severity: "high",
    description: "Fastly API token — 32-char base64url assigned to a fastly token variable.",
    regex: new RegExp(
      "fastly[_-]?(?:api[_-]?)?(?:token|key)[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_-]{32})[\"']?",
      "i",
    ),
  },
  {
    id: "intercom-access-token",
    severity: "high",
    description: "Intercom access token — base64 value assigned to an intercom token variable.",
    regex: new RegExp(
      "intercom[_-]?(?:access[_-]?)?token[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9=_-]{40,})[\"']?",
      "i",
    ),
  },
  {
    id: "contentful-access-token",
    severity: "high",
    description: "Contentful CMA/CDA access token (CFPAT- prefix or anchored variable).",
    regex: new RegExp("\\b(CFPAT-[A-Za-z0-9_-]{43})\\b"),
  },
  {
    id: "sonarqube-token",
    severity: "high",
    description: "SonarQube/SonarCloud token (squ_, sqp_, sqa_ prefixes).",
    regex: new RegExp("\\b(sq[upa]_[a-f0-9]{40})\\b"),
  },
  {
    id: "atlassian-api-token",
    severity: "critical",
    description: "Atlassian / Jira API token (ATATT / ATCTT prefix).",
    regex: new RegExp("\\b((?:ATATT|ATCTT)[A-Za-z0-9_=.+/-]{20,})\\b"),
  },
  {
    id: "notion-token",
    severity: "high",
    description: "Notion integration token (secret_ / ntn_ prefix).",
    regex: new RegExp("\\b((?:ntn_|secret_)[A-Za-z0-9]{40,})\\b"),
  },
  {
    id: "postman-api-key",
    severity: "high",
    description: "Postman API key (PMAK- prefix).",
    regex: new RegExp("\\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\\b"),
  },
  {
    id: "airtable-pat",
    severity: "high",
    description: "Airtable personal access token (pat prefix).",
    regex: new RegExp("\\b(pat[A-Za-z0-9]{14}\\.[a-f0-9]{64})\\b"),
  },
];

export const FILENAME_RULES: FilenameRule[] = [
  {
    id: "dotenv-file",
    description: "Environment file (may contain secrets)",
    severity: "high",
    regex: /^\.env(?:\.(?!example|sample|template|dist|defaults)[A-Za-z0-9_.-]+)?$/,
  },
  {
    id: "private-key-file",
    description: "Private key / certificate file",
    severity: "critical",
    regex: /\.(?:pem|key|p12|pfx|ppk|pkcs12)$/i,
  },
  {
    id: "ssh-private-key-file",
    description: "SSH private key file",
    severity: "critical",
    regex: /^id_(?:rsa|dsa|ecdsa|ed25519)$/,
  },
  {
    id: "credentials-file",
    description: "Credentials/secrets file",
    severity: "medium",
    regex: /^(?:credentials|secrets?)\.(?:json|ya?ml)$/i,
  },
  {
    id: "keystore-file",
    description: "Java keystore",
    severity: "high",
    regex: /\.(?:jks|keystore)$/i,
  },
  {
    id: "htpasswd-file",
    description: "htpasswd file",
    severity: "medium",
    regex: /(?:^|\.)htpasswd$/,
  },
];
