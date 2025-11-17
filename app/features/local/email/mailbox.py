from app.features.base import Feature
from app.features.utils.dns.dns_utils import resolve_dns

class EmailMailboxFeature(Feature):
    name = "email_mailbox"
    target_type = "email"
    run_on = "user"
    max_score = 0.15

    def run(self, email: str):
        try:
            local, domain = email.split("@", 1)
            answers = resolve_dns(domain, "MX")
            if len(answers) == 0:
                return self.error("Mailbox impossible — no MX records")
            return self.success(0.0, "Mailbox likely exists (MX found)")
        except Exception as e:
            return self.disabled(f"Mailbox check failed: {e}")
