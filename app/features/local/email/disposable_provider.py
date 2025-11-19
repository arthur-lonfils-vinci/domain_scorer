from typing import List
import tldextract

from app.config import get_weight
from app.features.base import Feature
from app.features.types import RunScope, TargetType, Category, ConfigCat


class DisposableEmailProvider(Feature):
    name = "email_disposable_provider"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.ROOT]
    category = Category.HEURISTICS

    # Base registered domains (not FQDN)
    DISPOSABLE_DOMAINS = {
        "10minutemail.com",
        "tempmail.com",
        "mailinator.com",
        "trashmail.com",
        "guerrillamail.com",
        "getnada.com",
        "dispostable.com",
        "maildrop.cc",
        "yopmail.com",
        "temp-mail.org",
        "moakt.com",
        "mytemp.email",
        "fakeinbox.com",
    }

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.6)

    def run(self, target: str, context: dict):
        """
        target → the root FQDN layer is passing "root"
        context["root"] → always available in email_analyzer
        """

        # Prefer explicit context (root domain)
        root = context.get("root") or target
        ext = tldextract.extract(root)

        if not ext.domain or not ext.suffix:
            return self.disabled(f"Invalid domain extraction for '{root}'")

        registered = f"{ext.domain}.{ext.suffix}".lower()

        # Exact match
        if registered in self.DISPOSABLE_DOMAINS:
            return self.success(
                self.max_score,
                f"Disposable provider detected: {registered}"
            )

        return self.success(0.0, "Provider is not a known disposable mail service")
