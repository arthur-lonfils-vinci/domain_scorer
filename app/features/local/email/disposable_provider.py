from app.config import get_weight
from app.features.base import Feature


class DisposableEmailProvider(Feature):
    name = "email_disposable_provider"
    target_type = "email"
    run_on = "root"   # run on the domain part

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
    }

    def __init__(self):
        self.max_score = get_weight("email", self.name, 0.6)

    def run(self, root: str):
        root_lower = root.lower()
        if root_lower in self.DISPOSABLE_DOMAINS:
            return self.success(
                self.max_score,
                f"Disposable provider detected: {root_lower}"
            )
        return self.success(0.0, "Provider is not a known disposable mail service")
