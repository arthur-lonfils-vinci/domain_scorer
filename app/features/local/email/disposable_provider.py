from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import RunScope, TargetType, Category, ConfigCat


class DisposableEmailProvider(Feature):
    name = "email_disposable_provider"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.HEURISTICS

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
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.6)

    def run(self, root: str):
        root_lower = root.lower()
        if root_lower in self.DISPOSABLE_DOMAINS:
            return self.success(
                self.max_score,
                f"Disposable provider detected: {root_lower}"
            )
        return self.success(0.0, "Provider is not a known disposable mail service")
