import pkgutil
import importlib
from typing import Dict
from .base import Feature
from .types import TargetType


def _load_from_package(package_name: str) -> Dict[str, Feature]:
    features = {}

    pkg = importlib.import_module(package_name)

    # Recursively walk packages
    for module_info in pkgutil.walk_packages(pkg.__path__, package_name + "."):
        module_name = module_info.name

        # Import every module, even inside subfolders
        module = importlib.import_module(module_name)

        # Extract Feature subclasses
        for attr in dir(module):
            obj = getattr(module, attr)
            if (
                isinstance(obj, type)
                and issubclass(obj, Feature)
                and obj is not Feature
            ):
                instance = obj()
                features[instance.name] = instance

    return features


# Load ALL domain + email features recursively
_all = {}
_all.update(_load_from_package("app.features.extern"))
_all.update(_load_from_package("app.features.local"))

FEATURES = _all

DOMAIN_FEATURES = {
    name: f for name, f in FEATURES.items()
    if TargetType.DOMAIN in f.target_type
}

EMAIL_FEATURES = {
    name: f for name, f in FEATURES.items()
    if TargetType.EMAIL in f.target_type
}

WEB_FEATURES = {
    name: f for name, f in FEATURES.items()
    if TargetType.WEB in f.target_type
}
