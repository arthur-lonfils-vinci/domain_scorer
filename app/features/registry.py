import pkgutil
import importlib
from typing import Dict
from .base import Feature

def _load_from_package(package_name: str) -> Dict[str, Feature]:
    features: Dict[str, Feature] = {}
    pkg = importlib.import_module(package_name)

    for _, modname, is_pkg in pkgutil.iter_modules(pkg.__path__):
        if is_pkg:
            continue
        module = importlib.import_module(f"{package_name}.{modname}")
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


# Load all features from extern + local
_all: Dict[str, Feature] = {}
_all.update(_load_from_package("app.features.extern"))
_all.update(_load_from_package("app.features.local"))

FEATURES: Dict[str, Feature] = _all

DOMAIN_FEATURES: Dict[str, Feature] = {
    name: f for name, f in FEATURES.items()
    if f.target_type in ("domain", "both")
}

EMAIL_FEATURES: Dict[str, Feature] = {
    name: f for name, f in FEATURES.items()
    if f.target_type in ("email", "both")
}
