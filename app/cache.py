import json
import os
from pathlib import Path

CACHE_FILE = Path("cache.json")

# Load existing cache or initialize empty
if CACHE_FILE.exists():
    with open(CACHE_FILE, "r") as f:
        cache = json.load(f)
else:
    cache = {}

def get_cache(key):
    return cache.get(key)

def set_cache(key, value):
    cache[key] = value
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)
