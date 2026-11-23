"""Threat intelligence: downloaded hash feeds matched locally, and live hash lookups.

Only hashes leave the NAS. Feeds are downloaded and matched here; live providers are sent a
file's SHA-256 (CIRCL gets its SHA-1, which NSRL indexes) and nothing else.
"""
