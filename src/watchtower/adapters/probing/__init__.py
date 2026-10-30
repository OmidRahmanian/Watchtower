"""Active probing adapters. Every connection goes through the scope guard."""

from watchtower.adapters.probing.http import HttpProber, PinnedHTTPConnection, PinnedHTTPSConnection

__all__ = ["DISABLED_ADAPTERS", "HttpProber", "PinnedHTTPConnection", "PinnedHTTPSConnection"]

# Adapters that stay off because their outbound traffic cannot be checked per destination.
DISABLED_ADAPTERS = {
    "httpx-cli": (
        "ProjectDiscovery httpx resolves names and follows redirects inside its own process, "
        "so each connection cannot be checked with check_connection/check_redirect. "
        "Use watchtower.adapters.probing.http.HttpProber instead."
    ),
}
