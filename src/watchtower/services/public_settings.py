"""Safe effective configuration for terminal and dashboard views."""

def public_settings(settings, rules):
    return {"profile": settings.profile, "scope": settings.scope.model_dump(),
            "runtime": {"concurrency": settings.runtime.concurrency, "lease_seconds": settings.runtime.lease_seconds,
                        "limits": settings.runtime.limits},
            "pipeline": {"discovery_sources": settings.pipeline.discovery_sources,
                         "check_kinds": settings.pipeline.check_kinds,
                         "evidence_retention_days": settings.pipeline.evidence_retention_days,
                         "http_schemes": settings.pipeline.http_schemes,
                         "confirm_changes": settings.pipeline.confirm_changes},
            "notifications": [{"name": d.name, "kind": d.kind, "enabled": d.enabled, "events": d.events}
                              for d in settings.notifications.destinations],
            "rules": [{"id": r.id, "version": r.version, "sha256": r.sha256, "approved": r.approved}
                      for r in rules()]}
