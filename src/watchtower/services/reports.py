"""Bounded, authorized reports shared by the CLI and HTTP API."""
import csv
import io
import json
from watchtower.api import queries
from watchtower.api.pagination import decode_cursor, encode_cursor, cursor_time, cursor_uuid
from watchtower.persistence.repositories.audit import record_audit
from watchtower.security.auth import Permission

def export_rows(items, dataset):
    if dataset == "assets":
        return [{"id": str(a.id), "kind": a.kind.value, "value": a.value, "owner": a.attributes.get("owner", ""),
                 "tags": ",".join(a.attributes.get("tags", [])), "first_seen": a.first_seen_at.isoformat(),
                 "last_seen": a.last_seen_at.isoformat()} for a in items]
    return [{"id": str(f.id), "title": f.title, "severity": f.severity.value, "status": f.status.value,
             "owner": f.details.get("owner", ""), "confidence": f.details.get("confidence", ""),
             "priority": (f.details.get("priority_override") or f.details.get("priority") or {}).get("level", ""),
             "check": f.source, "first_seen": f.first_seen_at.isoformat(), "last_seen": f.last_seen_at.isoformat()} for f in items]


def csv_report(rows):
    stream = io.StringIO(newline="")
    if rows:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\r\n")
        writer.writeheader()
        for row in rows:
            # Defend spreadsheet users against CSV formula injection, including whitespace prefixes.
            safe_row = {key: "'" + str(value) if str(value).lstrip().startswith(("=", "+", "-", "@"))
                        or str(value).startswith(("\t", "\r", "\n")) else value for key, value in row.items()}
            writer.writerow(safe_row)
    return stream.getvalue()


def build_report(database, project_id, ctx, *, dataset="assets", format="json", limit=100, cursor=None):
    if dataset not in ("assets", "findings") or format not in ("json", "csv") or not 1 <= limit <= 200:
        raise ValueError("invalid report dataset, format or page size")
    ctx.require(Permission.VIEW)
    with database.project(project_id) as uow:
        after, before = None, None
        if cursor:
            first, second = decode_cursor(cursor, "export:" + dataset, 2)
            if dataset == "assets":
                after = (str(first), str(second))
            else:
                before = (cursor_time(first), cursor_uuid(second))
        rows = (queries.list_assets(uow, limit=limit + 1, after=after) if dataset == "assets"
                else queries.list_findings(uow, limit=limit + 1, before=before))
        page = rows[:limit]
        next_cursor = None
        if len(rows) > limit:
            key = (page[-1].kind.value, page[-1].value) if dataset == "assets" else (page[-1].last_seen_at, page[-1].id)
            next_cursor = encode_cursor("export:" + dataset, *key)
        records = export_rows(page, dataset)
        record_audit(uow.connection, "report.exported", dataset, project_id=project_id,
                     actor=ctx.principal.id, details={"format": format, "count": len(records)})
    headers = {"Content-Disposition": f'attachment; filename="watchtower-{dataset}.{format}"',
               "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if next_cursor:
        headers["X-Next-Cursor"] = next_cursor
    content = csv_report(records) if format == "csv" else json.dumps({"items": records, "next_cursor": next_cursor})
    return content.encode(), "text/csv" if format == "csv" else "application/json", headers
