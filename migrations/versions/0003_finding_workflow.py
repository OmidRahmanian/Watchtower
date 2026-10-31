"""Add scope execution policies, durable request controls and finding workflow."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scope_revisions", sa.Column("execution_policy", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.create_table("run_requests", sa.Column("project_id", sa.UUID(), nullable=False),
                    sa.Column("request_id", sa.UUID(), nullable=False), sa.Column("run_id", sa.UUID(), nullable=False),
                    sa.Column("payload_sha256", sa.Text(), nullable=False),
                    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
                    sa.ForeignKeyConstraint(["project_id"], ["projects.id"]), sa.PrimaryKeyConstraint("project_id", "request_id"))
    op.execute("ALTER TABLE run_requests ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE run_requests FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY project_isolation ON run_requests USING (watchtower_is_system() OR project_id = watchtower_current_project()) WITH CHECK (watchtower_is_system() OR project_id = watchtower_current_project())")
    op.execute("CREATE TRIGGER run_requests_append_only BEFORE UPDATE OR DELETE ON run_requests FOR EACH ROW EXECUTE FUNCTION watchtower_reject_change()")
    op.execute("CREATE TRIGGER run_requests_no_truncate BEFORE TRUNCATE ON run_requests FOR EACH STATEMENT EXECUTE FUNCTION watchtower_reject_change()")
    op.create_table("request_counters", sa.Column("key", sa.Text(), primary_key=True),
                    sa.Column("window", sa.DateTime(timezone=True), primary_key=True),
                    sa.Column("count", sa.Integer(), nullable=False),
                    sa.CheckConstraint("count >= 0", name=op.f("ck_request_counters_count_nonnegative")))
    op.drop_constraint(op.f("ck_findings_status"), "findings", type_="check")
    op.create_check_constraint(op.f("ck_findings_status"), "findings",
                               "status IN ('open', 'triaged', 'in_progress', 'resolved', 'false_positive', 'accepted_risk')")


def downgrade():
    op.drop_column("scope_revisions", "execution_policy")
    op.drop_table("run_requests")
    op.drop_table("request_counters")
    op.execute("UPDATE findings SET status = 'triaged' WHERE status = 'in_progress'")
    op.drop_constraint(op.f("ck_findings_status"), "findings", type_="check")
    op.create_check_constraint(op.f("ck_findings_status"), "findings",
                               "status IN ('open', 'triaged', 'resolved', 'false_positive', 'accepted_risk')")
