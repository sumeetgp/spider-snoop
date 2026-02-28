"""Add policy engine tables

Revision ID: d1e2f3a4b5c6
Revises: c3d4e5f6a7b8
Create Date: 2026-02-28

"""
from alembic import op
import sqlalchemy as sa

revision = 'd1e2f3a4b5c6'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'policies',
        sa.Column('id',          sa.Integer(), primary_key=True, index=True),
        sa.Column('name',        sa.String(120), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('conditions',  sa.JSON(), nullable=False),
        sa.Column('action',      sa.String(20), nullable=False),
        sa.Column('priority',    sa.Integer(), nullable=False, server_default='100'),
        sa.Column('enabled',     sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('simulate',    sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('created_by',  sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at',  sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',  sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_policies_priority', 'policies', ['priority'])
    op.create_index('ix_policies_enabled',  'policies', ['enabled'])

    op.create_table(
        'policy_decisions',
        sa.Column('id',                 sa.Integer(), primary_key=True, index=True),
        sa.Column('scan_id',            sa.Integer(), sa.ForeignKey('dlp_scans.id', ondelete='SET NULL'), nullable=True),
        sa.Column('user_id',            sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('policy_id',          sa.Integer(), sa.ForeignKey('policies.id', ondelete='SET NULL'), nullable=True),
        sa.Column('policy_name',        sa.String(120), nullable=True),
        sa.Column('decision',           sa.String(20), nullable=False),
        sa.Column('matched_conditions', sa.JSON(), nullable=True),
        sa.Column('context_snapshot',   sa.JSON(), nullable=True),
        sa.Column('simulated',          sa.Boolean(), server_default='0'),
        sa.Column('would_have_action',  sa.String(20), nullable=True),
        sa.Column('evaluation_trace',   sa.JSON(), nullable=True),
        sa.Column('created_at',         sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )
    op.create_index('ix_policy_decisions_scan_id',  'policy_decisions', ['scan_id'])
    op.create_index('ix_policy_decisions_user_id',  'policy_decisions', ['user_id'])


def downgrade() -> None:
    op.drop_index('ix_policy_decisions_user_id',  table_name='policy_decisions')
    op.drop_index('ix_policy_decisions_scan_id',  table_name='policy_decisions')
    op.drop_table('policy_decisions')
    op.drop_index('ix_policies_enabled',  table_name='policies')
    op.drop_index('ix_policies_priority', table_name='policies')
    op.drop_table('policies')
