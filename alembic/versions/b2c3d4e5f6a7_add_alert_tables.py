"""Add alert_configs and alert_history tables

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-02-27

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # alert_configs table
    op.create_table(
        'alert_configs',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(120), nullable=False, server_default='Default Alert'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('trigger_on', sa.String(16), nullable=False, server_default='CRITICAL'),
        sa.Column('webhook_url', sa.String(512), nullable=True),
        sa.Column('email', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )

    # alert_history table
    op.create_table(
        'alert_history',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('config_id', sa.Integer(), sa.ForeignKey('alert_configs.id', ondelete='CASCADE'), nullable=True),
        sa.Column('scan_id', sa.Integer(), sa.ForeignKey('dlp_scans.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('channel', sa.String(16), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('response_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('fired_at', sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table('alert_history')
    op.drop_table('alert_configs')
