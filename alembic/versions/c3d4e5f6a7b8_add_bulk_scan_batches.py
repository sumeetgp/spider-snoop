"""Add bulk_scan_batches table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-02-27

"""
from alembic import op
import sqlalchemy as sa

revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'bulk_scan_batches',
        sa.Column('id',           sa.Integer(), primary_key=True, index=True),
        sa.Column('batch_id',     sa.String(36), nullable=False, unique=True, index=True),
        sa.Column('user_id',      sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('status',       sa.String(16), nullable=False, server_default='PENDING'),
        sa.Column('total_items',  sa.Integer(), nullable=False, server_default='0'),
        sa.Column('completed',    sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed',       sa.Integer(), nullable=False, server_default='0'),
        sa.Column('results',      sa.JSON(), nullable=True),
        sa.Column('created_at',   sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('bulk_scan_batches')
