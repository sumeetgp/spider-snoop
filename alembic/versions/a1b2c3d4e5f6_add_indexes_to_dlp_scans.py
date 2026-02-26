"""add indexes to dlp_scans

Revision ID: a1b2c3d4e5f6
Revises: 93b9dd446b00
Create Date: 2026-02-26

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '93b9dd446b00'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index('ix_dlp_scans_created_at', 'dlp_scans', ['created_at'], unique=False)
    op.create_index('ix_dlp_scans_status', 'dlp_scans', ['status'], unique=False)
    op.create_index('ix_dlp_scans_risk_level', 'dlp_scans', ['risk_level'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_dlp_scans_risk_level', table_name='dlp_scans')
    op.drop_index('ix_dlp_scans_status', table_name='dlp_scans')
    op.drop_index('ix_dlp_scans_created_at', table_name='dlp_scans')
