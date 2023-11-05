"""Add user_name column to User model

Revision ID: 651c97019638
Revises: d8e3e3d7e1d5
Create Date: 2023-11-03 00:28:58.352585

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '651c97019638'
down_revision = 'd8e3e3d7e1d5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_name', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('role', sa.String(length=20), nullable=True))
        batch_op.drop_column('last_name')
        batch_op.drop_column('first_name')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('first_name', sa.VARCHAR(length=100), nullable=True))
        batch_op.add_column(sa.Column('last_name', sa.VARCHAR(length=100), nullable=True))
        batch_op.drop_column('role')
        batch_op.drop_column('user_name')

    # ### end Alembic commands ###