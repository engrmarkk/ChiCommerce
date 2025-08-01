"""empty message

Revision ID: a4bd3d66e3a9
Revises: 42e906d96ca3
Create Date: 2025-07-31 10:07:43.958296

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4bd3d66e3a9'
down_revision = '42e906d96ca3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('order', schema=None) as batch_op:
        batch_op.add_column(sa.Column('address_id', sa.String(length=50), nullable=False))
        batch_op.create_foreign_key(None, 'order_address', ['address_id'], ['id'])

    with op.batch_alter_table('order_address', schema=None) as batch_op:
        batch_op.drop_constraint('order_address_order_id_fkey', type_='foreignkey')
        batch_op.drop_column('order_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('order_address', schema=None) as batch_op:
        batch_op.add_column(sa.Column('order_id', sa.VARCHAR(length=50), autoincrement=False, nullable=False))
        batch_op.create_foreign_key('order_address_order_id_fkey', 'order', ['order_id'], ['id'])

    with op.batch_alter_table('order', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('address_id')

    # ### end Alembic commands ###
