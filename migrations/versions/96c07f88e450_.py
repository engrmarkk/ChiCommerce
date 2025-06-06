"""empty message

Revision ID: 96c07f88e450
Revises: 685eb0a68001
Create Date: 2025-04-15 12:09:24.471277

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "96c07f88e450"
down_revision = "685eb0a68001"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "cart",
        sa.Column("id", sa.String(length=50), nullable=False),
        sa.Column("user_id", sa.String(length=50), nullable=False),
        sa.Column("product_id", sa.String(length=50), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("cart")
    # ### end Alembic commands ###
