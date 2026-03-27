"""
Run this ONCE if you already have a gaming.db and are getting errors
about 'password_reset_token' table not existing.

Usage:
    python migrate.py
"""
from app import app, db

with app.app_context():
    db.create_all()
    print("✅ Migration complete — all tables are up to date.")
    print("   (password_reset_token table created if it was missing)")
