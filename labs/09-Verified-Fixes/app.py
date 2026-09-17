"""Deliberately vulnerable, synthetic workshop application.

Use create_app().test_client(); no listening server is needed.
The bearer tokens below are public fixture values, not real credentials.
"""

import sqlite3
from flask import Flask, abort, g, jsonify, request


def create_app():
    app = Flask(__name__)
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE tickets (id INTEGER PRIMARY KEY, tenant TEXT, title TEXT);
        INSERT INTO tickets VALUES (1, 'alpha', 'Alpha onboarding');
        INSERT INTO tickets VALUES (2, 'beta', 'Beta payroll access');
        INSERT INTO tickets VALUES (3, 'alpha', 'Alpha invoice question');
    """)
    app.extensions["workshop_db"] = db
    tokens = {"alpha-demo-token": "alpha", "beta-demo-token": "beta"}

    @app.before_request
    def authenticate():
        g.tenant = tokens.get(request.headers.get("Authorization", "").removeprefix("Bearer "))
        if g.tenant is None:
            abort(401)

    @app.get("/tickets/<int:ticket_id>")
    def get_ticket(ticket_id):
        # Authentication has already run. Does that prove ownership?
        row = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if row is None:
            abort(404)
        return jsonify(dict(row))

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        rows = db.execute(
            "SELECT * FROM tickets WHERE tenant = ? AND title LIKE ? ORDER BY id",
            (g.tenant, "%" + q + "%"),
        ).fetchall()
        return jsonify([dict(row) for row in rows])

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    return app
