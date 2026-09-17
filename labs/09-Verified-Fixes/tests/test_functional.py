"""Existing product behavior. Students must preserve these tests."""
import pytest


def auth(tenant):
    return {"Authorization": f"Bearer {tenant}-demo-token"}


@pytest.mark.parametrize("tenant,ticket_id", [("alpha", 1), ("alpha", 3), ("beta", 2)])
def test_owner_can_read(client, tenant, ticket_id):
    response = client.get(f"/tickets/{ticket_id}", headers=auth(tenant))
    assert response.status_code == 200
    assert response.json["tenant"] == tenant
    assert response.json["id"] == ticket_id


@pytest.mark.parametrize("url", ["/tickets/1", "/search?q=Alpha", "/health"])
def test_authentication_required(client, url):
    assert client.get(url).status_code == 401
    assert client.get(url, headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_unknown_ticket(client):
    assert client.get("/tickets/999", headers=auth("alpha")).status_code == 404


def test_search_preserves_tenant_scope(client):
    response = client.get("/search", query_string={"q": ""}, headers=auth("alpha"))
    assert response.status_code == 200
    assert [row["id"] for row in response.json] == [1, 3]


def test_search_matches_title(client):
    response = client.get("/search", query_string={"q": "invoice"}, headers=auth("alpha"))
    assert [row["id"] for row in response.json] == [3]
