"""Tests for modules.api_discovery."""
from __future__ import annotations

import json
import pytest
from tests.conftest import FakeResponse, FakeSession


class TestParseOpenapiEndpoints:
    def test_openapi_3_spec(self):
        from modules.api_discovery import parse_openapi_endpoints

        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users": {
                    "get": {"summary": "List users"},
                    "post": {"summary": "Create user", "security": [{"bearerAuth": []}]},
                },
                "/api/health": {
                    "get": {"summary": "Health check"},
                },
            },
        }
        endpoints = parse_openapi_endpoints(spec)
        assert len(endpoints) == 3
        methods = {(e["path"], e["method"]) for e in endpoints}
        assert ("/api/users", "GET") in methods
        assert ("/api/users", "POST") in methods

    def test_auth_required_detected(self):
        from modules.api_discovery import parse_openapi_endpoints

        spec = {
            "paths": {
                "/secure": {
                    "get": {"security": [{"apiKey": []}]},
                },
                "/public": {
                    "get": {"summary": "No auth"},
                },
            },
        }
        endpoints = parse_openapi_endpoints(spec)
        secure = [e for e in endpoints if e["path"] == "/secure"]
        public = [e for e in endpoints if e["path"] == "/public"]
        assert secure[0]["auth_required"] is True
        assert public[0]["auth_required"] is False

    def test_empty_spec(self):
        from modules.api_discovery import parse_openapi_endpoints
        assert parse_openapi_endpoints({}) == []

    def test_swagger_2_spec(self):
        from modules.api_discovery import parse_openapi_endpoints

        spec = {
            "swagger": "2.0",
            "paths": {
                "/api/items": {
                    "get": {"operationId": "getItems"},
                    "delete": {"operationId": "deleteItem"},
                },
            },
        }
        endpoints = parse_openapi_endpoints(spec)
        assert len(endpoints) == 2


class TestDiscoverEndpointsFromJs:
    def test_extracts_api_paths(self, fake_session_factory):
        from modules.api_discovery import discover_endpoints_from_js

        js_content = '''
        fetch("/api/users/list");
        const url = '/api/orders/123';
        axios.get("/api/products");
        '''
        html = '<html><script src="https://example.com/app.js"></script></html>'
        fake = fake_session_factory({
            "app.js": FakeResponse(200, js_content, url="https://example.com/app.js"),
        })

        paths = discover_endpoints_from_js(fake, "https://example.com", html)
        assert "/api/users/list" in paths
        assert "/api/orders/123" in paths
        assert "/api/products" in paths

    def test_empty_js(self, fake_session_factory):
        from modules.api_discovery import discover_endpoints_from_js

        html = '<html><script src="https://example.com/app.js"></script></html>'
        fake = fake_session_factory({
            "app.js": FakeResponse(200, "var x = 1;", url="https://example.com/app.js"),
        })

        paths = discover_endpoints_from_js(fake, "https://example.com", html)
        assert paths == []


class TestDiscoverOpenapiSpec:
    def test_finds_spec(self, fake_session_factory, monkeypatch):
        from modules import api_discovery as mod

        spec_json = json.dumps({"openapi": "3.0.0", "paths": {"/test": {"get": {}}}})
        fake = fake_session_factory({
            "swagger.json": FakeResponse(
                200, spec_json,
                headers={"content-type": "application/json"},
                url="https://example.com/swagger.json",
            ),
        })

        spec, url = mod.discover_openapi_spec(fake, "https://example.com")
        assert spec is not None
        assert spec["openapi"] == "3.0.0"

    def test_no_spec_found(self, fake_session_factory, monkeypatch):
        from modules import api_discovery as mod

        fake = fake_session_factory({})
        spec, url = mod.discover_openapi_spec(fake, "https://example.com")
        assert spec is None
        assert url == ""


class TestBuildPayloadFromSchema:
    def test_builds_from_schema(self):
        from modules.prompt_injection import _build_payload_from_schema

        schema = {
            "properties": {
                "message": {"type": "string"},
                "model": {"type": "string", "default": "gpt-4"},
                "temperature": {"type": "integer", "default": 1},
            },
        }
        payload = _build_payload_from_schema(schema, "hello world")
        assert payload is not None
        assert payload["message"] == "hello world"
        assert payload["model"] == "gpt-4"

    def test_messages_array(self):
        from modules.prompt_injection import _build_payload_from_schema

        schema = {
            "properties": {
                "messages": {
                    "type": "array",
                    "items": {"type": "object"},
                },
            },
        }
        payload = _build_payload_from_schema(schema, "test")
        assert payload is not None
        assert isinstance(payload["messages"], list)
        assert payload["messages"][0]["content"] == "test"

    def test_no_message_field_returns_none(self):
        from modules.prompt_injection import _build_payload_from_schema

        schema = {
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
            },
        }
        payload = _build_payload_from_schema(schema, "test")
        assert payload is None

    def test_none_schema_returns_none(self):
        from modules.prompt_injection import _build_payload_from_schema
        assert _build_payload_from_schema(None, "test") is None


class TestRunScan:
    def test_dry_run(self):
        from modules.api_discovery import run_scan

        alerts = run_scan("https://example.com", dry_run=True)
        assert alerts == []
