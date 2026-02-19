"""API client for Grandstream GSC3516."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
from typing import Any

from aiohttp import ClientError, ClientResponse, ClientSession
from yarl import URL

from .const import (
    API_ACCESS_PATH,
    API_GET_LINE_STATUS_PATH,
    API_GET_PHONE_STATUS_PATH,
    API_LIST_BS_ACCOUNTS_PATH,
    API_LOGIN_PATH,
    API_MAKE_CALL_PATH,
    API_PHONE_OPERATION_PATH,
    API_WILL_LOGIN_PATH,
    API_VALUES_GET_PATH,
    API_VALUES_POST_PATH,
    LOGIN_PASSWORD_FIELD,
    LOGIN_USERNAME_FIELDS,
)


class GrandstreamApiError(Exception):
    """Raised when the Grandstream API fails."""


_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class GrandstreamApiClient:
    """Thin async wrapper around Grandstream CGI endpoints."""

    host: str
    port: int
    username: str
    password: str
    use_https: bool
    session: ClientSession

    _sid: str | None = None
    static_sid: str | None = None

    @property
    def _default_headers(self) -> dict[str, str]:
        """Headers expected by newer Grandstream web stacks."""
        return {
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/login",
        }

    @property
    def _effective_sid(self) -> str | None:
        # Prefer freshly authenticated SID over optional static fallback SID.
        return self._sid or self.static_sid

    @property
    def base_url(self) -> str:
        """Return full base URL."""
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.host}:{self.port}"

    async def async_get_values(self, keys: list[str]) -> dict[str, str]:
        """Fetch requested keys from Grandstream API."""
        if not keys:
            return {}

        response = await self._request_with_auth(
            "GET",
            API_VALUES_GET_PATH,
            params={"request": ":".join(keys)},
        )
        payload = await self._extract_payload(response)

        body = payload.get("body")
        if isinstance(body, dict):
            return {str(k): str(v) for k, v in body.items()}

        # Some firmware returns raw key-value output, fallback parser.
        text = await response.text()
        values: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
        return values

    async def async_set_value(self, key: str, value: str) -> None:
        """Set a single P-value using api.values.post."""
        await self.async_set_values({key: value})

    async def async_set_values(self, values: dict[str, str]) -> None:
        """Set multiple key/value pairs using api.values.post."""
        if not values:
            return

        await self._request_with_auth(
            "POST",
            API_VALUES_POST_PATH,
            data=values,
        )

    async def async_get_line_status(self) -> list[dict[str, Any]]:
        """Fetch line status list from native call API."""
        # JS firmware uses POST with line/update_session.
        response = await self._request_with_auth(
            "POST",
            API_GET_LINE_STATUS_PATH,
            data={"line": "-1", "update_session": "false"},
        )
        payload = await self._extract_payload(response, raise_on_invalid=False)
        body = payload.get("body")
        if isinstance(body, list):
            return [item for item in body if isinstance(item, dict)]
        return []

    async def async_get_phone_status(self) -> str | None:
        """Fetch global phone status (e.g. available/ringing/connected)."""
        # JS firmware uses POST with update_session.
        response = await self._request_with_auth(
            "POST",
            API_GET_PHONE_STATUS_PATH,
            data={"update_session": "false"},
        )
        payload = await self._extract_payload(response, raise_on_invalid=False)
        body = payload.get("body")
        if body is None:
            return None
        value = str(body).strip()
        if value.lower() in {"unauthorized", "forbidden", "invalid request"}:
            return None
        return value

    async def async_list_bs_accounts(self) -> list[dict[str, Any]]:
        """Fetch account list used by native call endpoint."""
        response = await self._request_with_auth("GET", API_LIST_BS_ACCOUNTS_PATH)
        payload = await self._extract_payload(response, raise_on_invalid=False)
        body = payload.get("body")
        results = payload.get("results")
        source = results if isinstance(results, list) else body
        if isinstance(source, list):
            return [item for item in source if isinstance(item, dict)]
        return []

    async def async_make_call(self, account: int, number: str, dialplan: str) -> dict[str, Any]:
        """Trigger outbound call via native API."""
        response = await self._request_with_auth(
            "POST",
            API_MAKE_CALL_PATH,
            data={
                "account": str(account),
                "phonenumber": number,
                "dialplan": dialplan,
            },
        )
        return await self._extract_payload(response, raise_on_invalid=False)

    async def async_phone_operation(
        self,
        *,
        cmd: str,
        arg: str = "",
        dtmf: str | None = None,
    ) -> dict[str, Any]:
        """Run call control operations (endcall, acceptcall, mute, dtmf...)."""
        data: dict[str, str] = {"cmd": cmd, "arg": arg}
        if dtmf is not None:
            data["dtmf"] = dtmf
        response = await self._request_with_auth("POST", API_PHONE_OPERATION_PATH, data=data)
        return await self._extract_payload(response, raise_on_invalid=False)

    async def _request_with_auth(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
    ) -> ClientResponse:
        """Make authenticated request and retry once after re-login."""
        try:
            return await self._request(method, path, params=params, data=data)
        except GrandstreamApiError:
            await self.async_login()
            return await self._request(method, path, params=params, data=data)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
    ) -> ClientResponse:
        """Send request with current SID/cookies."""
        req_params = dict(params or {})
        req_data = dict(data or {})
        sid = self._effective_sid
        if sid:
            req_params.setdefault("sid", sid)
            req_data.setdefault("sid", sid)
            # Use cookie jar instead of hardcoded Cookie header so other auth
            # cookies from login are preserved.
            self.session.cookie_jar.update_cookies(
                {"sid": sid},
                URL(f"{self.base_url}/"),
            )

        try:
            response = await self.session.request(
                method,
                f"{self.base_url}{path}",
                params=req_params or None,
                data=req_data or None,
                headers=self._default_headers,
                timeout=10,
            )
        except ClientError as err:
            raise GrandstreamApiError(str(err)) from err

        if response.status in (401, 403):
            raise GrandstreamApiError(f"Unauthorized ({response.status})")
        if response.status >= 400:
            body = await response.text()
            raise GrandstreamApiError(f"HTTP {response.status}: {body[:200]}")

        payload = await self._extract_payload(response, raise_on_invalid=False)
        if payload and str(payload.get("response", "")).lower() in {"error", "failed"}:
            raise GrandstreamApiError(str(payload))

        return response

    async def async_login(self) -> None:
        """Authenticate using common Grandstream login field names."""
        last_error: Exception | None = None

        # Match stock UI flow on newer firmware.
        try:
            await self.session.get(
                f"{self.base_url}{API_WILL_LOGIN_PATH}",
                headers=self._default_headers,
                timeout=10,
            )
        except ClientError:
            pass

        def _hash(value: str, algorithm: str) -> str:
            payload = value.encode("utf-8")
            if algorithm == "sha256":
                return hashlib.sha256(payload).hexdigest()
            return hashlib.md5(payload).hexdigest()

        def _build_access_candidates(username: str) -> list[tuple[str, str]]:
            # label, value
            return [
                ("sha256", _hash(username, "sha256")),
                ("md5", _hash(username, "md5")),
                ("plain", username),
            ]

        def _build_password_candidates(password: str, token: str) -> list[tuple[str, str]]:
            combined = f"{password}{token}"
            return [
                ("sha256(password+token)", _hash(combined, "sha256")),
                ("md5(password+token)", _hash(combined, "md5")),
                ("sha256(password)", _hash(password, "sha256")),
                ("md5(password)", _hash(password, "md5")),
                ("plain(password+token)", combined),
                ("plain(password)", password),
            ]

        for username_field in LOGIN_USERNAME_FIELDS:
            for access_variant_name, access_value in _build_access_candidates(self.username):
                try:
                    access_response = await self.session.post(
                        f"{self.base_url}{API_ACCESS_PATH}",
                        data={"access": access_value},
                        headers=self._default_headers,
                        timeout=10,
                    )
                    access_payload = await self._extract_payload(access_response, raise_on_invalid=False)
                    token = str(access_payload.get("body", ""))
                    if not token:
                        last_error = GrandstreamApiError("Login failed: empty challenge token")
                        continue

                    for pass_variant_name, pass_value in _build_password_candidates(self.password, token):
                        response = await self.session.post(
                            f"{self.base_url}{API_LOGIN_PATH}",
                            data={
                                username_field: self.username,
                                LOGIN_PASSWORD_FIELD: pass_value,
                            },
                            headers=self._default_headers,
                            timeout=10,
                        )
                        if response.status >= 400:
                            last_error = GrandstreamApiError(f"Login failed HTTP {response.status}")
                            continue

                        payload = await self._extract_payload(response, raise_on_invalid=False)
                        if payload:
                            if str(payload.get("response", "")).lower() == "error":
                                body = str(payload.get("body", "login error"))
                                last_error = GrandstreamApiError(f"Login failed: {body}")
                                _LOGGER.debug(
                                    "Grandstream login attempt failed (%s/%s): %s",
                                    access_variant_name,
                                    pass_variant_name,
                                    body,
                                )
                                continue
                            sid = payload.get("sid") or payload.get("session_id")
                            if sid:
                                self._sid = str(sid)
                                self.session.cookie_jar.update_cookies(
                                    {"sid": self._sid},
                                    response.url if response.url.host else URL(f"{self.base_url}/"),
                                )
                                _LOGGER.debug(
                                    "Grandstream login succeeded using %s access hash and %s pass hash",
                                    access_variant_name,
                                    pass_variant_name,
                                )
                                return

                            body = payload.get("body")
                            if isinstance(body, dict):
                                sid = body.get("sid") or body.get("session_id") or body.get("identity")
                                if sid:
                                    self._sid = str(sid)
                                    self.session.cookie_jar.update_cookies(
                                        {"sid": self._sid},
                                        response.url if response.url.host else URL(f"{self.base_url}/"),
                                    )
                                    _LOGGER.debug(
                                        "Grandstream login succeeded from response body using %s/%s",
                                        access_variant_name,
                                        pass_variant_name,
                                    )
                                    return

                        # Cookie fallback: many Grandstream devices issue session cookies.
                        if response.cookies:
                            if "sid" in response.cookies:
                                self._sid = response.cookies["sid"].value
                                _LOGGER.debug(
                                    "Grandstream login cookie accepted using %s access hash and %s pass hash",
                                    access_variant_name,
                                    pass_variant_name,
                                )
                            return
                except ClientError as err:
                    last_error = err
                    continue

        raise GrandstreamApiError(f"Login failed: {last_error or 'invalid credentials or unsupported firmware'}")

    async def async_probe_http(self) -> bool:
        """Check basic HTTP reachability without requiring API auth."""
        try:
            response = await self.session.get(
                self.base_url,
                headers=self._default_headers,
                timeout=10,
            )
        except ClientError:
            return False
        return response.status < 500

    async def _extract_payload(
        self,
        response: ClientResponse,
        *,
        raise_on_invalid: bool = True,
    ) -> dict[str, Any]:
        """Parse JSON API response, or return empty dict if not JSON."""
        text = await response.text()
        if not text:
            return {}

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            if raise_on_invalid:
                raise GrandstreamApiError("Device returned non-JSON response")
            return {}

        if not isinstance(payload, dict):
            if raise_on_invalid:
                raise GrandstreamApiError("Unexpected API payload")
            return {}

        return payload
