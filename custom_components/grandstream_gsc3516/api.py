"""API client for Grandstream GSC3516."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
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
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/login",
        }
        sid = self._effective_sid
        if sid:
            headers["Cookie"] = f"sid={sid}"
        return headers

    @property
    def _effective_sid(self) -> str | None:
        return self.static_sid or self._sid

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
        response = await self._request_with_auth("GET", API_GET_LINE_STATUS_PATH)
        payload = await self._extract_payload(response, raise_on_invalid=False)
        body = payload.get("body")
        if isinstance(body, list):
            return [item for item in body if isinstance(item, dict)]
        return []

    async def async_get_phone_status(self) -> str | None:
        """Fetch global phone status (e.g. available/ringing/connected)."""
        response = await self._request_with_auth("GET", API_GET_PHONE_STATUS_PATH)
        payload = await self._extract_payload(response, raise_on_invalid=False)
        body = payload.get("body")
        if body is None:
            return None
        return str(body)

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

        for username_field in LOGIN_USERNAME_FIELDS:
            try:
                user_hash = hashlib.md5(self.username.encode("utf-8")).hexdigest()
                access_response = await self.session.post(
                    f"{self.base_url}{API_ACCESS_PATH}",
                    data={"access": user_hash},
                    headers=self._default_headers,
                    timeout=10,
                )
                access_payload = await self._extract_payload(access_response, raise_on_invalid=False)
                token = str(access_payload.get("body", ""))
                pass_hash = hashlib.md5(f"{self.password}{token}".encode("utf-8")).hexdigest()
                response = await self.session.post(
                    f"{self.base_url}{API_LOGIN_PATH}",
                    data={
                        username_field: self.username,
                        LOGIN_PASSWORD_FIELD: pass_hash,
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
                        continue
                    sid = payload.get("sid") or payload.get("session_id")
                    if sid:
                        self._sid = str(sid)
                        self.session.cookie_jar.update_cookies(
                            {"sid": self._sid},
                            response.url if response.url.host else URL(f"{self.base_url}/"),
                        )
                        return

                # Cookie fallback: many Grandstream devices issue session cookies.
                if response.cookies:
                    if "sid" in response.cookies:
                        self._sid = response.cookies["sid"].value
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
