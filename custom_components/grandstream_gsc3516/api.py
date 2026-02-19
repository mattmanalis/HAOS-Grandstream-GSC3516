"""API client for Grandstream GSC3516."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import logging
from typing import Any

from aiohttp import ClientError, ClientResponse, ClientSession
from yarl import URL

from .const import (
    API_ACCESS_PATH,
    API_BS_XSI_LOGIN_PATH,
    API_CONFIG_UPDATE_PATH,
    API_DO_REFRESH_PATH,
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
    call_api_use_passcode: bool = False
    call_api_passcode: str | None = None
    call_api_hs: bool = True
    _login_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

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

        normalized = _normalize_pvalues(values)

        async def _values_post_sid_auto() -> None:
            await self._request_with_auth("POST", API_VALUES_POST_PATH, data=values)

        async def _values_post_cookie_only() -> None:
            await self._request("POST", API_VALUES_POST_PATH, data=values, allow_sid=False)

        async def _values_post_sid_body() -> None:
            payload = dict(values)
            sid = self._effective_sid
            if sid:
                payload["sid"] = sid
            await self._request("POST", API_VALUES_POST_PATH, data=payload, allow_sid=False)

        async def _config_update_cookie_only() -> None:
            await self._request(
                "PUT",
                API_CONFIG_UPDATE_PATH,
                json_data={"alias": {}, "pvalue": normalized},
                allow_sid=False,
            )

        async def _config_update_sid_body() -> None:
            payload: dict[str, Any] = {"alias": {}, "pvalue": normalized}
            sid = self._effective_sid
            if sid:
                payload["sid"] = sid
            await self._request(
                "PUT",
                API_CONFIG_UPDATE_PATH,
                json_data=payload,
                allow_sid=False,
            )

        async def _config_update_sid_query() -> None:
            sid = self._effective_sid
            await self._request(
                "PUT",
                API_CONFIG_UPDATE_PATH,
                params={"sid": sid} if sid else None,
                json_data={"alias": {}, "pvalue": normalized},
                allow_sid=False,
            )

        attempts: list[tuple[str, Any]] = [
            ("values_post_sid_auto", _values_post_sid_auto),
            ("values_post_cookie_only", _values_post_cookie_only),
            ("values_post_sid_body", _values_post_sid_body),
            ("config_update_cookie_only", _config_update_cookie_only),
            ("config_update_sid_body", _config_update_sid_body),
            ("config_update_sid_query", _config_update_sid_query),
        ]

        await self.async_login()
        last_error: GrandstreamApiError | None = None
        for name, attempt in attempts:
            try:
                await attempt()
                _LOGGER.debug("Grandstream set_values succeeded via %s", name)
                return
            except GrandstreamApiError as err:
                last_error = err
                _LOGGER.debug("Grandstream set_values failed via %s: %s", name, err)
                err_text = str(err).lower()
                if "session-expired" in err_text or "unauthorized" in err_text:
                    try:
                        await self.async_login()
                    except GrandstreamApiError:
                        pass

        # Last resort: some firmware accepts config changes only via SSH CLI.
        try:
            await self._async_set_values_via_ssh(values)
            _LOGGER.debug("Grandstream set_values succeeded via ssh_cli")
            return
        except GrandstreamApiError as ssh_err:
            _LOGGER.debug("Grandstream set_values failed via ssh_cli: %s", ssh_err)

        raise GrandstreamApiError(
            f"Failed to set values after trying all write methods: {last_error}"
        )

    async def _async_set_values_via_ssh(self, values: dict[str, str]) -> None:
        """Apply p-values through the device SSH command shell."""
        await asyncio.to_thread(self._set_values_via_ssh, values)

    def _set_values_via_ssh(self, values: dict[str, str]) -> None:
        """Blocking SSH CLI writer used as final fallback."""
        try:
            import paramiko  # type: ignore[import-not-found]
        except Exception as err:
            raise GrandstreamApiError(f"SSH fallback unavailable (paramiko missing): {err}") from err

        import time

        def _read_until_prompt(
            channel: Any,
            prompts: tuple[str, ...],
            timeout: float = 10.0,
        ) -> str:
            end = time.monotonic() + timeout
            buffer = ""
            while time.monotonic() < end:
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                    buffer += chunk
                    if any(prompt in buffer for prompt in prompts):
                        return buffer
                else:
                    time.sleep(0.05)
            raise GrandstreamApiError(
                f"SSH prompt timeout waiting for {prompts}; received: {buffer[-300:]}"
            )

        def _send_and_wait(
            channel: Any,
            command: str,
            prompts: tuple[str, ...],
            timeout: float = 10.0,
        ) -> str:
            channel.send(command + "\n")
            return _read_until_prompt(channel, prompts, timeout=timeout)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=22,
                username=self.username,
                password=self.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
            )
            channel = client.invoke_shell(width=160, height=24)
            _read_until_prompt(channel, ("GSC3516> ", "GSC3516>"), timeout=12.0)
            _send_and_wait(channel, "config", ("CONFIG> ", "CONFIG>"), timeout=8.0)

            for key, value in values.items():
                if not key or any(ch.isspace() for ch in key):
                    raise GrandstreamApiError(f"Invalid key for SSH set: {key!r}")
                # Grandstream CONFIG shell accepts: set <name> <value>
                _send_and_wait(channel, f"set {key} {value}", ("CONFIG> ", "CONFIG>"), timeout=8.0)

            _send_and_wait(channel, "commit", ("CONFIG> ", "CONFIG>"), timeout=8.0)
            _send_and_wait(channel, "cfg_update", ("CONFIG> ", "CONFIG>"), timeout=12.0)
            _send_and_wait(channel, "exit", ("GSC3516> ", "GSC3516>"), timeout=8.0)
            channel.send("exit\n")
        except Exception as err:
            if isinstance(err, GrandstreamApiError):
                raise
            raise GrandstreamApiError(f"SSH fallback failed: {err}") from err
        finally:
            client.close()

    async def async_get_line_status(self) -> list[dict[str, Any]]:
        """Fetch line status list from native call API."""
        # JS firmware uses POST with line/update_session.
        data = {"line": "-1", "update_session": "false"}
        if self._use_passcode_call_api:
            response = await self._request(
                "POST",
                API_GET_LINE_STATUS_PATH,
                params=self._call_api_auth_params,
                data=data,
                allow_sid=False,
            )
        else:
            response = await self._request_with_auth(
                "POST",
                API_GET_LINE_STATUS_PATH,
                data=data,
            )
        payload = await self._extract_payload(response, raise_on_invalid=False)
        body = payload.get("body")
        if isinstance(body, list):
            return [item for item in body if isinstance(item, dict)]
        return []

    async def async_get_phone_status(self) -> str | None:
        """Fetch global phone status (e.g. available/ringing/connected)."""
        # JS firmware uses POST with update_session.
        data = {"update_session": "false"}
        if self._use_passcode_call_api:
            response = await self._request(
                "POST",
                API_GET_PHONE_STATUS_PATH,
                params=self._call_api_auth_params,
                data=data,
                allow_sid=False,
            )
        else:
            response = await self._request_with_auth(
                "POST",
                API_GET_PHONE_STATUS_PATH,
                data=data,
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
        if self._use_passcode_call_api:
            response = await self._request(
                "GET",
                API_LIST_BS_ACCOUNTS_PATH,
                params=self._call_api_auth_params,
                allow_sid=False,
            )
        else:
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
        if self._use_passcode_call_api:
            response = await self._request(
                "GET",
                API_MAKE_CALL_PATH,
                params={
                    **self._call_api_auth_params,
                    "phonenumber": number,
                    # Keep these for firmware variants that inspect them.
                    "account": str(account),
                    "dialplan": dialplan,
                },
                allow_sid=False,
            )
            return await self._extract_payload(response, raise_on_invalid=False)

        # Ensure call-control endpoints use a fresh authenticated session.
        await self.async_login()

        # Some firmware branches require XSI call session init before make_call.
        try:
            await self._request_with_auth("POST", API_BS_XSI_LOGIN_PATH)
        except GrandstreamApiError:
            # Not all devices expose/require this endpoint.
            pass

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
        if self._use_passcode_call_api:
            response = await self._request(
                "GET",
                API_PHONE_OPERATION_PATH,
                params={
                    **self._call_api_auth_params,
                    **data,
                },
                allow_sid=False,
            )
        else:
            response = await self._request_with_auth("POST", API_PHONE_OPERATION_PATH, data=data)
        return await self._extract_payload(response, raise_on_invalid=False)

    async def _request_with_auth(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> ClientResponse:
        """Make authenticated request and retry once after re-login."""
        try:
            return await self._request(
                method,
                path,
                params=params,
                data=data,
                json_data=json_data,
            )
        except GrandstreamApiError as err:
            err_text = str(err).lower()
            is_auth_error = "unauthorized" in err_text or "session-expired" in err_text
            if not is_auth_error:
                raise
            # Polling endpoints should not force re-login loops every cycle.
            if path in {
                API_VALUES_GET_PATH,
                API_GET_LINE_STATUS_PATH,
                API_GET_PHONE_STATUS_PATH,
                API_LIST_BS_ACCOUNTS_PATH,
            }:
                raise
            await self.async_login()
            return await self._request(
                method,
                path,
                params=params,
                data=data,
                json_data=json_data,
            )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json_data: dict[str, Any] | None = None,
        allow_sid: bool = True,
    ) -> ClientResponse:
        """Send request with current SID/cookies."""
        req_params = dict(params or {})
        req_data = dict(data or {})
        sid = self._effective_sid
        if allow_sid and sid:
            req_params.setdefault("sid", sid)
            if json_data is None:
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
                json=json_data,
                headers=self._default_headers,
                timeout=10,
            )
        except ClientError as err:
            raise GrandstreamApiError(str(err)) from err

        self._remember_response_cookies(response)

        if response.status in (401, 403):
            body = await response.text()
            sid = self._effective_sid or ""
            _LOGGER.debug(
                "Grandstream unauthorized on %s status=%s sid_len=%s sid_prefix=%s body=%s",
                path,
                response.status,
                len(sid),
                sid[:8],
                body[:200],
            )
            raise GrandstreamApiError(f"Unauthorized ({response.status})")
        if response.status >= 400:
            body = await response.text()
            raise GrandstreamApiError(f"HTTP {response.status}: {body[:200]}")

        payload = await self._extract_payload(response, raise_on_invalid=False)
        if payload and str(payload.get("response", "")).lower() in {"error", "failed"}:
            raise GrandstreamApiError(str(payload))

        return response

    @property
    def _use_passcode_call_api(self) -> bool:
        return self.call_api_use_passcode and bool(self._effective_passcode)

    @property
    def _effective_passcode(self) -> str | None:
        configured = (self.call_api_passcode or "").strip()
        if configured:
            return configured
        # Most deployments use the same web login password for passcode APIs.
        fallback = self.password.strip()
        return fallback or None

    @property
    def _call_api_auth_params(self) -> dict[str, str]:
        passcode = self._effective_passcode
        if not passcode:
            return {}
        return {
            "passcode": passcode,
            "hs": "1" if self.call_api_hs else "0",
        }

    async def async_login(self) -> None:
        """Authenticate using common Grandstream login field names."""
        async with self._login_lock:
            last_error: Exception | None = None

            # Match stock UI flow on newer firmware.
            try:
                preflight_response = await self.session.get(
                    f"{self.base_url}{API_WILL_LOGIN_PATH}",
                    headers=self._default_headers,
                    timeout=10,
                )
                self._remember_response_cookies(preflight_response)
            except ClientError:
                pass

            def _hash(value: str, algorithm: str) -> str:
                payload = value.encode("utf-8")
                if algorithm == "sha256":
                    return hashlib.sha256(payload).hexdigest()
                return hashlib.md5(payload).hexdigest()

            def _build_access_candidates(username: str) -> list[tuple[str, str]]:
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
                        self._remember_response_cookies(access_response)
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
                            self._remember_response_cookies(response)

                            if response.status >= 400:
                                last_error = GrandstreamApiError(f"Login failed HTTP {response.status}")
                                continue

                            payload = await self._extract_payload(response, raise_on_invalid=False)
                            if payload and str(payload.get("response", "")).lower() == "error":
                                body = str(payload.get("body", "login error"))
                                last_error = GrandstreamApiError(f"Login failed: {body}")
                                _LOGGER.debug(
                                    "Grandstream login attempt failed (%s/%s): %s",
                                    access_variant_name,
                                    pass_variant_name,
                                    body,
                                )
                                continue

                            if payload:
                                sid = payload.get("sid") or payload.get("session_id")
                                if not sid and isinstance(payload.get("body"), dict):
                                    sid = payload["body"].get("sid") or payload["body"].get("session_id")
                                if sid:
                                    self._sid = str(sid)
                                    self.session.cookie_jar.update_cookies(
                                        {"sid": self._sid},
                                        response.url if response.url.host else URL(f"{self.base_url}/"),
                                    )

                            if self._effective_sid:
                                await self._async_post_login_refresh()
                                _LOGGER.debug(
                                    "Grandstream login succeeded using %s/%s",
                                    access_variant_name,
                                    pass_variant_name,
                                )
                                return

                            last_error = GrandstreamApiError("Login response did not include SID")
                    except ClientError as err:
                        last_error = err
                        continue

            raise GrandstreamApiError(
                f"Login failed: {last_error or 'invalid credentials or unsupported firmware'}"
            )

    def _remember_response_cookies(self, response: ClientResponse) -> None:
        """Persist all response cookies, including IP-host cookies."""
        if not response.cookies:
            return
        cookie_values = {name: morsel.value for name, morsel in response.cookies.items()}
        if not cookie_values:
            return
        cookie_url = response.url if response.url.host else URL(f"{self.base_url}/")
        self.session.cookie_jar.update_cookies(cookie_values, cookie_url)
        if "sid" in cookie_values and cookie_values["sid"]:
            self._sid = cookie_values["sid"]

    async def _async_post_login_refresh(self) -> None:
        """Finalize session similarly to web app after successful login."""
        sid = self._effective_sid
        if not sid:
            return
        try:
            await self.session.post(
                f"{self.base_url}{API_DO_REFRESH_PATH}",
                data={"sid": sid},
                headers=self._default_headers,
                timeout=10,
            )
        except ClientError:
            # Some firmware may not require or support dorefresh here.
            return

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


def _normalize_pvalues(values: dict[str, str]) -> dict[str, str]:
    """Convert P-style keys (e.g. P8310) to config_update format (8310)."""
    normalized: dict[str, str] = {}
    for key, value in values.items():
        raw_key = str(key).strip()
        if not raw_key:
            continue
        normalized_key = raw_key[1:] if raw_key.startswith("P") else raw_key
        normalized[normalized_key] = str(value)
    return normalized
