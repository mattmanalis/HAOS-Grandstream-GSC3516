"""Constants for Grandstream GSC3516 integration."""

from __future__ import annotations

DOMAIN = "grandstream_gsc3516"

CONF_USE_HTTPS = "use_https"
CONF_VERIFY_SSL = "verify_ssl"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_STATUS_KEYS = "status_keys"
CONF_VOLUME_PVALUE = "volume_pvalue"
CONF_MUTE_PVALUE = "mute_pvalue"
CONF_MUTE_TRUE_VALUE = "mute_true_value"
CONF_MUTE_FALSE_VALUE = "mute_false_value"
CONF_SIP_REGISTERED_KEY = "sip_registered_key"
CONF_SIP_REGISTERED_ON_VALUES = "sip_registered_on_values"
CONF_CALL_STATUS_KEY = "call_status_key"
CONF_CALL_ACTIVE_VALUES = "call_active_values"
CONF_CALL_RINGING_VALUES = "call_ringing_values"
CONF_DIAL_NUMBER_PVALUE = "dial_number_pvalue"
CONF_DIAL_TRIGGER_PVALUE = "dial_trigger_pvalue"
CONF_DIAL_TRIGGER_VALUE = "dial_trigger_value"
CONF_HANGUP_PVALUE = "hangup_pvalue"
CONF_HANGUP_VALUE = "hangup_value"
CONF_USE_CALL_API = "use_call_api"
CONF_CALL_API_ACCOUNT = "call_api_account"
CONF_CALL_API_DIALPLAN = "call_api_dialplan"
CONF_API_SID = "api_sid"

DEFAULT_PORT_HTTP = 80
DEFAULT_PORT_HTTPS = 443
DEFAULT_USE_HTTPS = False
DEFAULT_VERIFY_SSL = False
DEFAULT_SCAN_INTERVAL = 30
DEFAULT_STATUS_KEYS = "vendor_fullname:product_model:prog_version:sys_uptime:ip:mac"
DEFAULT_MUTE_TRUE_VALUE = "1"
DEFAULT_MUTE_FALSE_VALUE = "0"
DEFAULT_SIP_REGISTERED_ON_VALUES = "1,registered,true,ok"
DEFAULT_CALL_ACTIVE_VALUES = "in_call,on_call,active,connected,talking,busy"
DEFAULT_CALL_RINGING_VALUES = "ringing,incoming"
DEFAULT_DIAL_TRIGGER_VALUE = "1"
DEFAULT_HANGUP_VALUE = "1"
DEFAULT_USE_CALL_API = True
DEFAULT_CALL_API_ACCOUNT = 0
DEFAULT_CALL_API_DIALPLAN = "dialing"

PLATFORMS = ["media_player", "sensor", "binary_sensor"]

API_LOGIN_PATH = "/cgi-bin/dologin"
API_ACCESS_PATH = "/cgi-bin/access"
API_WILL_LOGIN_PATH = "/cgi-bin/api-will_login"
API_DO_REFRESH_PATH = "/cgi-bin/dorefresh"
API_VALUES_GET_PATH = "/cgi-bin/api.values.get"
API_VALUES_POST_PATH = "/cgi-bin/api.values.post"
API_GET_LINE_STATUS_PATH = "/cgi-bin/api-get_line_status"
API_GET_PHONE_STATUS_PATH = "/cgi-bin/api-get_phone_status"
API_LIST_BS_ACCOUNTS_PATH = "/cgi-bin/api-list_bs_accounts"
API_MAKE_CALL_PATH = "/cgi-bin/api-make_call"
API_PHONE_OPERATION_PATH = "/cgi-bin/api-phone_operation"

# Try common login field names used by Grandstream web UIs.
LOGIN_USERNAME_FIELDS = ("username", "P3", "user_name")
LOGIN_PASSWORD_FIELD = "password"

COORDINATOR_KEY_STATUS = "status"
COORDINATOR_KEY_ONLINE = "online"
COORDINATOR_KEY_LINE_STATUS = "line_status"
COORDINATOR_KEY_PHONE_STATUS = "phone_status"
COORDINATOR_KEY_ACCOUNTS = "accounts"

SERVICE_DIAL = "dial"
SERVICE_HANGUP = "hangup"

ATTR_ENTRY_ID = "entry_id"
ATTR_NUMBER = "number"
