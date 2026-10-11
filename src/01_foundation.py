# --- bundled from main.py ---
# --- bundled from greenpass.foundation.py ---
__id__ = "GreenPass"
__name__ = "GreenPass"
__description__ = "Практически универсальный прокси плагин, поддержка протоколов vless/vmess/hysteria2/etc., встроенные tg-ws-proxy, AmneziaWG и olcrtc, а также полноценнымм проксированием звонков"
__author__ = "@mm1vs"
__version__ = "2.5.7"
__icon__ = "bratpass/0"
__app_version__ = ">=12.5.1"
__sdk_version__ = ">=1.4.4.3"


import base64
import ctypes
import io
import json
import threading
import urllib.request
import urllib.error
import urllib.parse
import time
import ssl
import random
import re
import os
import gzip
import lzma
import hashlib
import hmac
import socket
import struct
import sys
import types
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from base_plugin import BasePlugin, AppEvent, MethodHook, MenuItemData, MenuItemType
from ui.bulletin import BulletinHelper as _BulletinHelper
from ui.alert import AlertDialogBuilder as _AlertDialogBuilder
from ui.settings import Header as _Header, Text as _Text, Divider, Selector as _Selector, Switch as _Switch, EditText as _EditText
from ui.settings import Custom as _Custom
from android_utils import run_on_ui_thread
from client_utils import get_last_fragment, send_document
from hook_utils import find_class
try:
    # SDK 1.4.5.0+: explicit account targeting for client_utils helpers.
    from client_utils import get_selected_account
except:
    get_selected_account = None
_elyx_get_environment = None
try:
    from java import jclass, dynamic_proxy
except:
    jclass = None
    dynamic_proxy = None
try:
    from java.lang import Integer
except:
    Integer = None
from java.util import Locale
from org.telegram.messenger import NotificationCenter, SharedConfig, MessagesController, UserConfig, ApplicationLoader, LocaleController, AndroidUtilities
from org.telegram.messenger.browser import Browser
from org.telegram.tgnet import ConnectionsManager
from org.telegram.ui.ActionBar import Theme
from org.telegram.ui.Components import LineProgressView
from android.graphics.drawable import GradientDrawable
from android.util import TypedValue
from android.view import View, ViewGroup, Gravity
from android.widget import FrameLayout, ImageView, LinearLayout, TextView
try:
    from javax.crypto import Cipher as JavaCipher
    from javax.crypto.spec import SecretKeySpec, IvParameterSpec
except:
    JavaCipher = None
    SecretKeySpec = None


def _is_elyx_runtime():
    if _elyx_get_environment is not None:
        try:
            _elyx_get_environment()
            return True
        except:
            pass
    try:
        path = os.path.abspath(str(__file__ or ""))
        normalized = path.replace("\\", "/").lower()
        if "/elyxplugins/" in normalized:
            return True
        parent = os.path.dirname(path)
        for _ in range(4):
            if any(os.path.isfile(os.path.join(parent, name)) for name in ("refmap.yml", "refmap.yaml", "refmap.json")):
                return True
            parent = os.path.dirname(parent)
    except:
        pass
    return False


def _selected_account():
    if get_selected_account is not None:
        try:
            return int(get_selected_account())
        except:
            pass
    try:
        return int(UserConfig.selectedAccount)
    except:
        return 0


def _send_document_as(account, peer, path, **kwargs):
    # Older SDKs have no account= and always send from the selected account.
    if get_selected_account is not None:
        return send_document(peer, path, account=account, **kwargs)
    return send_document(peer, path, **kwargs)

