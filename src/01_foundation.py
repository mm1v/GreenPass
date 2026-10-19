# --- bundled from main.py ---
# --- bundled from greenpass.foundation.py ---
__id__ = "GreenPass"
__name__ = "GreenPass"
__description__ = "Практически универсальный прокси плагин, поддержка протоколов vless/vmess/hysteria2/etc., встроенные tg-ws-proxy, AmneziaWG и olcrtc, а также полноценнымм проксированием звонков"
__author__ = "@mm1vs"
__version__ = "3.0.0"
__icon__ = "monek_icons/0"
__app_version__ = ">=12.5.1"
__sdk_version__ = ">=1.4.5.3"


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
import traceback
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


_DIAGNOSTIC_LOG_RING = []
_DIAGNOSTIC_LOG_LOCK = threading.Lock()
_PERSISTENT_LOG_FILE = None


def _get_persistent_log_path():
    global _PERSISTENT_LOG_FILE
    if _PERSISTENT_LOG_FILE:
        return _PERSISTENT_LOG_FILE
    try:
        base_dir = ""
        try:
            AU = find_class("org.telegram.messenger.ApplicationLoader")
            ctx = AU.applicationContext if AU else None
            if ctx:
                base_dir = ctx.getCacheDir().getAbsolutePath()
        except:
            base_dir = ""
        if not base_dir:
            base_dir = "."
        _PERSISTENT_LOG_FILE = os.path.join(base_dir, "greenpass_runtime.log")
        return _PERSISTENT_LOG_FILE
    except:
        return None


def _log_diag(level, message, exc=None):
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        err_extra = ""
        if exc is not None:
            try:
                tb = traceback.format_exc()
                if tb and tb.strip() != "NoneType: None":
                    err_extra = f"\n{tb.strip()}"
                else:
                    err_extra = f" ({exc})"
            except:
                err_extra = f" ({exc})"
        entry = f"[{ts}] [{str(level or 'INFO').upper()}] {str(message or '')}{err_extra}"
        with _DIAGNOSTIC_LOG_LOCK:
            _DIAGNOSTIC_LOG_RING.append(entry)
            if len(_DIAGNOSTIC_LOG_RING) > 200:
                _DIAGNOSTIC_LOG_RING.pop(0)

        path = _get_persistent_log_path()
        if path:
            try:
                if os.path.exists(path) and os.path.getsize(path) > 512 * 1024:
                    try:
                        old_path = path + ".old"
                        if os.path.exists(old_path):
                            os.remove(old_path)
                        os.rename(path, old_path)
                    except:
                        pass
                with open(path, "a", encoding="utf-8") as f:
                    f.write(entry + "\n")
            except:
                pass
    except:
        pass


def _get_diagnostic_events_text():
    try:
        events = []
        path = _get_persistent_log_path()
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    events = [line.rstrip() for line in f.readlines() if line.strip()]
                    if len(events) > 300:
                        events = events[-300:]
            except:
                pass
        if not events:
            with _DIAGNOSTIC_LOG_LOCK:
                events = list(_DIAGNOSTIC_LOG_RING)
        return "\n".join(events)
    except:
        return ""


def _gp_is_ui_thread():
    try:
        from android.os import Looper
        return bool(Looper.myLooper() == Looper.getMainLooper())
    except Exception:
        return threading.current_thread() is threading.main_thread()


def _gp_run_on_ui_wait(fn, timeout=3.0):
    """Run fn on the UI thread and wait for it, at most `timeout` seconds.

    Returns (completed, result). Called on the UI thread it just runs fn. If the
    wait times out before the UI thread started fn, fn is cancelled and will not
    run later. Never raises.
    """
    if _gp_is_ui_thread():
        try:
            return True, fn()
        except Exception:
            return True, None
    done = threading.Event()
    state = {"cancel": False, "started": False, "result": None}
    guard = threading.Lock()

    def _run():
        with guard:
            if state["cancel"]:
                return
            state["started"] = True
        try:
            state["result"] = fn()
        except Exception:
            state["result"] = None
        finally:
            done.set()

    try:
        run_on_ui_thread(_run)
    except Exception:
        return False, None
    if done.wait(float(timeout)):
        return True, state["result"]
    with guard:
        if not state["started"]:
            state["cancel"] = True
            return False, None
    # fn is already running on the UI thread; give it a short grace period.
    if done.wait(1.0):
        return True, state["result"]
    return False, None


def _gp_bulletin(method, text, args, kwargs):
    # Bulletins touch views: worker threads must post them to the UI thread.
    try:
        label = Z(text)
    except Exception:
        label = str(text or "")

    def _show():
        try:
            return method(label, *args, **kwargs)
        except Exception:
            return None

    if _gp_is_ui_thread():
        return _show()
    try:
        run_on_ui_thread(_show)
    except Exception:
        pass
    return None



