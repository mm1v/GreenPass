# --- bundled from greenpass.modes.singbox.py ---


class SingBoxModeMixin:
    def _libvless_so_path(self):
        return self._libsingbox_so_path()

    def _libsingbox_so_path(self):
        try:
            return os.path.join(self._vless_dir, SINGBOX_SO_FILE)
        except:
            return SINGBOX_SO_FILE

    def _libsingbox_lock_obj(self):
        lock = getattr(self, "_libsingbox_validation_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._libsingbox_validation_lock = lock
        return lock

    @staticmethod
    def _libsingbox_verified_path(path):
        return str(path) + ".verified"

    def _libsingbox_cached_validity(self, cache_key):
        """True/False when the integrity of this exact file (path, size, mtime) is known, else None.

        Only tiny sections run under the lock; the 126 MB hash never does. Known results
        live in the instance, in the process (they survive a plugin reload) and in a small
        <so>.verified file, so a cold start does not hash the library again."""
        lock = self._libsingbox_lock_obj()
        with lock:
            cached = self._libsingbox_validation_cache
            if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == cache_key:
                return bool(cached[1])
        try:
            known = getattr(_GP_PROCESS_STATE, "so_validity", None)
            if isinstance(known, dict) and cache_key in known:
                valid = bool(known[cache_key])
                with lock:
                    self._libsingbox_validation_cache = (cache_key, valid)
                return valid
        except Exception:
            pass
        try:
            with open(self._libsingbox_verified_path(cache_key[0]), "r") as handle:
                record = json.load(handle)
            if (
                isinstance(record, dict)
                and int(record.get("size", -1)) == int(cache_key[1])
                and int(record.get("mtime_ns", -1)) == int(cache_key[2])
                and str(record.get("sha256", "")) == str(SINGBOX_SO_SHA256)
            ):
                self._libsingbox_store_validity(cache_key, True, persist=False)
                return True
        except Exception:
            pass
        return None

    def _libsingbox_store_validity(self, cache_key, valid, persist=True):
        valid = bool(valid)
        lock = self._libsingbox_lock_obj()
        with lock:
            self._libsingbox_validation_cache = (cache_key, valid)
            # A file of the expected size whose hash differs is corrupt, not just an
            # older build (older builds differ in size): never dlopen that one.
            self._libsingbox_corrupt_key = None if valid else cache_key
        try:
            known = getattr(_GP_PROCESS_STATE, "so_validity", None)
            if not isinstance(known, dict):
                known = {}
                _GP_PROCESS_STATE.so_validity = known
            known[cache_key] = valid
        except Exception:
            pass
        if valid and persist:
            try:
                tmp = "%s.%d.tmp" % (self._libsingbox_verified_path(cache_key[0]), threading.get_ident())
                with open(tmp, "w") as handle:
                    json.dump({"size": int(cache_key[1]), "mtime_ns": int(cache_key[2]), "sha256": str(SINGBOX_SO_SHA256)}, handle)
                os.replace(tmp, self._libsingbox_verified_path(cache_key[0]))
            except Exception:
                pass

    @staticmethod
    def _libsingbox_cache_key(path):
        stat = os.stat(path)
        return (str(path), int(stat.st_size), int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1000000000)))), int(stat.st_size)

    def _libsingbox_prime_validity(self, path):
        """The caller just verified this file (hash checked while unpacking): record it."""
        try:
            cache_key, size = self._libsingbox_cache_key(path)
            if int(size) == int(SINGBOX_SO_SIZE):
                self._libsingbox_store_validity(cache_key, True)
                return True
        except Exception:
            pass
        self._libsingbox_validation_cache = None
        return False

    def _libsingbox_is_corrupt(self):
        """Right size but wrong hash: a damaged file that must not be mapped."""
        try:
            cache_key, _ = self._libsingbox_cache_key(self._libsingbox_so_path())
            return getattr(self, "_libsingbox_corrupt_key", None) == cache_key
        except Exception:
            return False

    def _libsingbox_core_load_allowed(self):
        """Call off the UI thread. False when dlopen of the file on disk is unsafe."""
        try:
            if _gp_core_loaded_in_process():
                return True
            if self._libsingbox_addon_status() != "outdated":
                return True
            return not self._libsingbox_is_corrupt()
        except Exception:
            return True

    def _core_needs_restart_notice(self):
        """The library on disk is not the one this process already runs: a second Go
        runtime would crash it, so only an app restart can switch."""
        try:
            if not (_gp_core_loaded_in_process() and bool(getattr(_GP_PROCESS_STATE, "go_core_blocked", False))):
                return False
            if not self._core_restart_required():
                self._mark_core_restart_required()
            return True
        except Exception:
            return False

    def _libsingbox_addon_status(self, quick=False):
        if not SINGBOX_BUNDLE_FILE:
            return "missing"
        try:
            path = self._libsingbox_so_path()
            if not path or not os.path.exists(path):
                return "missing"
            stat = os.stat(path)
            if int(stat.st_size) < 1024:
                return "missing"
            if int(stat.st_size) != int(SINGBOX_SO_SIZE):
                return "outdated"
            cache_key, _ = self._libsingbox_cache_key(path)
            lock = self._libsingbox_lock_obj()
            cached = self._libsingbox_cached_validity(cache_key)
            if cached is not None:
                return "current" if cached else "outdated"

            if quick:
                should_start = False
                try:
                    with lock:
                        if not bool(getattr(self, "_libsingbox_validation_in_progress", False)):
                            self._libsingbox_validation_in_progress = True
                            should_start = True
                except:
                    pass
                if should_start:
                    def _validate_in_background():
                        status = "missing"
                        try:
                            status = self._libsingbox_addon_status()
                        finally:
                            try:
                                with lock:
                                    self._libsingbox_validation_in_progress = False
                            except:
                                pass
                            try:
                                run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                            except:
                                pass
                        if status in ("missing", "outdated") and self._core_autoupdate_enabled():
                            try:
                                self._update_outdated_core_in_background()
                            except:
                                pass
                    threading.Thread(target=_validate_in_background, daemon=True).start()
                return "checking"

            # Hashing is serialized by its own lock, never by the cache lock the UI thread uses.
            hash_lock = getattr(self, "_libsingbox_hash_lock", None)
            if hash_lock is None:
                hash_lock = threading.Lock()
                self._libsingbox_hash_lock = hash_lock
            with hash_lock:
                cached = self._libsingbox_cached_validity(cache_key)
                if cached is not None:
                    return "current" if cached else "outdated"
                digest, size = self._sha256_file(path, max_bytes=int(SINGBOX_SO_SIZE))
                valid = bool(size == int(SINGBOX_SO_SIZE) and digest == SINGBOX_SO_SHA256)
                self._libsingbox_store_validity(cache_key, valid)
                return "current" if valid else "outdated"
        except:
            return "missing"

    def _has_libsingbox_addon(self):
        # quick: "checking" counts as present, so no caller (UI included) waits for a hash.
        return self._libsingbox_addon_status(quick=True) != "missing"

    def _vless_disconnect_with_reason(self, reason, silent=False):
        self._vless_disconnect(silent=bool(silent))

    def _vless_engine_index(self):
        return 1 if self._effective_vless_engine() == VLESS_ENGINE_MIHOMO else 0

    def _vless_auto_subscription_nodes(self, uri=None):
        node = self._find_vless_node(uri if uri is not None else self._get_active_vless_uri())
        hidden = self._vless_browser_hidden_sources()
        all_nodes = [item for item in list((node or {}).get("balance_nodes", []) or []) if isinstance(item, dict)]
        nodes = [item for item in all_nodes if self._vless_browser_source_key(item) not in hidden]
        if not nodes and all_nodes:
            # Every source is hidden: an empty Автовыбор would never connect again.
            nodes = all_nodes
            self._notify_all_sources_hidden()
        # ExitFy exposes failover as an explicit opt-in.  Keep the automatic
        # route deterministic when it is disabled instead of silently
        # rotating through every subscription node.
        if not self._vless_browser_failover_enabled() and nodes:
            return nodes[:1]
        return nodes


    def _vless_ping_value(self, node):
        try:
            return int(node.get("ping", -1) or 0)
        except:
            return -1

    def _vless_ping_checked_at(self, node):
        try:
            return float(node.get("ping_checked_at", 0.0) or 0.0)
        except:
            return 0.0

    def _vless_ping_badge(self, node):
        ping = self._vless_ping_value(node)
        checked_at = self._vless_ping_checked_at(node)
        if checked_at <= 0 or (time.time() - float(checked_at)) > float(VLESS_NODE_PING_STALE_SEC):
            return ""
        if ping <= 0 or ping >= 9999:
            return "нет"
        return f"{int(ping)} ms"

    def _vless_sort_key(self, node):
        checked_at = self._vless_ping_checked_at(node)
        ping = self._vless_ping_value(node)
        stale = checked_at <= 0 or (time.time() - float(checked_at)) > float(VLESS_NODE_PING_STALE_SEC)
        if stale or ping < 0:
            rank = 2
            score = 999999
        elif ping <= 0 or ping >= 9999:
            rank = 1
            score = 999998
        else:
            rank = 0
            score = int(ping)
        try:
            name = str(node.get("name", "") or "").strip().lower()
        except:
            name = ""
        return (rank, score, name)

    # ExitFy-style server browser primitives.  Keep the browser state in the
    # plugin settings instead of the node records so subscription refreshes do
    # not accidentally reset the user's filters/visibility choices.
    def _vless_browser_page_size(self):
        try:
            value = int(self.get_setting("vless_browser_page_size", 20) or 20)
        except:
            value = 20
        return max(5, min(100, value))

    def _set_vless_browser_page_size(self, value):
        try:
            value = int(value)
        except:
            value = 20
        value = max(5, min(100, value))
        try:
            self._set_setting_value("vless_browser_page_size", value, reload_settings=False)
        except:
            try:
                self.set_setting("vless_browser_page_size", value, reload_settings=False)
            except:
                return False
        return value

    def _vless_browser_auto_check_minutes(self):
        """Return periodic latency-check interval; zero means disabled."""
        try:
            value = int(self.get_setting("vless_auto_check_minutes", 0) or 0)
        except:
            value = 0
        return max(0, min(60, value))

    def _set_vless_browser_auto_check_minutes(self, value):
        try:
            value = int(value)
        except:
            value = 0
        value = max(0, min(60, value))
        try:
            self._set_setting_value("vless_auto_check_minutes", value, reload_settings=False)
        except:
            try:
                self.set_setting("vless_auto_check_minutes", value, reload_settings=False)
            except:
                return False
        return value

    def _vless_browser_failover_enabled(self):
        try:
            raw = self.get_setting("vless_failover_enabled", True)
            if isinstance(raw, str):
                return raw.strip().lower() not in ("", "0", "false", "off", "no")
            return bool(raw)
        except:
            return True

    def _set_vless_browser_failover_enabled(self, enabled):
        value = bool(enabled)
        try:
            self._set_setting_value("vless_failover_enabled", value, reload_settings=False)
        except:
            try:
                self.set_setting("vless_failover_enabled", value, reload_settings=False)
            except:
                return False
        return value

    def _vless_browser_hidden_sources(self):
        """Read hidden source keys as a tolerant set (old clients may return JSON)."""
        try:
            raw = self.get_setting("vless_browser_hidden_sources", "[]")
        except:
            raw = "[]"
        if isinstance(raw, (list, tuple, set)):
            values = raw
        else:
            try:
                values = json.loads(str(raw or "[]"))
            except:
                values = []
        return {str(item or "").strip() for item in list(values or []) if str(item or "").strip()}

    def _set_vless_browser_hidden_sources(self, sources):
        values = sorted({str(item or "").strip() for item in list(sources or []) if str(item or "").strip()})
        payload = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
        try:
            self._set_setting_value("vless_browser_hidden_sources", payload, reload_settings=False)
        except:
            try:
                self.set_setting("vless_browser_hidden_sources", payload, reload_settings=False)
            except:
                return False
        return values

    def _vless_browser_source_for_node(self, node):
        """Return stable source metadata for a node, including manual nodes."""
        node = node if isinstance(node, dict) else {}
        uri = str(node.get("uri", "") or "").strip()
        explicit_url = str(
            node.get("subscription_url", "")
            or node.get("source_url", "")
            or node.get("provider_url", "")
            or ""
        ).strip()
        if explicit_url:
            try:
                source = self._vless_browser_source_index().get("\x00" + explicit_url)
                if source:
                    return dict(source)
            except:
                pass
        # Subscription ownership is queried for every row while building the
        # settings page. Resolve it once per config snapshot; the old nested
        # scan made opening a large subscription quadratic and blocked the UI.
        if uri:
            try:
                source = self._vless_browser_source_index().get(uri)
                if source:
                    return dict(source)
            except:
                pass
        # Balancer wrappers often carry no source metadata themselves; inherit
        # the first concrete subscription source from their children.
        try:
            for child in list(node.get("balance_nodes", []) or []):
                if not isinstance(child, dict):
                    continue
                child_source = self._vless_browser_source_for_node(child)
                if not bool(child_source.get("manual", False)) and str(child_source.get("key", "") or ""):
                    return child_source
        except:
            pass
        source_name = str(node.get("source_name", "") or node.get("provider", "") or "").strip()
        source_url = explicit_url or str(node.get("source", "") or "").strip()
        if source_name or source_url:
            key = source_url or source_name
            return {"key": key, "name": source_name or source_url, "url": source_url, "manual": False}
        return {"key": "__manual__", "name": "Свои узлы", "url": "", "manual": True}

    def _vless_browser_source_index(self):
        """Map node URIs to their subscription without repeated nested scans."""
        data = getattr(self, "_vless_data", None)
        cached = getattr(self, "_vless_browser_source_index_cache", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] is data:
            return cached[1]

        index = {}

        def _walk(node, source):
            if not isinstance(node, dict):
                return
            uri = str(node.get("uri", "") or "").strip()
            if uri and uri not in index:
                index[uri] = source
            for child in list(node.get("balance_nodes", []) or []):
                _walk(child, source)

        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                url = str(sub.get("url", "") or "").strip()
                if not url:
                    continue
                source = {
                    "key": url,
                    "name": str(sub.get("name", "") or "").strip() or url,
                    "url": url,
                    "manual": False,
                }
                index["\x00" + url] = source
                for node in list(sub.get("nodes", []) or []):
                    _walk(node, source)
        except:
            pass
        self._vless_browser_source_index_cache = (data, index)
        return index

    def _vless_browser_source_key(self, node):
        try:
            return str(self._vless_browser_source_for_node(node).get("key", "") or "")
        except:
            return "__manual__"

    def _vless_browser_leaf_nodes(self, node):
        """Yield endpoint leaves so balancer wrappers do not hide their count."""
        if not isinstance(node, dict):
            return
        children = [item for item in list(node.get("balance_nodes", []) or []) if isinstance(item, dict)]
        if not children:
            yield node
            return
        for child in children:
            yield from self._vless_browser_leaf_nodes(child)

    def _vless_browser_sources(self, include_hidden=True):
        """Return source rows suitable for a provider filter/visibility screen."""
        rows = {}
        for root in self._get_all_vless_nodes():
            for node in self._vless_browser_leaf_nodes(root):
                source = self._vless_browser_source_for_node(node)
                key = str(source.get("key", "") or "")
                if not key:
                    continue
                row = rows.get(key)
                if row is None:
                    row = dict(source)
                    row["count"] = 0
                    rows[key] = row
                row["count"] = int(row.get("count", 0) or 0) + 1
        hidden = self._vless_browser_hidden_sources()
        result = []
        for row in rows.values():
            row["hidden"] = str(row.get("key", "") or "") in hidden
            if include_hidden or not row["hidden"]:
                result.append(row)
        result.sort(key=lambda item: (str(item.get("name", "") or "").lower(), str(item.get("key", "") or "")))
        return result

    def _vless_set_browser_source_visible(self, source_key, visible):
        key = str(source_key or "").strip()
        if not key:
            return False
        hidden = self._vless_browser_hidden_sources()
        if bool(visible):
            hidden.discard(key)
        else:
            hidden.add(key)
        self._set_vless_browser_hidden_sources(hidden)
        return True

    def _vless_browser_protocol(self, node):
        node = node if isinstance(node, dict) else {}
        kind = str(node.get("kind", "") or "").strip().lower()
        if not kind:
            try:
                kind = str(_proxy_uri_scheme(node.get("uri", "")) or "").lower()
            except:
                kind = ""
        aliases = {
            "shadowsocks": "ss",
            "hysteria": "hysteria2",
            "singbox-config": "sing-box",
            "mihomo-config": "mihomo",
        }
        return aliases.get(kind, kind or "unknown")

    def _vless_browser_normalize_protocol(self, value):
        value = str(value or "").strip().lower().replace("_", "-")
        aliases = {
            "shadowsocks": "ss",
            "hysteria": "hysteria2",
            "hysteria-2": "hysteria2",
            "singbox": "sing-box",
            "sing-box-config": "sing-box",
            "mihomo-config": "mihomo",
        }
        return aliases.get(value, value)

    def _vless_browser_filter_nodes(self, query="", protocol="", source="", include_hidden=False):
        query = str(query or "").strip().lower()
        protocol = self._vless_browser_normalize_protocol(protocol)
        source = str(source or "").strip()
        hidden = self._vless_browser_hidden_sources()
        cache_key = (
            id(getattr(self, "_vless_data", None)),
            query,
            protocol,
            source,
            bool(include_hidden),
            tuple(sorted(hidden)),
        )
        cached = getattr(self, "_vless_browser_filter_cache", None)
        if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == cache_key:
            return list(cached[1])
        result = []
        seen = set()
        for node in self._get_all_vless_nodes():
            if not isinstance(node, dict):
                continue
            uri = str(node.get("uri", "") or "").strip()
            dedup = _proxy_uri_dedup_key(uri) or uri
            if not dedup or dedup in seen:
                continue
            seen.add(dedup)
            source_row = self._vless_browser_source_for_node(node)
            source_key = str(source_row.get("key", "") or "")
            if source and source_key != source:
                continue
            if (not include_hidden) and source_key in hidden:
                continue
            node_protocol = self._vless_browser_protocol(node)
            if protocol and node_protocol != protocol:
                continue
            if query:
                haystack = " ".join(
                    str(node.get(name, "") or "")
                    for name in ("name", "server", "uri", "network", "security", "method")
                )
                haystack += " " + str(source_row.get("name", "") or "") + " " + node_protocol
                if query not in haystack.lower():
                    continue
            result.append(node)
        result = self._sorted_vless_nodes(result)
        self._vless_browser_filter_cache = (cache_key, list(result))
        return result

    def _vless_browser_snapshot(self, query="", protocol="", source="", page=0, page_size=None, include_hidden=False):
        """Return one deterministic page and metadata for the ExitFy-like browser."""
        nodes = self._vless_browser_filter_nodes(query, protocol, source, include_hidden=include_hidden)
        try:
            size = int(page_size or self._vless_browser_page_size())
        except:
            size = self._vless_browser_page_size()
        size = max(5, min(100, size))
        try:
            page = max(0, int(page or 0))
        except:
            page = 0
        total = len(nodes)
        pages = (total + size - 1) // size if total else 0
        if not pages:
            page = 0
        elif page >= pages:
            page = pages - 1
        start = page * size
        return {
            "nodes": nodes[start:start + size],
            "total": total,
            "page": page,
            "page_size": size,
            "pages": pages,
            "has_previous": bool(page > 0),
            "has_next": bool(start + size < total),
            "query": str(query or ""),
            "protocol": str(protocol or ""),
            "source": str(source or ""),
        }

    def _vless_browser_ping_interval_sec(self):
        minutes = self._vless_browser_auto_check_minutes()
        return float(minutes * 60) if minutes > 0 else 0.0

    def _maybe_run_vless_auto_ping(self, now=None):
        """Schedule one quiet periodic check; never block the worker loop."""
        interval = self._vless_browser_ping_interval_sec()
        if interval <= 0 or bool(getattr(self, "_vless_backgrounded", False)):
            return False
        try:
            if not self._is_vless_mode_selected() or not self._is_plugin_proxy_enabled():
                return False
        except:
            return False
        try:
            now = float(time.time() if now is None else now)
        except:
            now = time.time()
        lock = getattr(self, "_vless_transition_lock", None)
        try:
            if lock is None:
                return False
            with lock:
                last = float(getattr(self, "_vless_auto_ping_last_ts", 0.0) or 0.0)
                if bool(getattr(self, "_vless_auto_ping_in_progress", False)) or now - last < interval:
                    return False
                self._vless_auto_ping_last_ts = now
                self._vless_auto_ping_in_progress = True
        except:
            return False

        def _worker():
            try:
                self._refresh_vless_node_pings(force=True, save=True)
            except:
                pass
            finally:
                try:
                    with lock:
                        self._vless_auto_ping_in_progress = False
                except:
                    pass
                try:
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))
                except:
                    pass

        try:
            threading.Thread(target=_worker, daemon=True).start()
            return True
        except:
            try:
                with lock:
                    self._vless_auto_ping_in_progress = False
            except:
                pass
            return False

    def _is_vless_mode_selected(self):
        return self._get_connection_mode() == VLESS_KIND and bool(self._get_active_vless_uri())

    def _vless_save_data(self):
        try:
            self._vless_data["active_uri"] = str(self._vless_data.get("active_uri", "") or "")
        except:
            self._vless_data = {"manual": [], "subs": [], "active_uri": ""}
        self._vless_browser_source_index_cache = None
        self._vless_browser_filter_cache = None
        self._save_config()

    def _vless_provider_name(self, idx):
        try:
            provider_idx = int(idx or 0)
        except:
            provider_idx = 0
        if provider_idx == 0:
            return "Текущий"
        if provider_idx < 0 or provider_idx >= len(VLESS_PROVIDER_ITEMS):
            provider_idx = 0
        try:
            return str(VLESS_PROVIDER_ITEMS[provider_idx] or "")
        except:
            return ""

    def _vless_apply_tg_proxy(self, port, enable, username="", password=""):
        result = self._apply_local_socks_proxy(
            port,
            enable,
            owner=str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND),
            username=username,
            password=password,
        )
        return result

    def _vless_runtime_config_key(self, uri=None, node=None, auto_nodes=None):
        engine_prefix = self._effective_vless_engine(node if isinstance(node, dict) else None) + ":"
        try:
            nodes = list(auto_nodes or [])
        except:
            nodes = []
        if len(nodes) > 1:
            values = []
            seen = set()
            for candidate in nodes:
                if not isinstance(candidate, dict):
                    continue
                try:
                    kind = str(candidate.get("kind", "") or "").strip().lower()
                    if kind == "singbox-config":
                        value = str(candidate.get("raw_config", "") or "")
                    else:
                        value = str(candidate.get("uri", "") or "")
                    key = _proxy_uri_dedup_key(value) or value
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    values.append(kind + ":" + value)
                except:
                    continue
            if len(values) > 1:
                try:
                    return engine_prefix + "auto:" + hashlib.sha256("\n".join(values).encode("utf-8", errors="ignore")).hexdigest()
                except:
                    return engine_prefix + "auto:" + "|".join(values)
        try:
            node = node if isinstance(node, dict) else None
            kind = str((node or {}).get("kind", "") or "").strip().lower()
            if kind == "singbox-config":
                raw = str((node or {}).get("raw_config", "") or "")
                if raw:
                    return "singbox-config:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
            if kind == "mihomo-config":
                raw = str((node or {}).get("raw_config", "") or "")
                if raw:
                    return "mihomo-config:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
        except:
            pass
        try:
            value = str(uri if uri is not None else self._get_active_vless_uri() or "")
        except:
            value = ""
        value = _proxy_uri_dedup_key(value) or value
        if not value:
            return ""
        try:
            return engine_prefix + "uri:" + hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
        except:
            return value

    def _is_vless_connection_ready(self, port=None, check_tunnel=False):
        try:
            expected_port = int(port or self._vless_port or 0)
        except:
            expected_port = 0
        if expected_port <= 0 or not bool(self._vless_running):
            return False
        username = str(getattr(self, "_vless_socks_username", "") or "")
        password = str(getattr(self, "_vless_socks_password", "") or "")
        if not _check_vless_socks_ready(expected_port, timeout=0.5, username=username, password=password):
            return False
        if not self._is_local_vless_proxy_applied(expected_port):
            return False
        if bool(check_tunnel) and not _check_vless_tunnel_ready(expected_port, timeout=1.0, username=username, password=password):
            return False
        return True

    def _notify_all_sources_hidden(self):
        if getattr(self, "_all_sources_hidden_notified", False):
            return
        self._all_sources_hidden_notified = True
        try:
            run_on_ui_thread(lambda: BulletinHelper.show_info("Все источники скрыты — подключены все узлы"))
        except:
            pass

    def _vless_balancer_nodes(self):
        hidden = self._vless_browser_hidden_sources()
        selected = self._vless_balancer_nodes_for(hidden)
        if not selected and hidden:
            # Fall back to using every available source so the proxy never stays dead.
            selected = self._vless_balancer_nodes_for(set())
            if selected:
                self._notify_all_sources_hidden()
        return selected

    def _vless_balancer_nodes_for(self, hidden):
        groups = []
        for sub in list(self._vless_data.get("subs", []) or []):
            sub_url = str((sub or {}).get("url", "") or "").strip()
            if sub_url and sub_url in hidden:
                continue
            group = []
            for node in list((sub or {}).get("nodes", []) or []):
                children = list((node or {}).get("balance_nodes", []) or [])
                for candidate in (children or [node]):
                    if self._vless_browser_source_key(candidate) not in hidden:
                        group.append(candidate)
            if self._vless_browser_failover_enabled():
                group = self._sorted_vless_nodes(group)
            if group:
                groups.append(group)

        selected = []
        seen = set()
        while groups and len(selected) < VLESS_BALANCER_MAX_NODES:
            remaining = []
            for group in groups:
                node = group.pop(0)
                if group:
                    remaining.append(group)
                uri = str((node or {}).get("uri", "") or "")
                key = _proxy_uri_dedup_key(uri) or uri
                if _proxy_uri_scheme(uri) not in PROXY_PROTOCOL_REGISTRY or not key or key in seen:
                    continue
                seen.add(key)
                selected.append(node)
                if len(selected) >= VLESS_BALANCER_MAX_NODES:
                    break
            groups = remaining
        return selected

    def _set_vless_connection_state(self, connecting=False, error=""):
        connecting = bool(connecting)
        error = str(error or "").strip()
        changed = connecting != bool(getattr(self, "_vless_connecting", False)) or error != str(getattr(self, "_vless_last_error", "") or "")
        self._vless_connecting = connecting
        self._vless_last_error = error
        if changed:
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

    def _ensure_vless_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_vless_mode = runner_name == "_vless_connect"
        if require_vless_mode and (not self._should_run_vless()):
            return
        if self._go_core_switch_blocked("vless"):
            if require_vless_mode:
                self._set_vless_connection_state(False, "Перезапустите приложение для смены ядра")
            return

        def _prepare_and_run():
            # Hashing, dlopen of the ~120 MB library and downloads happen on this
            # worker thread, never on the caller's (possibly UI) thread.
            try:
                self._prepare_vless_core_and_run(runner, require_vless_mode)
            except Exception as exc:
                error_text = "Ошибка прокси: %s" % exc
                if require_vless_mode:
                    self._set_vless_connection_state(False, error_text)

        try:
            threading.Thread(target=_prepare_and_run, daemon=True).start()
        except Exception:
            pass

    def _prepare_vless_core_and_run(self, runner, require_vless_mode):
        if self._libsingbox_core_load_allowed():
            self._vless_core._ensure()
        if self._vless_core.is_available():
            if require_vless_mode and (not self._should_run_vless()):
                return
            runner()
            return
        if self._core_needs_restart_notice():
            if require_vless_mode:
                self._set_vless_connection_state(False, "Перезапустите приложение для нового ядра")
            BulletinHelper.show_info("Ядро обновлено — перезапустите приложение")
            return
        if self._vless_prepare_in_progress:
            return

        self._set_core_download_in_progress(True)
        BulletinHelper.show_info("Скачиваю ядро прокси...")
        try:
            ok = self._download_libvless_with_progress()
            if ok and self._core_restart_required():
                if require_vless_mode:
                    self._set_vless_connection_state(False, "Перезапустите приложение для нового ядра")
                BulletinHelper.show_success("Ядро установлено — перезапустите приложение")
                return
            self._reload_vless_core()
            self._vless_core._ensure()
            if ok and self._vless_core.is_available():
                if require_vless_mode and (not self._should_run_vless()):
                    return
                BulletinHelper.show_success("Ядро прокси готово")
                try:
                    runner()
                except Exception as e:
                    error_text = f"Ошибка прокси: {e}"
                    if require_vless_mode:
                        self._set_vless_connection_state(False, error_text)
                    else:
                        BulletinHelper.show_error(error_text)
            else:
                if require_vless_mode:
                    self._set_vless_connection_state(False, "Не удалось загрузить ядро прокси")
                else:
                    BulletinHelper.show_error("Не удалось загрузить ядро прокси")
        finally:
            self._set_core_download_in_progress(False)

    def _add_vless_manual_node(self, uri):
        node = _proxy_node_from_uri(uri)
        if not node:
            return None
        return self._save_vless_manual_node(node)

    def _vless_connect(self):
        with self._vless_connect_lock:
            if bool(self._vless_connect_worker_active):
                self._vless_connect_pending = True
                return True
            self._vless_connect_worker_active = True
            self._vless_connect_pending = False

        def _worker():
            try:
                while True:
                    with self._vless_connect_lock:
                        self._vless_connect_pending = False
                    self._vless_connect_once()
                    with self._vless_connect_lock:
                        if bool(self._vless_connect_pending) and self._should_run_vless():
                            continue
                        self._vless_connect_worker_active = False
                        return
            except Exception as exc:
                with self._vless_connect_lock:
                    self._vless_connect_worker_active = False
                self._set_vless_connection_state(False, f"Ошибка подключения: {exc}")

        try:
            threading.Thread(target=_worker, daemon=True).start()
            return True
        except:
            with self._vless_connect_lock:
                self._vless_connect_worker_active = False
            self._set_vless_connection_state(False, "Не удалось запустить подключение")
            return False

    def _prune_invalid_auto_nodes(self, nodes, port, username, password):
        good = []
        for node in list(nodes or []):
            try:
                cfg, _ = _build_registered_proxy_config(
                    str((node or {}).get("uri", "") or ""),
                    port,
                    socks_username=username,
                    socks_password=password,
                )
                if not cfg:
                    continue
                if self._validate_core_config_for_import(cfg, "node"):
                    continue
                good.append(node)
            except Exception:
                continue
        return good

    def _vless_connect_once(self):
        if not self._should_run_vless():
            return False
        if self._repair_active_vless_subscription_uri():
            self._vless_save_data()
        uri = self._get_active_vless_uri()
        scheme = _proxy_uri_scheme(uri)
        current_node = self._current_vless_node()
        mode_title = _proxy_protocol_label(current_node or scheme)
        qwdtt_mode = str((current_node or {}).get("kind", "") or "").strip().lower() == QWDTT_KIND
        if qwdtt_mode:
            mode_title = "qWDTT"
        if not uri or not current_node:
            self._set_vless_connection_state(False, "Нет выбранного узла")
            return False
        try:
            if str((current_node or {}).get("kind", "") or "").strip().lower() == "singbox-config":
                mode_title = "sing-box config"
        except:
            pass
        try:
            is_file_config = str((current_node or {}).get("kind", "") or "").strip().lower() == "singbox-config"
        except:
            is_file_config = False
        try:
            is_mihomo_config = str((current_node or {}).get("kind", "") or "").strip().lower() == "mihomo-config"
        except:
            is_mihomo_config = False
        use_sb = _is_singbox_core(self._vless_core)
        active_engine = self._effective_vless_engine(current_node)
        mihomo_mode = active_engine == VLESS_ENGINE_MIHOMO
        if mihomo_mode:
            mode_title = "Mihomo"
        auto_nodes = self._vless_auto_subscription_nodes(uri) if use_sb and not is_file_config and not is_mihomo_config and not qwdtt_mode else []
        resume_reconnect = bool(getattr(self, "_vless_resume_reconnect", False))
        self._vless_resume_reconnect = False
        target_config_key = self._vless_runtime_config_key(uri, current_node, auto_nodes=auto_nodes)
        if self._reuse_running_vless_if_ready(target_config_key):
            self._set_vless_connection_state(False, "")
            return True

        self._vless_disconnect(silent=True, cancel_pending=False)
        self._set_vless_connection_state(True, "")
        try:
            self._vless_core.lib
        except Exception as _le:
            pass
        if not self._vless_core.is_available():
            self._vless_running = False
            self._vless_port = 0
            self._delay_vless_retry()
            self._set_vless_connection_state(False, "Ядро прокси не загружено")
            return False
        port = int(self._pick_vless_runtime_port() or 0)
        if port <= 0:
            self._vless_running = False
            self._vless_port = 0
            self._delay_vless_retry()
            self._set_vless_connection_state(False, "Нет свободного локального порта")
            return False
        username = "" if qwdtt_mode else "greenpass"
        password = "" if qwdtt_mode else str(self._vless_socks_password or "")
        with self._vless_transition_lock:
            if not self._should_run_vless():
                return False
            generation = self._next_vless_generation()
            self._vless_port = int(port)
            self._vless_socks_username = username
            if not qwdtt_mode:
                self._vless_socks_password = password
            self._vless_local_owner = VLESS_KIND
        if qwdtt_mode:
            single_config = _qwdtt_core_config((current_node or {}).get("qwdtt", {}), port)
        elif is_mihomo_config:
            try:
                single_config = _build_mihomo_core_config(
                    config_text=str((current_node or {}).get("raw_config", "") or ""),
                    local_port=port,
                    work_dir=os.path.join(self._vless_dir, "mihomo"),
                    socks_username=username,
                    socks_password=password,
                )
            except:
                single_config = None
        elif is_file_config:
            if not use_sb:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, "Нужно ядро прокси")
                return False
            try:
                single_config = _prepare_singbox_file_config(
                    str((current_node or {}).get("raw_config", "") or ""),
                    port,
                    socks_username=username,
                    socks_password=password,
                )
            except:
                single_config = None
        elif mihomo_mode:
            links = [
                str(node.get("uri", "") or "")
                for node in (auto_nodes or [current_node])
                if isinstance(node, dict) and _is_proxy_uri(node.get("uri", ""))
            ]
            try:
                single_config = _build_mihomo_core_config(
                    links=links,
                    local_port=port,
                    work_dir=os.path.join(self._vless_dir, "mihomo"),
                    socks_username=username,
                    socks_password=password,
                )
            except:
                single_config = None
            if len(links) > 1:
                mode_title = "Mihomo Auto"
        elif use_sb:
            single_config = None
            if auto_nodes:
                if len(auto_nodes) > 1:
                    single_config = _build_singbox_balanced_config(
                        auto_nodes,
                        port,
                        socks_username=username,
                        socks_password=password,
                    )
                else:
                    single_config, _ = _build_registered_proxy_config(
                        str(auto_nodes[0].get("uri", "") or ""),
                        port,
                        socks_username=username,
                        socks_password=password,
                    )
                if single_config:
                    mode_title = "VLESS Auto"
            if not single_config:
                single_config, _ = _build_registered_proxy_config(
                    uri,
                    port,
                    socks_username=username,
                    socks_password=password,
                )
        else:
            single_config, _ = _build_vless_config(
                uri,
                port,
                socks_username=username,
                socks_password=password,
            )
        if not single_config:
            self._abort_vless_generation(generation, port)
            self._set_vless_connection_state(False, "Не удалось разобрать ссылку")
            return False

        def _singbox_runtime_patch(config_text):
            runtime_config = json.loads(config_text)
            log_config = runtime_config.get("log")
            log_config = dict(log_config) if isinstance(log_config, dict) else {}
            log_config.update({"disabled": False, "level": "info"})
            runtime_config["log"] = log_config
            experimental = runtime_config.get("experimental")
            experimental = dict(experimental) if isinstance(experimental, dict) else {}
            cache_file = experimental.get("cache_file")
            cache_file = dict(cache_file) if isinstance(cache_file, dict) else {}
            cache_file["path"] = os.path.join(self._vless_dir, "singbox-cache.db")
            experimental["cache_file"] = cache_file
            runtime_config["experimental"] = experimental
            return json.dumps(runtime_config)

        def _auto_pruned_config(nodes):
            can_prune = bool(use_sb and auto_nodes and len(auto_nodes) > 1 and not qwdtt_mode and not mihomo_mode
                             and not is_file_config and not is_mihomo_config)
            if not can_prune:
                return None, None
            good = self._prune_invalid_auto_nodes(nodes, port, username, password)
            if not good or len(good) >= len(nodes):
                return None, None
            if len(good) > 1:
                rebuilt = _build_singbox_balanced_config(good, port, socks_username=username, socks_password=password)
            else:
                rebuilt, _ = _build_registered_proxy_config(str(good[0].get("uri", "") or ""), port, socks_username=username, socks_password=password)
            if not rebuilt:
                return None, None
            try:
                return _singbox_runtime_patch(rebuilt), good
            except Exception:
                return None, None

        if use_sb and not qwdtt_mode and not mihomo_mode:
            try:
                single_config = _singbox_runtime_patch(single_config)
            except Exception as exc:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, f"Ошибка конфига sing-box: {exc}")
                return False
        if use_sb and not qwdtt_mode:
            validation_error = self._validate_core_config_for_import(single_config, mode_title)
            if validation_error and str(validation_error).startswith("Ошибка конфига"):
                retry_config, good_nodes = _auto_pruned_config(auto_nodes)
                if retry_config:
                    retry_error = self._validate_core_config_for_import(retry_config, mode_title)
                    if not retry_error:
                        single_config = retry_config
                        auto_nodes = good_nodes
                        validation_error = ""
            if validation_error:
                self._abort_vless_generation(generation, port)
                self._set_vless_connection_state(False, validation_error)
                return False
        config_json = single_config

        if qwdtt_mode:
            with self._vless_transition_lock:
                if not self._same_vless_generation(generation) or not self._should_run_vless() or int(self._vless_port or 0) != int(port):
                    return False
            err = self._vless_core.start(config_json)
            with self._vless_transition_lock:
                still_current = bool(self._same_vless_generation(generation) and self._should_run_vless() and int(self._vless_port or 0) == int(port))
            if not still_current:
                try:
                    if self._vless_core.current_engine() == QWDTT_KIND:
                        self._vless_core.stop()
                except:
                    pass
                return False
        else:
            with self._vless_core_op_lock:
                with self._vless_transition_lock:
                    if not self._same_vless_generation(generation) or not self._should_run_vless() or int(self._vless_port or 0) != int(port):
                        return False
                err = self._vless_core.start(config_json)
                if err and not any(token in str(err).lower() for token in ("address already in use", "eaddrinuse")):
                    retry_config, good_nodes = _auto_pruned_config(auto_nodes)
                    if retry_config:
                        config_json = retry_config
                        auto_nodes = good_nodes
                        err = self._vless_core.start(config_json)
        bind_error = str(err or "").lower()
        if err and ("address already in use" in bind_error or "eaddrinuse" in bind_error):
            if self._abort_vless_generation(generation, port):
                self._vless_avoid_preferred_port_once = True
                with self._vless_connect_lock:
                    self._vless_connect_pending = True
                self._set_vless_connection_state(True, "")
            return False
        if err:
            self._abort_vless_generation(generation, port)
            self._set_vless_connection_state(False, f"Ошибка ядра прокси: {err}")
            return False

        def _watchdog():
            ready_timeout = float(VLESS_LOCAL_READY_TIMEOUT_SEC)
            if resume_reconnect and uri == VLESS_AUTO_SUBSCRIPTIONS_URI:
                ready_timeout = max(ready_timeout, float(VLESS_RESUME_AUTO_READY_TIMEOUT_SEC))
            deadline = time.time() + ready_timeout
            local_ready = False
            final_pass = False
            while True:
                if (not final_pass) and time.time() >= deadline:
                    if (not local_ready) or mihomo_mode or qwdtt_mode:
                        break
                    if not _check_vless_telegram_route(port, timeout=1.5, username=username, password=password):
                        break
                    final_pass = True
                if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port) or not self._should_run_vless():
                    return
                if _check_vless_port(port) and _check_vless_socks_ready(port, timeout=0.5, username=username, password=password):
                    local_ready = True
                    allow_waking_auto = resume_reconnect and uri == VLESS_AUTO_SUBSCRIPTIONS_URI
                    if (not qwdtt_mode) and (not allow_waking_auto) and (not final_pass) and not _check_vless_tunnel_ready(port, timeout=1.5, username=username, password=password):
                        time.sleep(0.3)
                        continue
                    if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port) or not self._should_run_vless():
                        return
                    applied = self._vless_apply_tg_proxy(port, True, username=username, password=password)
                    if applied and (not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port)):
                        self._clear_local_socks_proxy_if_port(port, owner=VLESS_KIND)
                        return
                    apply_deadline = time.time() + 1.5
                    while applied and time.time() < apply_deadline:
                        if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port):
                            return
                        if self._is_local_vless_proxy_applied(port):
                            break
                        time.sleep(0.1)
                    if not applied or (not self._is_local_vless_proxy_applied(port)):
                        if not self._abort_vless_generation(generation, port):
                            return
                        self._set_vless_connection_state(False, "Локальный прокси не применился")
                        return
                    with self._vless_transition_lock:
                        if not self._same_vless_generation(generation) or int(self._vless_port or 0) != int(port):
                            return
                        self._vless_running = True
                        self._vless_active_config_key = target_config_key
                        self._reset_vless_retry()
                        self._save_config()
                    self._set_vless_connection_state(False, "Туннель не подтверждён" if final_pass else "")
                    return
                if final_pass:
                    break
                time.sleep(0.3)
            if mihomo_mode and local_ready:
                if not self._abort_vless_generation(generation, port):
                    return
                if (not is_mihomo_config) and self._vless_engine == VLESS_ENGINE_MIHOMO:
                    try:
                        self._vless_engine = VLESS_ENGINE_SINGBOX
                        self._save_config()
                        self._reset_vless_retry()
                    except:
                        pass
                self._set_vless_connection_state(False, "Прокси не работает. Попробуйте переключиться на ядро sing-box")
                return
            if not self._abort_vless_generation(generation, port):
                return
            self._set_vless_connection_state(False, f"{mode_title} не запустился")

        threading.Thread(target=_watchdog, daemon=True).start()
        return True

    def _stop_vless_core_for_generation(self, generation, background=None):
        if background is None:
            background = _gp_is_ui_thread()

        def _stop():
            try:
                with self._vless_core_op_lock:
                    if int(self._vless_generation or 0) != int(generation):
                        return
                    self._vless_core.stop()
            except Exception:
                pass

        if background:
            try:
                threading.Thread(target=_stop, daemon=True).start()
                return
            except Exception:
                pass
        _stop()

    def _vless_disconnect(self, silent=False, cancel_pending=True):
        if cancel_pending:
            with self._vless_connect_lock:
                self._vless_connect_pending = False
        with self._vless_transition_lock:
            self._vless_generation = int(self._vless_generation or 0) + 1
            generation = int(self._vless_generation)
            old_port = int(self._vless_port or 0)
            old_owner = str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND)
            self._vless_running = False
            self._vless_connecting = False
            if cancel_pending:
                self._vless_last_error = ""
            self._vless_port = 0
            self._vless_socks_username = ""
            self._vless_active_config_key = ""
            self._vless_local_owner = VLESS_KIND
        if old_port > 0:
            try:
                self._clear_local_socks_proxy_if_port(old_port, owner=old_owner)
            except Exception:
                pass
        self._stop_vless_core_for_generation(generation)
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _add_vless_subscription(self, url, activate_first=False):
        target = _normalize_subscription_url(url)
        if not target:
            BulletinHelper.show_error("Нужна ссылка на подписку")
            return

        BulletinHelper.show_info("Загружаю подписку...")

        def _worker():
            subscription_text = _fetch_text_url(target, timeout_sec=15.0)
            nodes = _fetch_vless_nodes(target, text=subscription_text)
            if not nodes:
                qwdtt_count = 0
                try:
                    qwdtt_count = self._import_qwdtt_payload(subscription_text, activate_first=bool(activate_first), subscription_url=target)
                except:
                    qwdtt_count = 0
                if qwdtt_count > 0:
                    run_on_ui_thread(lambda count=qwdtt_count: BulletinHelper.show_success(f"qWDTT профилей: {count}"))
                    return
                olcrtc_count = 0
                try:
                    olcrtc_count = self._try_import_olcrtc_subscription_text(target, subscription_text, activate_first=bool(activate_first))
                except:
                    olcrtc_count = 0
                if olcrtc_count <= 0:
                    try:
                        olcrtc_text = _fetch_olcrtc_subscription_text(target, timeout_sec=15.0)
                        olcrtc_count = self._try_import_olcrtc_subscription_text(target, olcrtc_text, activate_first=bool(activate_first)) if olcrtc_text else 0
                    except:
                        olcrtc_count = 0
                if olcrtc_count > 0:
                    run_on_ui_thread(lambda count=olcrtc_count: BulletinHelper.show_success(f"olcRTC профилей: {count}"))
                    return
                diag = _get_vless_fetch_diag(target)
                if diag:
                    text_len = int(diag.get("text_len", 0) or 0)
                    vless_count = int(diag.get("vless_count", 0) or 0)
                    ss_count = int(diag.get("ss_count", 0) or 0)
                    proxy_count = int(diag.get("proxy_count", 0) or 0)
                    link_count = int(diag.get("link_count", 0) or 0)
                    stage = str(diag.get("stage", "") or "")
                    tried = int(diag.get("tried", 0) or 0)
                    fetched_host = ""
                    try:
                        fetched_host = str(urllib.parse.urlparse(str(diag.get("fetched_url", "") or "")).netloc or "").strip()
                    except:
                        fetched_host = ""
                    errors = str(diag.get("errors", "") or "").strip()
                    msg = f"Нет узлов: text={text_len} proxy={proxy_count} sing-box={vless_count} ss={ss_count} links={link_count} tried={tried}"
                    if stage:
                        msg += f" stage={stage}"
                    if fetched_host:
                        msg += f" host={fetched_host}"
                    if errors:
                        msg += f" err={errors[:120]}"
                    run_on_ui_thread(lambda: BulletinHelper.show_error(msg))
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Подписка не содержит узлов"))
                return

            try:
                subs = list(self._vless_data.get("subs", []) or [])
            except:
                subs = []

            updated = False
            for sub in subs:
                try:
                    if str(sub.get("url", "") or "") == target:
                        sub["nodes"] = nodes
                        updated = True
                except:
                    continue
            if not updated:
                subs.append({
                    "id": target,
                    "url": target,
                    "name": str(urllib.parse.urlparse(target).netloc or target),
                    "nodes": nodes,
                })
            self._vless_data["subs"] = subs
            if activate_first and nodes:
                try:
                    self._vless_data["active_uri"] = str(nodes[0].get("uri", "") or "")
                    self._set_connection_mode(VLESS_KIND)
                except:
                    pass
            self._repair_active_vless_subscription_uri()
            self._vless_save_data()
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))
            run_on_ui_thread(lambda: BulletinHelper.show_success(f"Импортировано узлов: {len(nodes)}"))

            if activate_first and nodes:
                try:
                    self._enable_plugin_proxy_flag()
                except:
                    pass
                try:
                    self._tgws_disconnect_with_reason("activate_vless_subscription", silent=True)
                except:
                    pass
                try:
                    self._awg_disconnect_with_reason("activate_vless_subscription", silent=True)
                except:
                    pass
                self._ensure_vless_core_then(self._vless_connect)
            elif (updated or self._get_active_vless_uri() == VLESS_AUTO_SUBSCRIPTIONS_URI) and self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND:
                self._ensure_vless_core_then(self._vless_connect)

        threading.Thread(target=_worker, daemon=True).start()

    def _vless_counts(self):
        try:
            manual_count = len(list(self._vless_data.get("manual", []) or []))
        except:
            manual_count = 0
        try:
            subs = list(self._vless_data.get("subs", []) or [])
        except:
            subs = []
        sub_count = len(subs)
        node_count = int(manual_count)
        for sub in subs:
            try:
                node_count += len(list(sub.get("nodes", []) or []))
            except:
                pass
        return {"manual": int(manual_count), "subs": int(sub_count), "nodes": int(node_count)}

    def _download_vless_addon(self):
        if self._vless_prepare_in_progress:
            BulletinHelper.show_info("Ядро прокси уже скачивается")
            return

        self._set_core_download_in_progress(True)
        dialog, update_progress = self._open_core_download_progress()
        if dialog is None:
            BulletinHelper.show_info("Скачиваю ядро прокси...")

        def _worker():
            try:
                ok = self._install_singbox_as_vless_core(on_progress=update_progress)
                if ok:
                    message = "Ядро установлено — перезапустите приложение" if self._core_restart_required() else "Ядро прокси готово"
                    run_on_ui_thread(lambda: BulletinHelper.show_success(message))
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить ядро прокси"))
            finally:
                self._set_core_download_in_progress(False)
                if dialog is not None:
                    run_on_ui_thread(lambda: dialog.dismiss())

        threading.Thread(target=_worker, daemon=True).start()

    def _import_vless_from_clipboard(self):
        blob = self._get_clipboard_text()
        if not blob:
            BulletinHelper.show_error("Буфер обмена пуст")
            return

        uri = _extract_import_uri(blob)
        if uri:
            self._handle_import_uri(uri)
            return

        subscription_url = _normalize_subscription_url(blob)
        if subscription_url:
            self._add_vless_subscription(subscription_url, activate_first=(not self._get_active_vless_uri()))
            return

        BulletinHelper.show_error("В буфере нет ссылки на сервер")

    def _vless_node_label(self, node):
        base = self._vless_node_plain_label(node)
        ping = self._vless_ping_value(node)
        checked_at = self._vless_ping_checked_at(node)
        if checked_at > 0 and (time.time() - checked_at) <= float(VLESS_NODE_PING_STALE_SEC):
            if ping > 0 and ping < 9999:
                return f"🟢 {int(ping)} ms: {base}"
            return f"🔴 {base}"
        return base

    def _vless_node_plain_label(self, node):
        try:
            target_uri = str(node.get("uri", "") or "")
        except:
            target_uri = ""
        is_active = bool(
            target_uri
            and target_uri == self._get_active_vless_uri()
            and self._is_vless_mode_selected()
            and self._is_plugin_proxy_enabled()
        )
        if target_uri == VLESS_AUTO_SUBSCRIPTIONS_URI:
            return ("🟢 " if is_active else "") + Z("Автовыбор")
        try:
            raw_name = str(node.get("name", "") or "").strip()
            name = _clean_proxy_name(raw_name, "") if raw_name else ""
            name = re.sub(r"\s+proxy(?:[-_ ]*\d+)?$", "", name, flags=re.I).strip()
        except:
            name = ""
        try:
            kind = str(node.get("kind", "") or "").strip().lower()
        except:
            kind = ""
        if not kind:
            kind = _proxy_uri_scheme(target_uri)
        protocol_label = _proxy_protocol_label(kind)

        parts = []
        if name:
            parts.append(name)
        if protocol_label and protocol_label.lower() != name.lower():
            parts.append(protocol_label)
        prefix = "🟢 " if is_active else ""
        return prefix + (" • ".join(parts) if parts else "Узел")

    def _switch_to_vless_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("vless"):
            return
        if persist_mode:
            self._set_connection_mode(VLESS_KIND)
        try:
            self._tgws_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        try:
            self._awg_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        try:
            self._olcrtc_disconnect_with_reason("switch_to_vless_mode", silent=True)
        except:
            pass
        if self._get_active_vless_uri():
            self._enable_plugin_proxy_flag()
            self._reset_vless_retry()
            self._ensure_vless_core_then(self._vless_connect)
        else:
            run_on_ui_thread(lambda: BulletinHelper.show_info("Импортируйте сервер"))
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _vless_subscription_has_active(self, sub):
        active_uri = self._get_active_vless_uri()
        if not active_uri:
            return False
        for node in list(sub.get("nodes", []) or []):
            try:
                if str(node.get("uri", "") or "") == active_uri:
                    return True
            except:
                pass
        return False

# --- bundled from greenpass.modes.awg.py ---


class AwgModeMixin:
    def _libawg_so_path(self):
        return self._libsingbox_so_path()

    def _has_libawg_addon(self):
        return self._has_libsingbox_addon()

    def _is_awg_mode_selected(self):
        return self._get_connection_mode() == AWG_KIND

    def _is_awg_connection_ready(self):
        if not self._should_run_awg():
            return False
        try:
            return bool(self._is_local_proxy_applied(int(self._awg_port or AWG_LOCAL_PORT), owner=AWG_KIND))
        except Exception:
            return False

    def _restore_running_awg_proxy(self, force_reapply=False):
        if not self._should_run_awg():
            return False
        started_conf = str(getattr(self, "_awg_started_conf", "") or "")
        if not started_conf or started_conf != str(self._awg_conf_content or "").strip():
            return False
        if not bool(getattr(self._awg_core, "started", False)):
            return False
        port = int(self._awg_port or AWG_LOCAL_PORT)
        if not _check_vless_socks_ready(port, timeout=0.35):
            return False
        applied = self._is_local_proxy_applied(port, owner=AWG_KIND)
        changed = bool(force_reapply) or not bool(self._awg_running) or int(self._awg_port or 0) != port or not applied
        if (bool(force_reapply) or not applied) and not self._apply_local_socks_proxy(port, True, owner=AWG_KIND):
            return False
        self._awg_port = port
        self._awg_running = True
        if changed:
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        return True

    def _ensure_awg_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_awg_mode = runner_name == "_awg_connect"
        if require_awg_mode and (not self._should_run_awg()):
            return
        if self._go_core_switch_blocked("awg"):
            return

        def _prepare_and_run():
            try:
                self._prepare_awg_core_and_run(runner, require_awg_mode)
            except Exception as exc:
                err_text = str(exc)
                BulletinHelper.show_error("Ошибка AWG: %s" % err_text)

        try:
            threading.Thread(target=_prepare_and_run, daemon=True).start()
        except Exception:
            pass

    def _prepare_awg_core_and_run(self, runner, require_awg_mode):
        if self._libsingbox_core_load_allowed():
            self._awg_core._ensure()
        if self._awg_core.is_available():
            if require_awg_mode and (not self._should_run_awg()):
                return
            runner()
            return
        if self._core_needs_restart_notice():
            BulletinHelper.show_info("Ядро обновлено — перезапустите приложение")
            return
        if self._awg_prepare_in_progress:
            return
        if time.monotonic() < float(getattr(self, "_awg_core_fail_until", 0.0) or 0.0):
            return

        self._awg_prepare_in_progress = True
        BulletinHelper.show_info("Скачиваю ядро AWG...")
        try:
            ok = self._has_libawg_addon()
            if ok:
                self._reload_awg_core()
                self._awg_core._ensure()
                if not self._awg_core.is_available():
                    if self._core_needs_restart_notice():
                        BulletinHelper.show_info("Ядро обновлено — перезапустите приложение")
                        return
                    status = self._libsingbox_addon_status()
                    now_m = time.monotonic()
                    if status == "current" or now_m - float(getattr(self, "_awg_core_redownload_ts", 0.0) or 0.0) < 600.0:
                        self._awg_core_fail_until = now_m + 600.0
                        BulletinHelper.show_error("Не удалось загрузить ядро AWG")
                        return
                    self._awg_core_redownload_ts = now_m
                    try:
                        os.remove(self._libawg_so_path())
                        self._libsingbox_validation_cache = None
                    except:
                        pass
                    ok = False
            if not ok:
                ok = self._download_libawg_with_progress()
                if ok and self._core_restart_required():
                    BulletinHelper.show_success("Ядро установлено — перезапустите приложение")
                    return
                self._reload_awg_core()
                self._awg_core._ensure()
            if not (ok and self._awg_core.is_available()):
                BulletinHelper.show_error("Не удалось загрузить ядро AWG")
                return
            if require_awg_mode and (not self._should_run_awg()):
                return
            try:
                runner()
            except Exception as exc:
                err_text = str(exc)
                BulletinHelper.show_error("Ошибка AWG: %s" % err_text)
        finally:
            self._awg_prepare_in_progress = False

    def _stop_awg_core(self, epoch):
        def _stop():
            try:
                if int(getattr(self, "_awg_epoch", 0) or 0) != int(epoch):
                    return
                self._awg_core.stop()
            except Exception:
                pass

        if _gp_is_ui_thread():
            try:
                threading.Thread(target=_stop, daemon=True).start()
                return
            except Exception:
                pass
        _stop()

    def _awg_connect(self):
        if not self._should_run_awg():
            self._awg_connecting = False
            return False
        self._awg_connecting = True
        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        try:
            conf_content = str(self._awg_conf_content or "").strip()
            if not conf_content:
                self._awg_running = False
                self._awg_port = 0
                _log_diag("WARN", "AmneziaWG: configuration content is empty, requesting free config")
                self._download_free_awg_config()
                return False

            if self._restore_running_awg_proxy():
                _log_diag("INFO", "AmneziaWG: restored already running proxy")
                return True

            if not self._awg_core.is_available():
                self._awg_running = False
                self._awg_port = 0
                _log_diag("INFO", "AmneziaWG: core not available yet, ensuring core")
                self._ensure_awg_core_then(self._awg_connect)
                return False

            port = int(AWG_LOCAL_PORT)
            self._awg_port = port
            if not self._should_run_awg():
                self._awg_port = 0
                return False
            self._awg_epoch = int(getattr(self, "_awg_epoch", 0) or 0) + 1
            err = self._awg_core.start(conf_content)
            if err:
                self._awg_running = False
                self._awg_port = 0
                self._awg_started_conf = ""
                run_on_ui_thread(lambda: BulletinHelper.show_error("Ошибка AWG: %s" % str(err)))
                return False

            self._awg_started_conf = conf_content
            self._awg_running = True
            if not self._should_run_awg():
                self._awg_running = False
                self._awg_port = 0
                return False
            if not self._apply_local_socks_proxy(port, True, owner=AWG_KIND):
                self._awg_running = False
                return False
            if not self._should_run_awg() or int(self._awg_port or 0) != int(port):
                self._clear_local_socks_proxy_if_port(port, owner=AWG_KIND)
                self._awg_running = False
                return False
            self._save_config()
            run_on_ui_thread(lambda: BulletinHelper.show_success("AmneziaWG подключен"))
            self._on_awg_connected()
            return True
        finally:
            self._awg_connecting = False
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

    def _awg_disconnect_with_reason(self, reason, silent=False):
        reason_text = str(reason or "unknown")
        stop_core = reason_text in ("manual_stop", "restart_awg", "clear_awg_config", "start_failed", "apply_failed")
        self._awg_disconnect(silent=bool(silent), reason=reason_text, stop_core=bool(stop_core))

    def _awg_disconnect(self, silent=False, reason="unknown", stop_core=True):
        _log_diag("INFO", f"AmneziaWG disconnect: reason={reason}, stop_core={stop_core}")
        try:
            self._stop_awg_health_loop()
        except Exception:
            pass
        old_port = int(self._awg_port or 0)
        if bool(stop_core):
            try:
                self._awg_core.stop()
            except Exception:
                pass
            self._awg_started_conf = ""
        self._awg_running = False
        self._awg_connecting = False
        self._awg_port = 0
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=AWG_KIND)
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _ensure_awg_config_then_connect(self):
        if str(self._awg_conf_content or "").strip():
            self._ensure_awg_core_then(self._awg_connect)
            return
        self._download_free_awg_config()

    def _switch_to_awg_mode(self, persist_mode=True):
        _log_diag("INFO", "Switching to AmneziaWG mode")
        if self._go_core_switch_blocked("awg"):
            _log_diag("WARN", "Switch to AWG blocked by go core switch lock")
            return
        if persist_mode:
            self._set_connection_mode(AWG_KIND)
        self._vless_disconnect_with_reason("switch_to_awg_mode", silent=True)
        self._tgws_disconnect_with_reason("switch_to_awg_mode", silent=True)
        self._olcrtc_disconnect_with_reason("switch_to_awg_mode", silent=True)
        if not str(self._awg_conf_content or "").strip():
            self._enable_plugin_proxy_flag()
            self._ensure_awg_config_then_connect()
        else:
            self._enable_plugin_proxy_flag()
            self._ensure_awg_core_then(self._awg_connect)
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)


# --- bundled from greenpass.modes.olcrtc.py ---


class OlcRtcModeMixin:
    def _libzvonki_so_path(self):
        return self._libsingbox_so_path()

    def _has_libzvonki_addon(self):
        return self._has_libsingbox_addon()

    def _is_olcrtc_mode_selected(self):
        return self._get_connection_mode() == OLCRTC_KIND

    def _olcrtc_item_by_setting(self, key, items, default_index=0):
        try:
            idx = int(self.get_setting(key, int(default_index)))
        except:
            idx = int(default_index)
        try:
            if idx < 0 or idx >= len(items):
                idx = int(default_index)
        except:
            idx = int(default_index)
        try:
            return str(items[idx])
        except:
            return str(items[int(default_index)])

    def _olcrtc_carrier_index(self):
        try:
            idx = int(self.get_setting("olcrtc_carrier", 0))
            if 0 <= idx < len(OLCRTC_CARRIER_ITEMS):
                return idx
        except:
            pass
        return 0

    def _get_olcrtc_carrier(self):
        return self._olcrtc_item_by_setting("olcrtc_carrier", OLCRTC_CARRIER_ITEMS, 0)

    def _get_olcrtc_transport(self):
        transport = self._olcrtc_item_by_setting("olcrtc_transport", OLCRTC_TRANSPORT_ITEMS, 0)
        supported = _olcrtc_supported_transports(self._get_olcrtc_carrier())
        return transport if transport in supported else supported[0]

    def _olcrtc_transport_choices(self):
        return _olcrtc_supported_transports(self._get_olcrtc_carrier())

    def _olcrtc_transport_choice_index(self):
        choices = self._olcrtc_transport_choices()
        try:
            return choices.index(self._get_olcrtc_transport())
        except:
            return 0

    def _olcrtc_carrier_label(self, value):
        return self._olcrtc_label_for_item(value, OLCRTC_CARRIER_ITEMS, OLCRTC_CARRIER_LABELS, 0)

    def _olcrtc_transport_label(self, value):
        return self._olcrtc_label_for_item(value, OLCRTC_TRANSPORT_ITEMS, OLCRTC_TRANSPORT_LABELS, 0)

    def _olcrtc_label_for_item(self, value, items, labels, default_index=0):
        try:
            target = str(value or "").strip().lower()
            for idx, item in enumerate(items):
                if str(item or "").strip().lower() == target and idx < len(labels):
                    return str(labels[idx] or item)
        except:
            pass
        try:
            idx = int(default_index)
            if 0 <= idx < len(labels):
                return str(labels[idx] or items[idx])
        except:
            pass
        return str(value or "")

    def _olcrtc_current_labels(self):
        return self._olcrtc_carrier_label(self._get_olcrtc_carrier()), self._olcrtc_transport_label(self._get_olcrtc_transport())

    def _get_olcrtc_room_id(self):
        try:
            return str(self.get_setting("olcrtc_room_id", "") or "").strip()
        except:
            return ""

    def _get_olcrtc_client_id(self):
        return _get_or_create_olcrtc_device_id()

    def _get_olcrtc_vp8_options(self):
        try:
            fps = max(1, min(120, int(self.get_setting("olcrtc_vp8_fps", "60") or 60)))
        except:
            fps = 60
        try:
            batch = max(1, min(64, int(self.get_setting("olcrtc_vp8_batch_size", "64") or 64)))
        except:
            batch = 64
        return fps, batch

    def _get_olcrtc_key_hex(self):
        try:
            return str(self.get_setting("olcrtc_key_hex", "") or "").strip()
        except:
            return ""

    def _olcrtc_config_error(self):
        if not self._get_olcrtc_room_id():
            return "Укажите room_id"
        if not self._get_olcrtc_client_id():
            return "Укажите client_id"
        key_hex = self._get_olcrtc_key_hex()
        if not key_hex:
            return "Укажите key_hex"
        if len(key_hex) != 64 or re.search(r"[^0-9a-fA-F]", key_hex):
            return "key_hex должен быть 64 hex"
        return ""

    def _is_olcrtc_config_ready(self):
        return not bool(self._olcrtc_config_error())

    def _olcrtc_profile_id_for(self, carrier, transport, room_id, client_id, key_hex):
        try:
            raw = "|".join([
                str(carrier or "").strip().lower(),
                str(transport or "").strip().lower(),
                str(room_id or "").strip(),
                str(client_id or "").strip(),
                str(key_hex or "").strip().lower(),
            ])
            return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        except:
            return str(int(time.time() * 1000))

    def _olcrtc_profile_name(self, profile):
        try:
            name = str(profile.get("name", "") or "").strip()
            if name:
                return name[:48]
            room_id = str(profile.get("room_id", "") or "").strip()
            client_id = str(profile.get("client_id", "") or "").strip()
            tail = room_id.rstrip("/").split("/")[-1] if room_id else ""
            base = tail or room_id or client_id or "olcRTC"
            if client_id and client_id not in base:
                base = "%s • %s" % (base, client_id)
            return base[:48] if base else "olcRTC"
        except:
            return "olcRTC"

    def _ensure_olcrtc_legacy_profile(self):
        if self._olcrtc_profiles:
            return
        try:
            profile = self._normalize_olcrtc_profile({
                "carrier": self._get_olcrtc_carrier(),
                "transport": self._get_olcrtc_transport(),
                "room_id": self._get_olcrtc_room_id(),
                "client_id": self._get_olcrtc_client_id(),
                "key_hex": self._get_olcrtc_key_hex(),
            })
        except:
            profile = None
        if profile:
            self._olcrtc_profiles = [profile]
            self._olcrtc_active_profile_id = str(profile.get("id", "") or "")

    def _set_olcrtc_legacy_settings_from_profile(self, profile):
        if not isinstance(profile, dict):
            return
        self._set_setting_value("olcrtc_carrier", self._olcrtc_index_for_item(profile.get("carrier"), OLCRTC_CARRIER_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_transport", self._olcrtc_index_for_item(profile.get("transport"), OLCRTC_TRANSPORT_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_room_id", str(profile.get("room_id", "") or ""), reload_settings=False)
        self._set_setting_value("olcrtc_client_id", str(profile.get("client_id", "") or ""), reload_settings=False)
        self._set_setting_value("olcrtc_key_hex", str(profile.get("key_hex", "") or ""), reload_settings=False)
        self._set_setting_value("olcrtc_vp8_fps", str(profile.get("vp8_fps", 60) or 60), reload_settings=False)
        self._set_setting_value("olcrtc_vp8_batch_size", str(profile.get("vp8_batch_size", 64) or 64), reload_settings=False)

    def _olcrtc_core_query_allowed(self, allow_connecting=False):
        if bool(getattr(self, "_olcrtc_prepare_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_start_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_stop_in_progress", False)):
            return False
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            return False
        if (not bool(allow_connecting)) and bool(getattr(self, "_olcrtc_connecting", False)):
            return False
        try:
            return bool(self._olcrtc_core.is_available())
        except:
            return False

    def _set_olcrtc_last_log(self, message, event="state", level="info", **fields):
        try:
            text = str(message or "").strip()
        except:
            text = ""
        self._olcrtc_last_log = text

    def _set_olcrtc_last_error(self, message, event="error", **fields):
        try:
            text = str(message or "").strip()
        except:
            text = ""
        self._olcrtc_last_error = text

    def _olcrtc_core_status_data(self):
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            fallback_state = "background"
        elif bool(getattr(self, "_olcrtc_resume_checking", False)) or bool(getattr(self, "_olcrtc_health_stale", False)):
            fallback_state = "checking"
        elif bool(self._olcrtc_running):
            fallback_state = "ready"
        elif bool(getattr(self, "_olcrtc_connecting", False)):
            fallback_state = "handshake"
        elif bool(getattr(self, "_olcrtc_prepare_in_progress", False)) or bool(getattr(self, "_vless_prepare_in_progress", False)):
            fallback_state = "starting"
        elif self._should_run_olcrtc() and str(getattr(self, "_olcrtc_last_error", "") or "").strip():
            fallback_state = "error"
        else:
            fallback_state = "stopped"
        fallback = {
            "state": fallback_state,
            "message": str(getattr(self, "_olcrtc_last_error", "") or getattr(self, "_olcrtc_last_log", "") or "").strip(),
            "running": fallback_state == "ready",
        }
        if fallback_state in ("background", "checking"):
            return fallback
        try:
            raw = self._safe_olcrtc_core_text("status_json", allow_connecting=False)
            if not raw:
                return fallback
            data = json.loads(raw)
            if not isinstance(data, dict):
                return fallback
            state = str(data.get("state", "") or "").strip().lower()
            if not state:
                return fallback
            data["state"] = state
            return data
        except:
            return fallback

    def _olcrtc_status_presentation(self):
        data = self._olcrtc_core_status_data()
        state = str(data.get("state", "") or "stopped").strip().lower()
        labels = {
            "starting": "olcRTC: запуск",
            "handshake": "olcRTC: handshake",
            "ready": "olcRTC: подключен",
            "running": "olcRTC: подключен",
            "background": "olcRTC: в фоне",
            "checking": "olcRTC: проверка",
            "stopping": "olcRTC: остановка",
            "stopped": "olcRTC: выключен",
            "error": "olcRTC: ошибка",
        }
        text = labels.get(state, "olcRTC: " + state[:24])
        message = str(data.get("message", "") or "").strip()
        carrier_label, transport_label = self._olcrtc_current_labels()
        subtext = message[:120] if message else "%s / %s" % (carrier_label, transport_label)
        return text, subtext, state

    def _olcrtc_local_ready(self, port, check_tunnel=False, reason="health"):
        try:
            target_port = int(port or 0)
        except:
            target_port = 0
        if target_port <= 0:
            return False
        if not _check_vless_port(target_port):
            return False
        if not _check_vless_socks_ready(target_port, timeout=0.5):
            return False
        if not bool(check_tunnel):
            return True
        ok = _check_olcrtc_tunnel_ready(target_port, timeout=float(OLCRTC_TUNNEL_CHECK_TIMEOUT_SEC))
        if not ok:
            pass
        return bool(ok)

    def _olcrtc_state_needs_restart(self, core_state):
        state = str(core_state or "").strip().lower()
        return state in ("error", "stopped") and (not bool(getattr(self, "_olcrtc_connecting", False)))

    def _olcrtc_try_next_profile(self, reason=""):
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        if len(profiles) < 2:
            return False
        active_id = str(self._olcrtc_active_profile_id or "")
        index = 0
        for idx, profile in enumerate(profiles):
            if str(profile.get("id", "") or "") == active_id:
                index = idx
                break
        next_profile = profiles[(index + 1) % len(profiles)]
        next_id = str(next_profile.get("id", "") or "")
        if not next_id or next_id == active_id:
            return False
        self._olcrtc_profiles = profiles
        self._olcrtc_active_profile_id = next_id
        self._set_olcrtc_legacy_settings_from_profile(next_profile)
        self._set_connection_mode(OLCRTC_KIND)
        self._save_config()
        self._set_olcrtc_last_log("next profile after " + str(reason or "failure"), event="profile_failover")
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        self._ensure_olcrtc_core_then(self._olcrtc_connect)
        return True

    def _ensure_olcrtc_core_then(self, runner):
        runner_name = str(getattr(runner, "__name__", "") or "")
        require_olcrtc_mode = runner_name == "_olcrtc_connect"
        show_feedback = bool(getattr(self, "_olcrtc_feedback_requested", False))
        if require_olcrtc_mode and (not self._should_run_olcrtc()):
            if show_feedback and self._is_olcrtc_mode_selected():
                run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
            return
        if self._go_core_switch_blocked("olcrtc"):
            return
        self._olcrtc_core._ensure()
        if self._olcrtc_core.is_available():
            if require_olcrtc_mode and (not self._should_run_olcrtc()):
                if show_feedback and self._is_olcrtc_mode_selected():
                    run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
                return
            threading.Thread(target=runner, daemon=True).start()
            return
        if self._olcrtc_prepare_in_progress:
            if show_feedback:
                BulletinHelper.show_info("olcRTC уже готовится")
            return

        self._olcrtc_prepare_in_progress = True
        if show_feedback:
            BulletinHelper.show_info("Готовлю olcRTC...")

        def _worker():
            try:
                ok = self._install_libzvonki_bundle(allow_network=True)
                if ok and self._core_restart_required():
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                    return
                self._reload_olcrtc_core()
                self._olcrtc_core._ensure()
                if ok and self._olcrtc_core.is_available():
                    if require_olcrtc_mode and (not self._should_run_olcrtc()):
                        return
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро olcRTC готово"))
                    try:
                        runner()
                    except Exception as exc:
                        err_text = str(exc)
                        self._set_olcrtc_last_error(err_text, event="ensure_runner_exception", runner=runner_name)
                        if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка olcRTC: %s" % err_text))
                else:
                    self._set_olcrtc_last_error("core prepare failed", event="ensure_prepare_failed", runner=runner_name, installed=ok)
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить olcRTC"))
            finally:
                self._olcrtc_prepare_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()

    def _olcrtc_connect(self):
        with self._olcrtc_connect_lock:
            if bool(getattr(self, "_olcrtc_connect_worker_active", False)):
                self._olcrtc_connect_pending = True
                should_queue = True
            else:
                self._olcrtc_connect_worker_active = True
                self._olcrtc_connect_pending = False
                should_queue = False
        if should_queue:
            self._set_olcrtc_last_log("restart queued", event="connect_queued")
            return True

        result = False
        try:
            while True:
                with self._olcrtc_connect_lock:
                    self._olcrtc_connect_pending = False
                result = self._olcrtc_connect_once()
                with self._olcrtc_connect_lock:
                    repeat = bool(self._olcrtc_connect_pending) and bool(self._should_run_olcrtc())
                    if not repeat:
                        self._olcrtc_connect_worker_active = False
                        return result
        finally:
            with self._olcrtc_connect_lock:
                self._olcrtc_connect_worker_active = False

    def _olcrtc_connect_once(self):
        if bool(getattr(self, "_olcrtc_backgrounded", False)):
            return False
        show_feedback = bool(getattr(self, "_olcrtc_feedback_requested", False))
        if not self._should_run_olcrtc():
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_feedback_requested = False
            if show_feedback and self._is_olcrtc_mode_selected():
                run_on_ui_thread(lambda: BulletinHelper.show_error(self._olcrtc_config_error() or "olcRTC выключен"))
            return False
        config_json, config_err = self._build_olcrtc_config_json()
        if config_err:
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._olcrtc_feedback_requested = False
            self._set_olcrtc_last_error(config_err, event="connect_config_error")
            if show_feedback:
                run_on_ui_thread(lambda config_err=config_err: BulletinHelper.show_error(config_err))
            return False
        if not self._olcrtc_core.is_available():
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
            return False

        self._olcrtc_feedback_requested = False
        generation = self._next_olcrtc_generation()
        old_port = int(self._olcrtc_port or 0)
        self._olcrtc_running = False
        self._olcrtc_connecting = True
        self._olcrtc_dead_checks = 0
        self._olcrtc_last_error = ""
        self._set_olcrtc_last_log(
            "starting %s %s" % (self._get_olcrtc_carrier(), self._get_olcrtc_transport()),
            event="connect_start",
            generation=generation,
            old_port=old_port,
            carrier=self._get_olcrtc_carrier(),
            transport=self._get_olcrtc_transport(),
            room_id=self._get_olcrtc_room_id(),
            client_id=self._get_olcrtc_client_id(),
            key_hex=self._mask_olcrtc_key(),
        )
        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=OLCRTC_KIND)
        port = int(OLCRTC_LOCAL_PORT)

        self._olcrtc_port = port
        self._olcrtc_start_in_progress = True
        self._set_olcrtc_last_log("handshake started", event="native_start_enter", generation=generation, port=port)
        try:
            err = self._olcrtc_core.start(config_json)
        finally:
            self._olcrtc_start_in_progress = False
        if err:
            if not self._same_olcrtc_generation(generation) or not self._is_olcrtc_mode_selected():
                return False
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            detail = str(err or "")
            self._set_olcrtc_last_error(detail, event="native_start_failed", generation=generation, port=port)
            self._set_olcrtc_last_log("start failed", event="connect_failed", generation=generation, port=port)
            if self._olcrtc_try_next_profile("start failed"):
                return False
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
            if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                run_on_ui_thread(lambda detail=detail: BulletinHelper.show_error("Ошибка olcRTC: %s" % str(detail)))
            return False

        def _watchdog():
            deadline = time.time() + float(OLCRTC_LOCAL_READY_TIMEOUT_SEC)
            while time.time() < deadline:
                if not self._same_olcrtc_generation(generation) or not self._should_run_olcrtc() or int(self._olcrtc_port or 0) != int(port):
                    self._olcrtc_running = False
                    self._olcrtc_connecting = False
                    self._set_olcrtc_last_log("watchdog cancelled", event="watchdog_cancelled", generation=generation, port=port)
                    return
                if self._olcrtc_local_ready(port, check_tunnel=True, reason="watchdog_ready"):
                    if not self._same_olcrtc_generation(generation) or not self._should_run_olcrtc() or int(self._olcrtc_port or 0) != int(port):
                        self._clear_local_socks_proxy_if_port(port, owner=OLCRTC_KIND)
                        self._olcrtc_running = False
                        self._olcrtc_connecting = False
                        self._set_olcrtc_last_log("cancelled before ready", event="watchdog_cancelled_before_apply", generation=generation, port=port)
                        return
                    applied = self._apply_local_socks_proxy(port, True, owner=OLCRTC_KIND)
                    apply_deadline = time.time() + 1.5
                    while applied and time.time() < apply_deadline:
                        if self._is_local_olcrtc_proxy_applied(port):
                            break
                        time.sleep(0.1)
                    if not applied or (not self._is_local_olcrtc_proxy_applied(port)):
                        self._olcrtc_running = False
                        self._olcrtc_connecting = False
                        self._olcrtc_port = 0
                        self._set_olcrtc_last_error("telegram local proxy apply failed", event="telegram_proxy_apply_failed", generation=generation, port=port, applied=applied)
                        self._set_olcrtc_last_log("socks ready, telegram apply failed", event="connect_failed_after_socks_ready", generation=generation, port=port)
                        if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)) and self._same_olcrtc_generation(generation) and self._is_olcrtc_mode_selected():
                            run_on_ui_thread(lambda: BulletinHelper.show_error("Локальный прокси не применился"))
                        return
                    self._olcrtc_running = True
                    self._olcrtc_connecting = False
                    self._olcrtc_health_stale = False
                    self._olcrtc_resume_checking = False
                    self._olcrtc_dead_checks = 0
                    self._olcrtc_last_error = ""
                    self._set_olcrtc_last_log("connected on socks port %s" % int(port), event="connect_ready", generation=generation, port=port)
                    self._save_config()
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                    if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                        run_on_ui_thread(lambda: BulletinHelper.show_success("olcRTC подключен"))
                    return
                time.sleep(0.3)
            if not self._same_olcrtc_generation(generation) or not self._is_olcrtc_mode_selected():
                return
            self._olcrtc_running = False
            self._olcrtc_connecting = False
            self._olcrtc_port = 0
            self._set_olcrtc_last_error("WebRTC timeout", event="watchdog_timeout", generation=generation, port=port)
            self._set_olcrtc_last_log("ready watchdog timeout", event="connect_timeout", generation=generation, port=port)
            if self._olcrtc_try_next_profile("timeout"):
                return
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
            if show_feedback and not bool(getattr(self, "_olcrtc_backgrounded", False)):
                run_on_ui_thread(lambda: BulletinHelper.show_error("olcRTC: WebRTC timeout"))

        threading.Thread(target=_watchdog, daemon=True).start()
        return True

    def _olcrtc_disconnect_with_reason(self, reason, silent=False):
        reason_text = str(reason or "")
        self._olcrtc_disconnect(silent=bool(silent), stop_core=True)

    def _olcrtc_disconnect(self, silent=False, stop_core=True):
        self._next_olcrtc_generation()
        self._olcrtc_feedback_requested = False
        old_port = int(self._olcrtc_port or 0)
        with self._olcrtc_connect_lock:
            self._olcrtc_connect_pending = False
        if bool(stop_core):
            self._stop_olcrtc_core_async()
        self._olcrtc_running = False
        self._olcrtc_connecting = False
        self._olcrtc_dead_checks = 0
        self._olcrtc_port = 0
        self._set_olcrtc_last_log("stopped", event="disconnect_finish", old_port=old_port)
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=OLCRTC_KIND)
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _olcrtc_index_for_item(self, value, items, default_index=0):
        try:
            target = str(value or "").strip().lower()
            for idx, item in enumerate(items):
                if str(item).lower() == target:
                    return int(idx)
        except:
            pass
        return int(default_index)

    def _olcrtc_subscription_urls(self):
        result = []
        for profile in self._sanitize_olcrtc_profiles(self._olcrtc_profiles):
            url = str(profile.get("subscription_url", "") or "").strip()
            if url.lower().startswith(("http://", "https://")) and url not in result:
                result.append(url)
        return result

    def _olcrtc_subscriptions_stale(self):
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        cutoff = int(time.time()) - 86400
        for url in self._olcrtc_subscription_urls():
            updated = max([
                int(profile.get("subscription_updated_at", 0) or 0)
                for profile in profiles
                if str(profile.get("subscription_url", "") or "") == url
            ] or [0])
            if updated < cutoff:
                return True
        return False

    def _switch_to_olcrtc_mode(self, persist_mode=True):
        if self._go_core_switch_blocked("olcrtc"):
            return
        if persist_mode:
            self._set_connection_mode(OLCRTC_KIND)
        self._vless_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        self._tgws_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        self._awg_disconnect_with_reason("switch_to_olcrtc_mode", silent=True)
        if not self._is_olcrtc_config_ready():
            run_on_ui_thread(lambda: BulletinHelper.show_info("Заполните olcRTC"))
        else:
            self._enable_plugin_proxy_flag()
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

# --- bundled from greenpass.modes.tgws.py ---


class TgWsModeMixin:
    def _is_tgws_mode_selected(self):
        return self._get_connection_mode() == TGWS_KIND

    def _get_tgws_voip_relay_enabled(self):
        try:
            return bool(self.get_setting("tgws_voip_relay_enabled", True))
        except:
            return False

    def _set_tgws_voip_relay_enabled(self, enabled, reload_settings=True):
        self._set_setting_value("tgws_voip_relay_enabled", bool(enabled), reload_settings=bool(reload_settings))

    def _get_tgws_voip_relay_config(self):
        return _validate_tgws_voip_relay(
            self.get_setting("tgws_voip_relay_ip", TGWS_VOIP_RELAY_HOST),
            self.get_setting("tgws_voip_relay_port", str(TGWS_VOIP_RELAY_CONTROL_PORT)),
            self.get_setting("tgws_voip_relay_hmac", TGWS_VOIP_RELAY_SECRET.decode("utf-8")),
        )

    def _tgws_voip_relay_link(self):
        config, error = self._get_tgws_voip_relay_config()
        if config is None:
            return "", error
        relay_ip, relay_port, secret = config
        return "tg://relay?" + urllib.parse.urlencode({
            "ip": relay_ip,
            "port": relay_port,
            "h": secret,
        }), ""

    def _tgws_allocate_voip_relay(self, target_ip, target_port, timeout_sec=None):
        if not self._get_tgws_voip_relay_enabled() or not _is_telegram_reflector_ip(target_ip):
            return None
        try:
            config, _ = self._get_tgws_voip_relay_config()
            if config is None:
                return None
            relay_ip, relay_control_port, relay_secret = config
            relay_secret = relay_secret.encode("utf-8")
            target_port = int(target_port)
            if target_port <= 0 or target_port > 65535:
                return None
            nonce = os.urandom(16)

            def build_request(operation, request_nonce):
                body = bytearray((2, int(operation)))
                body.extend(struct.pack(">Q", int(time.time())))
                body.extend(request_nonce)
                body.extend(struct.pack(">IHH", _ipv4_to_int(target_ip), target_port, 0))
                body.extend(hmac.new(relay_secret, bytes(body), hashlib.sha256).digest())
                return bytes(body)

            def valid_response(data):
                return (
                    len(data) == 48
                    and data[0] == 2
                    and hmac.compare_digest(
                        data[16:],
                        hmac.new(relay_secret, data[:16], hashlib.sha256).digest(),
                    )
                )

            deadline = None if timeout_sec is None else time.monotonic() + max(0.05, float(timeout_sec))

            def receive_timeout():
                if deadline is None:
                    return float(TGWS_VOIP_RELAY_ALLOCATE_TIMEOUT_SEC)
                return max(0.05, deadline - time.monotonic())

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((relay_ip, relay_control_port))
                sock.send(build_request(1, nonce))
                sock.settimeout(receive_timeout())
                challenge = sock.recv(128)
                if not valid_response(challenge) or challenge[1] != 9:
                    return None
                allocation_nonce = nonce[:8] + challenge[8:16]
                sock.send(build_request(2, allocation_nonce))
                sock.settimeout(receive_timeout())
                data = sock.recv(128)
            if not valid_response(data) or data[8:16] != nonce[:8]:
                return None
            relay_port = struct.unpack(">H", data[2:4])[0]
            if data[1] != 0 or relay_port <= 0:
                return None
            return relay_ip, relay_port
        except:
            return None

    def _tgws_allocate_voip_relays(self, targets, timeout_sec=TGWS_VOIP_RELAY_ALLOCATE_TIMEOUT_SEC):
        targets = list(targets or [])
        if not targets:
            return []
        if time.monotonic() < float(getattr(self, "_tgws_voip_relay_retry_after", 0.0) or 0.0):
            return [None] * len(targets)
        deadline = time.monotonic() + max(0.05, float(timeout_sec))

        def allocate(target):
            return self._tgws_allocate_voip_relay(
                target[0], target[1], timeout_sec=max(0.05, deadline - time.monotonic())
            )

        with ThreadPoolExecutor(max_workers=min(16, len(targets))) as executor:
            relays = list(executor.map(allocate, targets))
        self._tgws_voip_relay_retry_after = 0.0 if any(relays) else time.monotonic() + 20.0
        return relays

    def _is_tgws_connection_ready(self, port=None):
        try:
            expected_port = int(port or self._tgws_port or 0)
        except:
            expected_port = 0
        if expected_port <= 0:
            return False
        return bool(
            self._is_local_tgws_proxy_applied(expected_port)
            and _check_vless_port(expected_port)
        )

    def _tgws_heal_if_due(self):
        now = time.time()
        try:
            last = float(getattr(self, "_tgws_last_heal_ts", 0.0) or 0.0)
        except:
            last = 0.0
        if last and (now - last) < float(TGWS_HEAL_COOLDOWN_SEC):
            return False
        self._tgws_last_heal_ts = float(now)
        try:
            self._tgws_core.self_heal()
            return True
        except:
            return False

    def _tgws_local_alive(self):
        try:
            return bool(self._tgws_running and self._tgws_port and _check_vless_port(self._tgws_port))
        except:
            return False

    def _tgws_unapply_local_proxy_for_background(self):
        self._tgws_ready = False
        try:
            port = int(self._tgws_port or 0)
        except:
            port = 0
        if port <= 0:
            try:
                owner, owner_port = self._local_socks_owner_snapshot()
                if owner == TGWS_KIND:
                    port = int(owner_port or 0)
            except:
                port = 0
        if port > 0:
            try:
                self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
            except:
                pass
        return True

    def _tgws_ensure_local_proxy(self):
        if not self._should_run_tgws():
            self._tgws_ready = False
            return False
        try:
            port = int(self._tgws_port or 0)
        except:
            port = 0
        if port <= 0 or not self._tgws_local_alive():
            self._tgws_ready = False
            if not bool(getattr(self, "_tgws_connecting", False)):
                self._tgws_connect()
            return False
        if not self._is_local_tgws_proxy_applied(port):
            if not self._apply_local_socks_proxy(port, True, owner=TGWS_KIND, secret=_tgws_proxy_secret_for_telegram()):
                self._tgws_ready = False
                if not bool(getattr(self, "_tgws_connecting", False)):
                    self._tgws_disconnect_with_reason("tgws_local_proxy_reapply_failed", silent=True)
                    self._tgws_connect()
                return False
        self._tgws_running = True
        self._tgws_ready = bool(self._is_tgws_connection_ready(port))
        return bool(self._tgws_ready)

    def _tgws_connect(self):
        if not self._should_run_tgws():
            self._tgws_ready = False
            return False
        with self._tgws_connect_lock:
            if bool(getattr(self, "_tgws_connecting", False)):
                return False
            self._tgws_connecting = True
            try:
                self._tgws_generation = int(getattr(self, "_tgws_generation", 0) or 0) + 1
            except:
                self._tgws_generation = 1
            generation = int(self._tgws_generation or 0)
        handed_off = False
        try:
            try:
                self._vless_disconnect_with_reason("tgws_connect_preempt", silent=True)
            except:
                pass
            self._tgws_ready = False
            if not self._should_run_tgws():
                return False
            port = _pick_tgws_port(TGWS_LOCAL_PORT)
            if int(port or 0) <= 0:
                self._tgws_running = False
                self._tgws_ready = False
                self._tgws_port = 0
                return False
            self._tgws_port = port
            config_json = json.dumps({"port": int(port), "verbose": False, "dc_ip": dict(TGWS_DEFAULT_DC_IP)})
            err = self._tgws_core.start(config_json)
            if err:
                self._tgws_running = False
                self._tgws_ready = False
                self._tgws_port = 0
                return False

            def _watchdog():
                self._tgws_ready = False

                def _same_generation():
                    try:
                        return int(getattr(self, "_tgws_generation", 0) or 0) == int(generation)
                    except:
                        return False

                def _is_current():
                    try:
                        return bool(
                            _same_generation()
                            and self._should_run_tgws()
                            and int(self._tgws_port or 0) == int(port)
                        )
                    except:
                        return False

                deadline = time.time() + float(TGWS_LOCAL_READY_TIMEOUT_SEC)
                while time.time() < deadline:
                    if not _is_current():
                        if _same_generation():
                            self._tgws_running = False
                            self._tgws_ready = False
                            try:
                                self._tgws_core.stop()
                            except:
                                pass
                        return
                    if _check_vless_port(port):
                        if not _is_current():
                            if _same_generation():
                                self._tgws_ready = False
                            return
                        if self._is_local_tgws_proxy_applied(port):
                            applied = True
                        else:
                            applied = self._apply_local_socks_proxy(port, True, owner=TGWS_KIND, secret=_tgws_proxy_secret_for_telegram())
                        apply_deadline = time.time() + 1.5
                        while applied and time.time() < apply_deadline:
                            if not _is_current():
                                if _same_generation():
                                    self._tgws_ready = False
                                    self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
                                return
                            if self._is_local_tgws_proxy_applied(port):
                                break
                            time.sleep(0.1)
                        if not applied or (not self._is_local_tgws_proxy_applied(port)):
                            if _same_generation():
                                self._tgws_running = False
                                self._tgws_ready = False
                                self._tgws_port = 0
                                try:
                                    self._tgws_core.stop()
                                except:
                                    pass
                            return
                        if not _is_current():
                            if _same_generation():
                                self._tgws_ready = False
                                self._clear_local_socks_proxy_if_port(port, owner=TGWS_KIND)
                            return
                        self._tgws_running = True
                        self._tgws_ready = False
                        self._save_config()
                        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                        confirm_deadline = time.time() + float(TGWS_CONNECT_CONFIRM_TIMEOUT_SEC)
                        connected = False
                        while time.time() < confirm_deadline:
                            if not _is_current():
                                if _same_generation():
                                    self._tgws_ready = False
                                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                                return
                            if self._is_tgws_connection_ready(port):
                                connected = True
                                break
                            time.sleep(0.5)
                        if connected:
                            self._tgws_ready = True
                            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                            run_on_ui_thread(lambda: BulletinHelper.show_success("TG WS подключен"))
                        else:
                            self._tgws_ready = False
                            self._tgws_heal_if_due()
                            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                            run_on_ui_thread(lambda: BulletinHelper.show_info("TG WS: соединяю..."))
                        return
                    time.sleep(0.3)
                if _same_generation():
                    self._tgws_running = False
                    self._tgws_ready = False
                    self._tgws_port = 0
                    try:
                        self._tgws_core.stop()
                    except:
                        pass
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

            def _watchdog_wrapped():
                try:
                    _watchdog()
                finally:
                    changed = False
                    try:
                        if int(getattr(self, "_tgws_generation", 0) or 0) == int(generation):
                            changed = bool(getattr(self, "_tgws_connecting", False))
                            self._tgws_connecting = False
                    except:
                        changed = bool(getattr(self, "_tgws_connecting", False))
                        self._tgws_connecting = False
                    if changed:
                        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

            threading.Thread(target=_watchdog_wrapped, daemon=True).start()
            handed_off = True
            return True
        except Exception:
            self._tgws_running = False
            self._tgws_ready = False
            self._tgws_port = 0
            try:
                self._tgws_core.stop()
            except:
                pass
            return False
        finally:
            if not handed_off:
                self._tgws_connecting = False

    def _tgws_disconnect_with_reason(self, reason, silent=False):
        self._tgws_disconnect(silent=bool(silent))

    def _tgws_disconnect(self, silent=False):
        old_port = int(self._tgws_port or 0)
        try:
            self._tgws_generation = int(getattr(self, "_tgws_generation", 0) or 0) + 1
        except:
            self._tgws_generation = 1
        try:
            self._tgws_core.stop()
        except:
            pass
        self._tgws_running = False
        self._tgws_ready = False
        self._tgws_port = 0
        self._tgws_connecting = False
        if old_port > 0:
            self._clear_local_socks_proxy_if_port(old_port, owner=TGWS_KIND)
        if not silent:
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _switch_to_tgws_mode(self, persist_mode=True):
        if persist_mode:
            self._set_connection_mode(TGWS_KIND)
        self._vless_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        self._awg_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        self._olcrtc_disconnect_with_reason("switch_to_tgws_mode", silent=True)
        if self._is_plugin_proxy_enabled():
            self._tgws_connect()
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

# --- main.py ---


class SafeBypassPlugin(SettingsUiMixin, SingBoxModeMixin, AwgModeMixin, OlcRtcModeMixin, TgWsModeMixin, BasePlugin):
    def create_settings(self):
        return SettingsUiMixin.create_settings(self)

    def __init__(self):
        super().__init__()
        self.name = __name__
        self._active = False
        self._thread = None
        self._worker_stop = threading.Event()
        self._reload_ui_pending = False
        self._settings_theme_observer = None
        self._tgws_connecting = False
        self._tgws_ready = False
        self._tgws_generation = 0
        self._tgws_last_heal_ts = 0.0
        self._tgws_backgrounded = False
        self._tgws_connect_lock = threading.Lock()
        self._proxy_suspended_by_vpn = False
        self._proxy_suspended_by_wifi = False
        self._excluded_wifi_ssids = []
        self._wifi_mode_rules = {}
        self._wifi_default_mode = AWG_KIND
        self._wifi_rule_active_ssid = ""
        self._wifi_rule_switching = False
        self._current_wifi_ssid_cache = ""
        self._vpn_policy_lock = threading.Lock()
        self._chat_menu_item_id = "greenpass_settings_open"
        self._drawer_menu_item_id = "greenpass_settings_drawer"
        self._proxy_button_hooks_installed = False
        self._sync_hooks_installed = False
        self._proxy_killswitch_hook_installed = False
        self._awg_activity_hook_installed = False
        self._browser_vless_hook_installed = False
        self._voip_relay_link_hook_installed = False
        self._text_vless_hook_installed = False
        self._cell_vless_hook_installed = False
        self._greenpass_file_hook_installed = False
        self._voip_relay_hook_installed = False
        self._webrtc_relay_hook_installed = False
        self._plugin_proxy_python_patch_installed = False
        self._plugin_proxy_originals = {}
        self._plugin_proxy_frida_registered = False
        self._plugin_proxy_frida_endpoint_key = ""
        self._plugin_proxy_last_error = ""
        # WebProxy is an additional Telegram proxy type.  Keep its adapter state
        # alongside GreenPass so saved WEB relays survive plugin reloads.
        self._webproxy = WebProxyNativePlugin()

        self._current_server = ""
        self._current_port = 0
        self._desired_use_proxy = False
        self._connection_mode = AWG_KIND
        self._tgws_port = 0
        self._tgws_running = False
        self._awg_port = 0
        self._awg_running = False
        self._awg_connecting = False
        self._awg_started_conf = ""
        self._awg_prepare_in_progress = False
        self._awg_conf_name = ""
        self._awg_conf_content = ""
        self._awg_config_downloading = False
        self._awg_conf_is_free = False
        self._awg_health_thread = None
        self._awg_health_stop = threading.Event()
        self._awg_health_gen = 0
        self._awg_health_recovering = False
        self._awg_health_restarts = 0
        self._awg_health_hold_until = 0.0
        self._awg_last_refresh_ts = 0.0
        self._awg_refresh_failures = 0
        self._awg_ipv4_only = False
        self._ipv6_hook_installed = False
        self._vless_core_op_lock = threading.Lock()
        self._olcrtc_port = 0
        self._olcrtc_running = False
        self._olcrtc_connecting = False
        self._olcrtc_backgrounded = False
        self._olcrtc_health_stale = False
        self._olcrtc_resume_checking = False
        self._olcrtc_feedback_requested = False
        self._olcrtc_dead_checks = 0
        self._olcrtc_profiles = []
        self._olcrtc_active_profile_id = ""
        self._olcrtc_prepare_in_progress = False
        self._olcrtc_generation = 0
        self._olcrtc_start_in_progress = False
        self._olcrtc_connect_lock = threading.Lock()
        self._olcrtc_connect_worker_active = False
        self._olcrtc_connect_pending = False
        self._olcrtc_stop_lock = threading.Lock()
        self._olcrtc_stop_in_progress = False
        self._olcrtc_last_error = ""
        self._olcrtc_last_log = ""
        self._vless_port = 0
        self._vless_running = False
        self._vless_connecting = False
        self._vless_last_error = ""
        self._vless_generation = 0
        self._vless_transition_lock = threading.RLock()
        self._vless_connect_lock = threading.Lock()
        self._vless_connect_worker_active = False
        self._vless_connect_pending = False
        self._vless_engine = VLESS_ENGINE_SINGBOX
        self._vless_socks_username = ""
        self._vless_socks_password = ""
        self._vless_local_owner = VLESS_KIND
        self._vless_active_config_key = ""
        self._vless_backgrounded = False
        self._vless_backgrounded_at = 0.0
        self._vless_resume_reconnect = False
        self._vless_resume_recovery_token = 0
        self._vless_retry_failures = 0
        self._vless_retry_after = 0.0
        self._vless_avoid_preferred_port_once = False
        self._local_socks_lock = threading.RLock()
        self._local_socks_owner = ""
        self._local_socks_port = 0
        self._vless_data = {"manual": [], "subs": [], "active_uri": ""}
        self._qwdtt_data = {"profiles": [], "subs": [], "active_id": ""}
        self._vless_prepare_in_progress = False
        self._autoupdate_last_check_ts = 0
        self._autoupdate_last_seen_version = ""
        self._autoupdate_in_progress = False
        self._libsingbox_install_lock = threading.Lock()
        self._libsingbox_validation_lock = threading.Lock()
        self._libsingbox_validation_in_progress = False
        self._libsingbox_validation_cache = None
        self._core_restart_required_pid = 0
        self._core_restart_reason = ""
        self._core_restart_resume_mode = ""
        self._core_restart_resume_enabled = False
        self._core_restart_resumed = False
        self._config_needs_save = False
        self._proxy_transition_state_lock = threading.Lock()
        self._proxy_transition_next_lease = 1
        self._proxy_transition_active_leases = set()
        self._proxy_transition_paused_accounts = []
        self._proxy_transition_param_leases = {}

        try:
            ctx = ApplicationLoader.applicationContext
            self._config_file = os.path.join(ctx.getFilesDir().getAbsolutePath(), "safebypass_v2_config.json")
            self._vless_dir = os.path.join(ctx.getFilesDir().getAbsolutePath(), "greenpass_modules")
        except:
            self._config_file = "safebypass_v2_config.json"
            self._vless_dir = "greenpass_modules"

        try:
            self._plugin_file_path = os.path.abspath(str(__file__ or ""))
        except:
            self._plugin_file_path = os.path.abspath("GreenPass.plugin")

        try:
            if not os.path.exists(self._vless_dir):
                os.makedirs(self._vless_dir)
        except:
            pass

        self._tgws_core = TgWsCore()
        self._vless_core = _LazySingboxCore(self._libvless_so_path())
        self._awg_core = _LazyAWGCore(self._libawg_so_path())
        self._olcrtc_core = _LazyVlessCore(self._libzvonki_so_path())

        self._load_config()
        if self._config_needs_save:
            self._save_config()
        if self._core_restart_resumed:
            self._cleanup_legacy_core_files()

    def _atomic_write_json(self, path, data):
        path = str(path)
        try:
            suffix = "%s.%s" % (int(threading.get_ident()), int(time.time() * 1000000))
        except:
            suffix = str(int(time.time() * 1000000))
        tmp = path + "." + suffix + ".tmp"
        try:
            payload = json.dumps(data)
            with open(tmp, 'w') as f:
                f.write(payload)
                try:
                    f.flush()
                    os.fsync(f.fileno())
                except:
                    pass
            os.replace(tmp, path)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except:
                pass
            raise

    def _recover_config_from_backup(self):
        if getattr(self, "_config_recovering", False):
            return
        bak = self._config_file + ".bak"
        try:
            if not os.path.exists(bak):
                return
        except:
            return
        self._config_recovering = True
        try:
            with open(bak, 'r') as bf:
                good = bf.read()
            data = json.loads(good)
            self._atomic_write_json(self._config_file, data)
            self._load_config()
        except Exception:
            pass
        finally:
            self._config_recovering = False

    def _load_config(self):
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, 'r') as f:
                    data = json.load(f)
                    _saved_schema = int(data.get("config_schema", 0) or 0)
                    _saved_version = str(data.get("last_loaded_version", "") or "")
                    _cur_major = str(__version__).split(".")[0]
                    _saved_major = _saved_version.split(".")[0] if _saved_version else ""
                    _stale = (_saved_schema < self._GREENPASS_CONFIG_SCHEMA) or (
                        bool(_saved_major) and _saved_major != _cur_major
                    )
                    self._current_server = data.get("server", "")
                    self._current_port = data.get("port", 0)
                    self._connection_mode = str(data.get("connection_mode", AWG_KIND) or AWG_KIND)
                    self._desired_use_proxy = bool(data.get("desired_use_proxy", data.get("use_proxy", False)))
                    saved_socks_password = str(data.get("vless_socks_password", "") or "").strip().lower()
                    self._vless_socks_password = saved_socks_password if re.fullmatch(r"[0-9a-f]{32}", saved_socks_password) else ""
                    self._vless_engine = _normalize_vless_engine(data.get("vless_engine", VLESS_ENGINE_SINGBOX))
                    _current_pid = int(os.getpid())
                    _restart_pid = int(data.get("core_restart_required_pid", 0) or 0)
                    _restart_reason = str(data.get("core_restart_reason", "") or "")
                    self._core_restart_resume_mode = str(data.get("core_restart_resume_mode", "") or "")
                    self._core_restart_resume_enabled = bool(data.get("core_restart_resume_enabled", False))
                    if _restart_pid and _restart_pid != _current_pid:
                        self._core_restart_required_pid = 0
                        self._core_restart_reason = ""
                        if self._core_restart_resume_mode:
                            self._connection_mode = self._core_restart_resume_mode
                        self._desired_use_proxy = self._core_restart_resume_enabled
                        self._core_restart_resumed = True
                        self._config_needs_save = True
                    elif _restart_pid and _restart_reason == "library_update":
                        self._core_restart_required_pid = _restart_pid
                        self._core_restart_reason = _restart_reason
                        if self._core_restart_resume_mode:
                            self._connection_mode = self._core_restart_resume_mode
                        _gp_set_go_core_blocked(True)
                    elif _restart_pid:
                        self._core_restart_required_pid = 0
                        self._core_restart_reason = ""
                        if self._core_restart_resume_mode:
                            self._connection_mode = self._core_restart_resume_mode
                        self._desired_use_proxy = self._core_restart_resume_enabled
                        self._config_needs_save = True
                    if _stale:
                        self._config_needs_save = True
                    self._autoupdate_last_check_ts = int(data.get("autoupdate_last_check_ts", 0) or 0)
                    self._autoupdate_last_seen_version = str(data.get("autoupdate_last_seen_version", "") or "")
                    self._proxy_suspended_by_vpn = False
                    self._proxy_suspended_by_wifi = False
                    self._excluded_wifi_ssids = self._sanitize_excluded_wifi_ssids(data.get("excluded_wifi_ssids", []))
                    self._wifi_mode_rules = self._sanitize_wifi_mode_rules(data.get("wifi_mode_rules", {}))
                    for _ssid in self._excluded_wifi_ssids:
                        self._wifi_mode_rules.setdefault(_ssid, "off")
                    self._excluded_wifi_ssids = [
                        _ssid for _ssid, _mode in self._wifi_mode_rules.items() if _mode == "off"
                    ]
                    self._wifi_default_mode = self._normalize_proxy_mode(
                        data.get("wifi_default_mode", self._connection_mode), self._connection_mode
                    )
                    awg_data = data.get("awg_data", None)
                    if isinstance(awg_data, dict):
                        self._awg_conf_name = str(awg_data.get("conf_name", "") or "")
                        self._awg_conf_content = str(awg_data.get("conf_content", "") or "")
                        if "conf_is_free" in awg_data:
                            self._awg_conf_is_free = bool(awg_data.get("conf_is_free"))
                        else:
                            self._awg_conf_is_free = _infer_awg_conf_is_free(self._awg_conf_name, self._awg_conf_content)
                    else:
                        self._awg_conf_name = ""
                        self._awg_conf_content = ""
                        self._awg_conf_is_free = False
                    vless_data = data.get("vless_data", None)
                    if isinstance(vless_data, dict):
                        manual = vless_data.get("manual", [])
                        subs = vless_data.get("subs", [])
                        active_uri = vless_data.get("active_uri", "")
                        self._vless_data = {
                            "manual": manual if isinstance(manual, list) else [],
                            "subs": subs if isinstance(subs, list) else [],
                            "active_uri": str(active_uri or ""),
                        }
                    else:
                        self._vless_data = {"manual": [], "subs": [], "active_uri": ""}

                    qwdtt_data = data.get("qwdtt_data", None)
                    if isinstance(qwdtt_data, dict):
                        self._qwdtt_data = {
                            "profiles": self._sanitize_qwdtt_profiles(qwdtt_data.get("profiles", [])),
                            "subs": self._sanitize_qwdtt_subscriptions(qwdtt_data.get("subs", [])),
                            "active_id": str(qwdtt_data.get("active_id", "") or ""),
                        }
                        if self._qwdtt_data["active_id"] and not self._find_qwdtt_profile(self._qwdtt_data["active_id"]):
                            self._qwdtt_data["active_id"] = ""
                    else:
                        self._qwdtt_data = {"profiles": [], "subs": [], "active_id": ""}

                    legacy_qwdtt_nodes = [self._qwdtt_node_from_profile(profile) for profile in self._iter_qwdtt_profiles()]
                    legacy_qwdtt_nodes = [node for node in legacy_qwdtt_nodes if node]
                    if legacy_qwdtt_nodes:
                        known = {str(node.get("uri", "") or "") for node in legacy_qwdtt_nodes}
                        self._vless_data["manual"] = (legacy_qwdtt_nodes + [node for node in list(self._vless_data.get("manual", []) or []) if str(node.get("uri", "") or "") not in known])[:64]
                        if self._connection_mode == QWDTT_KIND and not self._vless_data.get("active_uri"):
                            self._vless_data["active_uri"] = str(legacy_qwdtt_nodes[0].get("uri", "") or "")
                        self._qwdtt_data = {"profiles": [], "subs": [], "active_id": ""}
                        self._config_needs_save = True
                    if self._connection_mode == QWDTT_KIND:
                        self._connection_mode = VLESS_KIND
                        self._config_needs_save = True
                    if self._wifi_default_mode == QWDTT_KIND:
                        self._wifi_default_mode = VLESS_KIND
                    self._connection_mode = self._normalize_proxy_mode(
                        self._wifi_default_mode, self._connection_mode
                    )

                    olcrtc_data = data.get("olcrtc_data", None)
                    if isinstance(olcrtc_data, dict):
                        profiles = olcrtc_data.get("profiles", [])
                        self._olcrtc_profiles = self._sanitize_olcrtc_profiles(profiles if isinstance(profiles, list) else [])
                        self._olcrtc_active_profile_id = str(olcrtc_data.get("active_profile_id", "") or "")
                        if self._olcrtc_active_profile_id and not self._find_olcrtc_profile(self._olcrtc_active_profile_id):
                            self._olcrtc_active_profile_id = ""
                    else:
                        self._olcrtc_profiles = []
                        self._olcrtc_active_profile_id = ""
                    self._ensure_olcrtc_legacy_profile()
                    active_olcrtc_profile = self._active_olcrtc_profile()
                    if active_olcrtc_profile:
                        self._set_olcrtc_legacy_settings_from_profile(active_olcrtc_profile)

                try:
                    self._atomic_write_json(self._config_file + ".bak", data)
                except:
                    pass
        except Exception:
            self._recover_config_from_backup()
        try:
            prefs = ApplicationLoader.applicationContext.getSharedPreferences("greenpass_prefs", 0)
            persisted_password = str(prefs.getString("vless_socks_password", "") or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{32}", persisted_password):
                self._vless_socks_password = persisted_password
            else:
                if not re.fullmatch(r"[0-9a-f]{32}", str(self._vless_socks_password or "")):
                    self._vless_socks_password = os.urandom(16).hex()
                prefs.edit().putString("vless_socks_password", self._vless_socks_password).commit()
                self._config_needs_save = True
        except:
            if not re.fullmatch(r"[0-9a-f]{32}", str(self._vless_socks_password or "")):
                self._vless_socks_password = os.urandom(16).hex()
                self._config_needs_save = True
        if not self._core_restart_required():
            _gp_set_go_core_blocked(False)

    _GREENPASS_CONFIG_SCHEMA = 3

    def _save_config(self):
        try:
            data = {
                "server": self._current_server,
                "port": self._current_port,
                "connection_mode": str(self._connection_mode or AWG_KIND),
                "desired_use_proxy": bool(self._desired_use_proxy),
                "vless_engine": _normalize_vless_engine(self._vless_engine),
                "vless_socks_password": str(self._vless_socks_password or ""),
                "config_schema": int(self._GREENPASS_CONFIG_SCHEMA),
                "last_loaded_version": str(__version__),
                "core_restart_required_pid": int(self._core_restart_required_pid or 0),
                "core_restart_reason": str(self._core_restart_reason or ""),
                "core_restart_resume_mode": str(self._core_restart_resume_mode or ""),
                "core_restart_resume_enabled": bool(self._core_restart_resume_enabled),
                "autoupdate_last_check_ts": int(self._autoupdate_last_check_ts or 0),
                "autoupdate_last_seen_version": str(self._autoupdate_last_seen_version or ""),
                "proxy_suspended_by_vpn": bool(self._proxy_suspended_by_vpn),
                "excluded_wifi_ssids": self._sanitize_excluded_wifi_ssids(self._excluded_wifi_ssids),
                "wifi_mode_rules": self._sanitize_wifi_mode_rules(self._wifi_mode_rules),
                "wifi_default_mode": self._normalize_proxy_mode(self._wifi_default_mode, self._connection_mode),
                "awg_data": {
                    "conf_name": str(self._awg_conf_name or ""),
                    "conf_content": str(self._awg_conf_content or ""),
                    "conf_is_free": bool(self._awg_conf_is_free),
                },
                "vless_data": self._vless_data,
                "olcrtc_data": {
                    "profiles": self._sanitize_olcrtc_profiles(self._olcrtc_profiles),
                    "active_profile_id": str(self._olcrtc_active_profile_id or ""),
                },
            }
            self._atomic_write_json(self._config_file, data)
            try:
                self._atomic_write_json(self._config_file + ".bak", data)
            except:
                pass
        except Exception:
            pass

    def _greenpass_settings_keys(self):
        return (
            "use_proxy",
            "proxy_calls_via_proxy",
            "tgws_voip_relay_enabled",
            "tgws_voip_relay_ip",
            "tgws_voip_relay_port",
            "tgws_voip_relay_hmac",
            "dont_use_with_vpn",
            "proxy_plugins_via_greenpass",
            "subscription_hwid_custom",
            "olcrtc_carrier",
            "olcrtc_transport",
            "olcrtc_room_id",
            "olcrtc_client_id",
            "olcrtc_key_hex",
            "olcrtc_vp8_fps",
            "olcrtc_vp8_batch_size",
            "vless_browser_page_size",
            "vless_auto_check_minutes",
            "vless_failover_enabled",
            "vless_browser_hidden_sources",
        )

    def _greenpass_repair_settings_keys(self):
        return self._greenpass_settings_keys()

    def _greenpass_setting_default(self, key):
        key = str(key or "")
        if key == "use_proxy":
            try:
                return bool(self._desired_use_proxy)
            except:
                return False
        defaults = {
            "proxy_calls_via_proxy": False,
            "tgws_voip_relay_enabled": True,
            "tgws_voip_relay_ip": TGWS_VOIP_RELAY_HOST,
            "tgws_voip_relay_port": str(TGWS_VOIP_RELAY_CONTROL_PORT),
            "tgws_voip_relay_hmac": TGWS_VOIP_RELAY_SECRET.decode("utf-8"),
            "dont_use_with_vpn": True,
            "proxy_plugins_via_greenpass": False,
            "subscription_hwid_custom": "",
            "olcrtc_carrier": 0,
            "olcrtc_transport": 0,
            "olcrtc_room_id": "",
            "olcrtc_client_id": "",
            "olcrtc_key_hex": "",
            "olcrtc_vp8_fps": "60",
            "olcrtc_vp8_batch_size": "64",
            "vless_browser_page_size": 20,
            "vless_auto_check_minutes": 0,
            "vless_failover_enabled": True,
            "vless_browser_hidden_sources": "[]",
        }
        return defaults.get(key, "")

    def _sanitize_greenpass_setting_value(self, key, value):
        key = str(key or "")
        if key not in self._greenpass_repair_settings_keys():
            return None
        if value is None:
            value = self._greenpass_setting_default(key)
        if key in ("use_proxy", "proxy_calls_via_proxy", "tgws_voip_relay_enabled", "dont_use_with_vpn", "proxy_plugins_via_greenpass", "vless_failover_enabled"):
            if isinstance(value, str):
                return value.strip().lower() not in ("", "0", "false", "off", "no")
            return bool(value)
        if key in ("olcrtc_carrier", "olcrtc_transport", "vless_browser_page_size", "vless_auto_check_minutes"):
            try:
                return int(value)
            except:
                return int(self._greenpass_setting_default(key) or 0)
        if key == "vless_browser_hidden_sources":
            try:
                values = value if isinstance(value, (list, tuple, set)) else json.loads(str(value or "[]"))
                return json.dumps(sorted({str(item or "").strip() for item in list(values or []) if str(item or "").strip()}), ensure_ascii=False, separators=(",", ":"))
            except:
                return "[]"
        return str(value or "")

    def _repair_greenpass_settings_nulls(self):
        sentinel = object()
        for key in self._greenpass_repair_settings_keys():
            try:
                raw = self.get_setting(str(key), sentinel)
            except:
                continue
            if raw is None:
                try:
                    value = self._sanitize_greenpass_setting_value(key, raw)
                    if value is not None:
                        self._set_setting_value(key, value, reload_settings=False)
                except:
                    pass

    def _greenpass_export_settings(self):
        settings = {}
        sentinel = object()
        for key in self._greenpass_settings_keys():
            try:
                raw = self.get_setting(str(key), sentinel)
                if raw is sentinel:
                    continue
                value = self._sanitize_greenpass_setting_value(key, raw)
                if value is not None:
                    settings[str(key)] = value
            except:
                pass
        try:
            settings["use_proxy"] = bool(self._desired_use_proxy)
        except:
            pass
        return settings

    def _greenpass_current_config_snapshot(self):
        try:
            self._save_config()
        except:
            pass
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, "r") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
        except:
            pass
        return {
            "server": self._current_server,
            "port": self._current_port,
            "connection_mode": str(self._connection_mode or AWG_KIND),
            "desired_use_proxy": bool(self._desired_use_proxy),
            "vless_engine": _normalize_vless_engine(self._vless_engine),
            "vless_socks_password": str(self._vless_socks_password or ""),
            "proxy_suspended_by_vpn": bool(self._proxy_suspended_by_vpn),
            "excluded_wifi_ssids": self._sanitize_excluded_wifi_ssids(self._excluded_wifi_ssids),
            "wifi_mode_rules": self._sanitize_wifi_mode_rules(self._wifi_mode_rules),
            "wifi_default_mode": self._normalize_proxy_mode(self._wifi_default_mode, self._connection_mode),
            "awg_data": {
                "conf_name": str(self._awg_conf_name or ""),
                "conf_content": str(self._awg_conf_content or ""),
                "conf_is_free": bool(self._awg_conf_is_free),
            },
            "vless_data": self._vless_data,
            "olcrtc_data": {
                "profiles": self._sanitize_olcrtc_profiles(self._olcrtc_profiles),
                "active_profile_id": str(self._olcrtc_active_profile_id or ""),
            },
        }

    def _greenpass_export_payload(self):
        return {
            "format": GREENPASS_EXPORT_FORMAT,
            "plugin_id": str(__id__),
            "plugin_version": str(__version__),
            "exported_at": int(time.time()),
            "config": self._greenpass_current_config_snapshot(),
            "settings": self._greenpass_export_settings(),
        }

    def _greenpass_export_bytes(self):
        raw = json.dumps(self._greenpass_export_payload(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return gzip.compress(raw)

    def _greenpass_export_file_path(self):
        try:
            base_dir = os.path.dirname(os.path.abspath(str(self._config_file or "")))
        except:
            base_dir = ""
        if not base_dir:
            try:
                base_dir = os.path.abspath(str(self._vless_dir or ""))
            except:
                base_dir = ""
        if base_dir:
            try:
                if not os.path.exists(base_dir):
                    os.makedirs(base_dir)
            except:
                pass
            return os.path.join(base_dir, GREENPASS_EXPORT_FILE_NAME)
        return GREENPASS_EXPORT_FILE_NAME

    def _export_settings_to_favorites(self):
        def _worker():
            try:
                file_path = self._greenpass_export_file_path()
                payload = self._greenpass_export_bytes()
                with open(file_path, "wb") as f:
                    f.write(payload)
                account = _selected_account()
                user_id = UserConfig.getInstance(account).getClientUserId()

                def _send():
                    try:
                        _send_document_as(account, user_id, file_path, caption=GREENPASS_EXPORT_FILE_NAME)
                        BulletinHelper.show_success("Экспорт отправлен")
                    except Exception as send_exc:
                        BulletinHelper.show_error("Ошибка отправки: %s" % str(send_exc))

                run_on_ui_thread(_send)
            except Exception as exc:
                err_text = str(exc)
                run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка экспорта: %s" % err_text))

        threading.Thread(target=_worker, daemon=True).start()

    def _current_activity(self):
        activity = None
        try:
            fragment = get_last_fragment()
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            try:
                AU = find_class("org.telegram.messenger.AndroidUtilities")
                activity = AU.getActivity()
            except:
                activity = None
        return activity


    def _read_greenpass_import_uri_bytes(self, uri):
        activity = self._current_activity()
        if activity is None:
            raise Exception("activity is missing")
        resolver = activity.getContentResolver()
        stream = None
        out = None
        try:
            ByteArrayOutputStream = jclass("java.io.ByteArrayOutputStream") if jclass is not None else find_class("java.io.ByteArrayOutputStream")
            stream = resolver.openInputStream(uri)
            if stream is None:
                raise Exception("stream is missing")
            out = ByteArrayOutputStream()
            try:
                from java import jarray, jbyte
                buffer = jarray(jbyte)(8192)
            except:
                buffer = None
            if buffer is None:
                value = int(stream.read())
                while value != -1:
                    out.write(value)
                    value = int(stream.read())
            else:
                read_count = int(stream.read(buffer))
                while read_count != -1:
                    if read_count > 0:
                        out.write(buffer, 0, read_count)
                    read_count = int(stream.read(buffer))
            arr = out.toByteArray()
            return bytes([(int(arr[i]) + 256) % 256 for i in range(len(arr))])
        finally:
            try:
                if out is not None:
                    out.close()
            except:
                pass
            try:
                if stream is not None:
                    stream.close()
            except:
                pass

    def _decode_greenpass_export_bytes(self, raw_bytes):
        decoded = gzip.decompress(bytes(raw_bytes))
        payload = json.loads(decoded.decode("utf-8"))
        if not isinstance(payload, dict):
            raise Exception("bad export")
        if str(payload.get("format", "") or "") != GREENPASS_EXPORT_FORMAT:
            raise Exception("bad format")
        if not isinstance(payload.get("config", None), dict):
            raise Exception("missing config")
        settings = payload.get("settings", {})
        if settings is not None and not isinstance(settings, dict):
            raise Exception("bad settings")
        return payload

    def _process_greenpass_import_bytes(self, raw):
        payload = self._decode_greenpass_export_bytes(raw)
        self._apply_greenpass_import_payload(payload)

    def _process_greenpass_import_file_path(self, file_path):
        try:
            with open(str(file_path), "rb") as f:
                raw = f.read()
            self._process_greenpass_import_bytes(raw)
            run_on_ui_thread(lambda: BulletinHelper.show_success("Импорт выполнен"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка импорта: %s" % err_text))

    def _apply_greenpass_import_payload(self, payload):
        config = payload.get("config", {})
        settings = payload.get("settings", {}) or {}
        if not isinstance(config, dict):
            raise Exception("missing config")
        self._atomic_write_json(self._config_file, config)
        try:
            self._atomic_write_json(self._config_file + ".bak", config)
        except:
            pass
        self._load_config()
        for key in self._greenpass_settings_keys():
            if key in settings:
                try:
                    value = self._sanitize_greenpass_setting_value(key, settings.get(key))
                    if value is not None:
                        self._set_setting_value(key, value, reload_settings=False)
                except:
                    pass
        try:
            _set_subscription_hwid_custom(self.get_setting("subscription_hwid_custom", ""))
        except:
            pass
        try:
            desired = bool(settings.get("use_proxy", config.get("desired_use_proxy", False)))
        except:
            desired = bool(getattr(self, "_desired_use_proxy", False))
        self._on_use_proxy_changed(desired)
        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        self._refresh_settings_without_reopen()

    def _process_greenpass_import_file_uri(self, uri):
        try:
            raw = self._read_greenpass_import_uri_bytes(uri)
            self._process_greenpass_import_bytes(raw)
            run_on_ui_thread(lambda: BulletinHelper.show_success("Импорт выполнен"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка импорта: %s" % err_text))

    def _greenpass_document_name(self, message_object):
        try:
            name = message_object.getDocumentName()
            if name:
                return str(name)
        except:
            pass
        try:
            doc = message_object.getDocument()
        except:
            doc = None
        try:
            attrs = getattr(doc, "attributes", None)
            if attrs is not None:
                for attr in list(attrs or []):
                    try:
                        file_name = str(getattr(attr, "file_name", "") or "")
                    except:
                        file_name = ""
                    if file_name:
                        return file_name
        except:
            pass
        return ""

    def _is_greenpass_export_file_name(self, name):
        try:
            return str(name or "").strip().lower().endswith(".greenpass")
        except:
            return False

    def _is_singconf_file_name(self, name):
        try:
            return str(name or "").strip().lower().endswith(".singconf")
        except:
            return False

    def _is_mihomo_file_name(self, name):
        try:
            return str(name or "").strip().lower().endswith(".mihomo")
        except:
            return False

    def _is_qwdtt_file_name(self, name):
        try:
            return str(name or "").strip().lower().endswith(".qwdtt")
        except:
            return False

    def _greenpass_message_file_path(self, message_object):
        try:
            ChatUtils = jclass("com.exteragram.messenger.utils.chats.ChatUtils") if jclass is not None else find_class("com.exteragram.messenger.utils.chats.ChatUtils")
            path = ChatUtils.getInstance().getPathToMessage(message_object)
            if path:
                return str(path)
        except:
            pass
        try:
            owner = getattr(message_object, "messageOwner", None)
            media = getattr(owner, "media", None) if owner is not None else None
            doc = getattr(media, "document", None) if media is not None else None
            local_path = str(getattr(doc, "localPath", "") or "")
            if local_path:
                return local_path
        except:
            pass
        try:
            doc = message_object.getDocument()
            if doc is not None and hasattr(doc, "getPathName"):
                path = doc.getPathName()
                if path:
                    return str(path)
        except:
            pass
        try:
            doc = message_object.getDocument()
            if doc is not None and hasattr(doc, "getLocalPath"):
                path = doc.getLocalPath()
                if path:
                    return str(path)
        except:
            pass
        try:
            FileLoader = jclass("org.telegram.messenger.FileLoader") if jclass is not None else find_class("org.telegram.messenger.FileLoader")
            doc = message_object.getDocument()
            if doc is not None:
                account = getattr(message_object, "currentAccount", None)
                if account is None:
                    account = _selected_account()
                path_obj = FileLoader.getInstance(int(account)).getPathToAttach(doc, True)
                if path_obj:
                    return str(path_obj.getAbsolutePath() if hasattr(path_obj, "getAbsolutePath") else path_obj)
        except:
            pass
        return ""





    def _process_singconf_import_file_path(self, file_path, display_name=""):
        try:
            with open(str(file_path), "r", encoding="utf-8") as f:
                text = f.read()
            node = _singbox_node_from_config_text(text, display_name or os.path.basename(str(file_path)))
            prepared = _prepare_singbox_file_config(text, VLESS_LOCAL_PORT)
            validation_error = self._validate_core_config_for_import(prepared, "sing-box config")
            if validation_error:
                raise Exception(validation_error)
            self._vless_engine = VLESS_ENGINE_SINGBOX
            self._save_vless_manual_node(node)
            self._set_connection_mode(VLESS_KIND)
            if self._is_plugin_proxy_enabled():
                self._reset_vless_retry()
                self._ensure_vless_core_then(self._vless_connect)
            self._refresh_settings_without_reopen(reload_main=True)
            run_on_ui_thread(lambda: BulletinHelper.show_success("sing-box конфиг импортирован"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка импорта: %s" % err_text))

    def _process_qwdtt_import_file_path(self, file_path):
        try:
            with open(str(file_path), "r", encoding="utf-8") as f:
                text = f.read(1024 * 1024)
            count = self._import_qwdtt_payload(text, activate_first=True)
            if count <= 0:
                raise Exception("неверный формат qWDTT")
            run_on_ui_thread(lambda: BulletinHelper.show_success("qWDTT импортирован"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка qWDTT: %s" % err_text))

    def _process_mihomo_import_file_path(self, file_path, display_name=""):
        try:
            with open(str(file_path), "r", encoding="utf-8") as f:
                text = f.read(MIHOMO_CONFIG_MAX_BYTES + 1)
            node = _mihomo_node_from_config_text(text, display_name or os.path.basename(str(file_path)))
            prepared = _build_mihomo_core_config(
                config_text=text,
                local_port=VLESS_LOCAL_PORT,
                work_dir=os.path.join(self._vless_dir, "mihomo"),
                socks_username="greenpass",
                socks_password=str(self._vless_socks_password or ""),
            )
            validation_error = self._validate_core_config_for_import(prepared, "Mihomo config")
            if validation_error:
                raise Exception(validation_error)
            self._vless_engine = VLESS_ENGINE_MIHOMO
            self._save_vless_manual_node(node)
            self._set_connection_mode(VLESS_KIND)
            if self._is_plugin_proxy_enabled():
                self._reset_vless_retry()
                self._ensure_vless_core_then(self._vless_connect)
            self._refresh_settings_without_reopen(reload_main=True)
            run_on_ui_thread(lambda: BulletinHelper.show_success("Mihomo конфиг импортирован"))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка импорта: %s" % err_text))

    def _handle_greenpass_file_open(self, message_object):
        name = self._greenpass_document_name(message_object)
        is_greenpass = self._is_greenpass_export_file_name(name)
        is_singconf = self._is_singconf_file_name(name)
        is_mihomo = self._is_mihomo_file_name(name)
        is_qwdtt = self._is_qwdtt_file_name(name)
        if not is_greenpass and not is_singconf and not is_mihomo and not is_qwdtt:
            return False
        file_path = self._greenpass_message_file_path(message_object)
        if not file_path:
            BulletinHelper.show_info("Сначала скачайте файл")
            return True
        try:
            if not os.path.exists(str(file_path)):
                BulletinHelper.show_info("Сначала скачайте файл")
                return True
        except:
            pass
        if is_qwdtt:
            run_on_ui_thread(lambda file_path=file_path, name=name: self._confirm_qwdtt_file_import(file_path, name))
        elif is_mihomo:
            run_on_ui_thread(lambda file_path=file_path, name=name: self._confirm_mihomo_file_import(file_path, name))
        elif is_singconf:
            run_on_ui_thread(lambda file_path=file_path, name=name: self._confirm_singconf_file_import(file_path, name))
        else:
            run_on_ui_thread(lambda file_path=file_path, name=name: self._confirm_greenpass_file_import(file_path, name))
        return True

    def _plugin_runtime_path(self):
        if _is_elyx_runtime():
            return ""
        try:
            path = os.path.abspath(str(self._plugin_file_path or ""))
        except:
            path = ""
        if not path:
            return ""
        try:
            name = os.path.basename(path).lower()
        except:
            name = ""
        if not name:
            return ""
        if not (name.endswith(".plugin") or name.endswith(".py")):
            return ""
        return path

    def _write_updated_plugin_source(self, plugin_text):
        path = self._plugin_runtime_path()
        if not path:
            return False
        source = str(plugin_text or "")
        if len(source.encode("utf-8", errors="ignore")) < 1024 or len(source.encode("utf-8", errors="ignore")) > 2 * 1024 * 1024:
            return False
        try:
            compile(source, path, "exec")
        except:
            return False
        temp_path = path + ".tmp"
        try:
            with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(source)
            os.replace(temp_path, path)
            return True
        except:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
        return False

    def _fetch_plugin_update_text(self):
        try:
            req = urllib.request.Request(str(GREENPASS_UPDATE_URL), headers={"User-Agent": "GreenPass-Updater"})
            with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as resp:
                raw = resp.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                return ""
            return raw.decode("utf-8", errors="strict")
        except:
            return ""

    def _fetch_elyx_update_archive(self):
        try:
            req = urllib.request.Request(str(GREENPASS_ELYX_UPDATE_URL), headers={"User-Agent": "GreenPass-Updater"})
            with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as resp:
                raw = resp.read(2 * 1024 * 1024 + 1)
            if len(raw) < 1024 or len(raw) > 2 * 1024 * 1024:
                return b"", ""
            with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
                names = set(archive.namelist())
                if "refmap.yml" not in names or "plugin/main.py" not in names or "plugin/meta.yml" not in names:
                    return b"", ""
                info = archive.getinfo("plugin/meta.yml")
                if int(info.file_size or 0) > 64 * 1024:
                    return b"", ""
                meta = archive.read(info).decode("utf-8", errors="strict")
            plugin_id = re.search(r'(?mi)^id\s*:\s*["\']?([^"\'\s]+)', meta)
            version = re.search(r'(?mi)^version\s*:\s*["\']?([^"\'\s]+)', meta)
            if not plugin_id or str(plugin_id.group(1) or "").strip() != __id__ or not version:
                return b"", ""
            return raw, str(version.group(1) or "").strip()
        except:
            return b"", ""

    def _save_elyx_update_archive(self, raw):
        try:
            cache_dir = str(ApplicationLoader.applicationContext.getCacheDir().getAbsolutePath())
            path = os.path.join(cache_dir, "GreenPass-update.elyx")
            temp_path = path + ".tmp"
            with open(temp_path, "wb") as handle:
                handle.write(bytes(raw or b""))
            os.replace(temp_path, path)
            return path
        except:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass
            return ""

    def _open_elyx_update_archive(self, path):
        try:
            fragment = get_last_fragment()
            controller = self._plugins_controller_instance()
            if fragment is None or controller is None or not os.path.isfile(str(path or "")):
                raise Exception("installer is unavailable")
            controller.showInstallDialog(fragment, str(path), True)
            return True
        except:
            BulletinHelper.show_error("Не удалось открыть установщик обновления")
            return False

    def _run_autoupdate_check(self, force=False):
        if (not force) and (not self._plugin_autoupdate_enabled()):
            return False
        if self._autoupdate_in_progress:
            return False

        now_ts = int(time.time())
        if (not force) and (now_ts - int(self._autoupdate_last_check_ts or 0) < int(PLUGIN_AUTOUPDATE_CHECK_INTERVAL_SEC)):
            return False

        self._autoupdate_in_progress = True
        try:
            self._autoupdate_last_check_ts = now_ts
            self._save_config()

            if _is_elyx_runtime():
                archive_bytes, remote_version = self._fetch_elyx_update_archive()
                self._autoupdate_last_seen_version = str(remote_version or "")
                self._save_config()
                if not archive_bytes or not remote_version:
                    if force:
                        run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось проверить обновления GreenPass"))
                    return False
                if not _is_version_newer(remote_version, __version__):
                    if force:
                        run_on_ui_thread(lambda: BulletinHelper.show_success("Установлена актуальная версия GreenPass"))
                    return False
                if (not force) and (not self._plugin_autoupdate_enabled()):
                    return False
                if (not force) and str(self.get_setting("plugin_autoupdate_prompted_version", "") or "") == remote_version:
                    return False
                archive_path = self._save_elyx_update_archive(archive_bytes)
                if not archive_path:
                    if force:
                        run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось сохранить обновление GreenPass"))
                    return False
                run_on_ui_thread(lambda: self._show_plugin_update_available(remote_version, archive_path))
                return True

            remote_text = self._fetch_plugin_update_text()
            if (not self._active) and (not force):
                return False
            remote_version = _extract_declared_plugin_version(remote_text)
            self._autoupdate_last_seen_version = str(remote_version or "")
            self._save_config()

            if not remote_text or not remote_version:
                if force:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось проверить обновления GreenPass"))
                return False
            if not _is_version_newer(remote_version, __version__):
                if force:
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Установлена актуальная версия GreenPass"))
                return False
            if (not force) and (not self._plugin_autoupdate_enabled()):
                return False
            if (not self._active) and (not force):
                return False
            if not self._write_updated_plugin_source(remote_text):
                return False

            if (not self._active) and (not force):
                return False
            run_on_ui_thread(lambda: BulletinHelper.show_info("GreenPass обновлён до %s. Перезапустите приложение." % str(remote_version)))
            return True
        except Exception:
            return False
        finally:
            self._autoupdate_in_progress = False

    def _set_core_download_in_progress(self, in_progress):
        in_progress = bool(in_progress)
        changed = in_progress != bool(self._vless_prepare_in_progress)
        self._vless_prepare_in_progress = in_progress
        if changed:
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

    def _update_outdated_core_in_background(self, force=False):
        if (not force) and (not self._core_autoupdate_enabled()):
            return False
        initial_status = self._libsingbox_addon_status()
        if initial_status not in ("missing", "outdated") or self._vless_prepare_in_progress:
            return False
        self._set_core_download_in_progress(True)

        def _worker():
            try:
                if self._install_libsingbox_bundle(allow_network=True):
                    installed = initial_status == "missing"
                    if self._core_restart_required():
                        message = "Ядро GreenPass установлено. Перезапустите приложение" if installed else "Ядро GreenPass обновлено. Перезапустите приложение"
                    else:
                        message = "Ядро GreenPass установлено" if installed else "Ядро GreenPass обновлено"
                    run_on_ui_thread(lambda: BulletinHelper.show_success(message))
                    if not self._core_restart_required() and self._is_plugin_proxy_enabled():
                        run_on_ui_thread(lambda: self._on_use_proxy_changed(True))
            finally:
                self._set_core_download_in_progress(False)

        threading.Thread(target=_worker, daemon=True).start()
        return True








    def _core_restart_required(self):
        try:
            return self._core_restart_reason == "library_update" and int(self._core_restart_required_pid or 0) == int(os.getpid())
        except:
            return False

    def _greenpass_core_loaded(self):
        return any(
            getattr(getattr(self, name, None), "_real", None) is not None
            for name in ("_vless_core", "_awg_core", "_olcrtc_core")
        )

    def _mark_core_restart_required(self):
        self._core_restart_resume_mode = str(self._get_connection_mode() or AWG_KIND)
        self._core_restart_resume_enabled = bool(self._is_plugin_proxy_enabled())
        self._core_restart_required_pid = int(os.getpid())
        self._core_restart_reason = "library_update"
        _gp_set_go_core_blocked(True)
        self._save_config()

    def _cleanup_legacy_core_files(self):
        if not self._has_libsingbox_addon():
            return
        for name in ("libvless.so", "libawg_proxy.so", "libzvonki.so"):
            try:
                path = os.path.join(self._vless_dir, name)
                if os.path.exists(path):
                    os.remove(path)
            except:
                pass



    def _mask_olcrtc_key(self, key_hex=None):
        try:
            value = str(key_hex if key_hex is not None else self._get_olcrtc_key_hex() or "").strip()
        except:
            value = ""
        if not value:
            return ""
        return value[:6] + "..." + value[-6:] if len(value) > 12 else "***"



    def _sha256_file(self, path, max_bytes=0):
        try:
            hasher = hashlib.sha256()
            total = 0
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(256 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if max_bytes and total > int(max_bytes):
                        return "", total
                    hasher.update(chunk)
            return hasher.hexdigest(), total
        except:
            return "", 0




    def _install_libzvonki_bundle(self, allow_network=True):
        return self._install_libsingbox_bundle(allow_network=allow_network)

    def _download_libsingbox_bundle_to_temp(self, dst_path, on_progress=None):
        for url in SINGBOX_BUNDLE_URLS:
            for attempt in range(3):
                try:
                    req = urllib.request.Request(str(url or ""), headers={"User-Agent": "GreenPass", "Connection": "close"})
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    hasher = hashlib.sha256()
                    total = 0
                    with urllib.request.urlopen(req, timeout=40, context=ctx) as resp, open(dst_path, "wb") as handle:
                        while True:
                            chunk = resp.read(128 * 1024)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > int(SINGBOX_BUNDLE_SIZE) + 4096:
                                raise ValueError("singbox bundle too large")
                            hasher.update(chunk)
                            handle.write(chunk)
                            if on_progress:
                                try:
                                    on_progress(min(1.0, float(total) / float(SINGBOX_BUNDLE_SIZE)))
                                except:
                                    pass
                    if total == int(SINGBOX_BUNDLE_SIZE) and hasher.hexdigest() == SINGBOX_BUNDLE_SHA256:
                        return True
                    # A complete download with the wrong hash is another build:
                    # retrying the same mirror would fetch it again.
                    try:
                        os.remove(dst_path)
                    except:
                        pass
                    break
                except:
                    try:
                        if os.path.exists(dst_path):
                            os.remove(dst_path)
                    except:
                        pass
                if attempt < 2:
                    time.sleep(1 + attempt)
        return False

    def _unpack_libsingbox_bundle(self, xz_path, target_path, on_progress=None):
        tmp_path = str(target_path) + ".tmp"
        try:
            hasher = hashlib.sha256()
            total = 0
            with lzma.open(xz_path, "rb", format=lzma.FORMAT_XZ) as src, open(tmp_path, "wb") as dst:
                while True:
                    chunk = src.read(256 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > int(SINGBOX_SO_SIZE) + 4096:
                        raise ValueError("singbox library too large")
                    hasher.update(chunk)
                    dst.write(chunk)
                    if on_progress:
                        try:
                            on_progress(min(1.0, float(total) / float(SINGBOX_SO_SIZE)))
                        except:
                            pass
                try:
                    dst.flush()
                    os.fsync(dst.fileno())
                except:
                    pass
            if total != int(SINGBOX_SO_SIZE) or hasher.hexdigest() != SINGBOX_SO_SHA256:
                raise ValueError("singbox checksum mismatch")
            os.replace(tmp_path, target_path)
            self._libsingbox_validation_cache = None
            return True
        except:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except:
                pass
            return False

    def _install_libsingbox_bundle(self, allow_network=True, on_progress=None):
        if not self._libsingbox_install_lock.acquire(False):
            return False
        try:
            return self._install_libsingbox_bundle_impl(allow_network=allow_network, on_progress=on_progress)
        finally:
            self._libsingbox_install_lock.release()

    def _install_libsingbox_bundle_impl(self, allow_network=True, on_progress=None):
        if not SINGBOX_BUNDLE_FILE:
            return False
        if self._libsingbox_addon_status() == "current":
            if on_progress:
                on_progress(1.0, "Готово")
            return True
        core_was_loaded = self._greenpass_core_loaded()
        try:
            if not os.path.exists(self._vless_dir):
                os.makedirs(self._vless_dir)
        except:
            pass

        target = self._libsingbox_so_path()
        xz_tmp = str(target) + ".xz.tmp"
        try:
            if allow_network:
                ok = self._download_libsingbox_bundle_to_temp(
                    xz_tmp,
                    on_progress=(lambda value: on_progress(0.05 + 0.70 * value, "Скачивание")) if on_progress else None,
                )
            else:
                ok = False
            if not ok:
                return False
            digest, size = self._sha256_file(xz_tmp, max_bytes=int(SINGBOX_BUNDLE_SIZE))
            if size != int(SINGBOX_BUNDLE_SIZE) or digest != SINGBOX_BUNDLE_SHA256:
                return False
            installed = self._unpack_libsingbox_bundle(
                xz_tmp,
                target,
                on_progress=(lambda value: on_progress(0.75 + 0.24 * value, "Распаковка")) if on_progress else None,
            ) and self._libsingbox_addon_status() == "current"
            if installed:
                if on_progress:
                    on_progress(1.0, "Готово")
                if core_was_loaded:
                    self._mark_core_restart_required()
                else:
                    self._core_restart_required_pid = 0
                    self._core_restart_reason = ""
                    self._core_restart_resume_mode = ""
                    self._core_restart_resume_enabled = False
                    _gp_set_go_core_blocked(False)
                    self._reload_vless_core()
                    self._reload_awg_core()
                    self._reload_olcrtc_core()
                    self._save_config()
            return installed
        finally:
            try:
                if os.path.exists(xz_tmp):
                    os.remove(xz_tmp)
            except:
                pass









    def _reload_vless_core(self):
        try:
            self._vless_core = _LazySingboxCore(self._libvless_so_path())
        except:
            self._vless_core = _LazySingboxCore("")

    def _reload_awg_core(self):
        try:
            self._awg_core = _LazyAWGCore(self._libawg_so_path())
        except:
            self._awg_core = _LazyAWGCore("")

    def _reload_olcrtc_core(self):
        try:
            self._olcrtc_core = _LazyVlessCore(self._libzvonki_so_path())
        except:
            self._olcrtc_core = _LazyVlessCore("")

    def _has_libvless_addon(self):
        return self._has_libsingbox_addon()


    def _has_olcrtc_core_addon(self):
        return self._has_libzvonki_addon()

    def _sanitize_qwdtt_profiles(self, profiles):
        result = []
        seen = set()
        for item in list(profiles or []):
            profile = _qwdtt_profile_from_mapping(item, source_uri=str((item or {}).get("source_uri", "") or "") if isinstance(item, dict) else "")
            if not profile:
                continue
            profile_id = str(profile.get("id", "") or "")
            if not profile_id or profile_id in seen:
                continue
            seen.add(profile_id)
            result.append(profile)
            if len(result) >= 64:
                break
        return result

    def _sanitize_qwdtt_subscriptions(self, subscriptions):
        result = []
        seen = set()
        for item in list(subscriptions or []):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "") or "").strip()
            if not url or url in seen:
                continue
            profiles = self._sanitize_qwdtt_profiles(item.get("profiles", []))
            if not profiles:
                continue
            seen.add(url)
            result.append({
                "url": url,
                "name": str(item.get("name", "") or "").strip()[:80] or "qWDTT подписка",
                "description": str(item.get("description", "") or "").strip()[:160],
                "profiles": profiles,
                "updated_at": int(item.get("updated_at", 0) or 0),
            })
            if len(result) >= 16:
                break
        return result

    def _iter_qwdtt_profiles(self):
        seen = set()
        for profile in self._sanitize_qwdtt_profiles(self._qwdtt_data.get("profiles", [])):
            profile_id = str(profile.get("id", "") or "")
            if not profile_id or profile_id in seen:
                continue
            seen.add(profile_id)
            yield profile
        for sub in self._sanitize_qwdtt_subscriptions(self._qwdtt_data.get("subs", [])):
            for profile in list(sub.get("profiles", []) or []):
                profile_id = str(profile.get("id", "") or "")
                if not profile_id or profile_id in seen:
                    continue
                seen.add(profile_id)
                yield profile

    def _find_qwdtt_profile(self, profile_id):
        target = str(profile_id or "")
        if not target:
            return None
        for profile in self._iter_qwdtt_profiles():
            if str(profile.get("id", "") or "") == target:
                return profile
        return None

    def _save_qwdtt_profile(self, profile, activate=True):
        node = self._qwdtt_node_from_profile(profile)
        if not node:
            return None
        if activate:
            return self._save_vless_manual_node(node)
        return node

    def _qwdtt_node_from_profile(self, profile):
        clean = _qwdtt_profile_from_mapping(profile, source_uri=str((profile or {}).get("source_uri", "") or "") if isinstance(profile, dict) else "")
        if not clean:
            return None
        profile_id = str(clean.get("id", "") or "")
        return {
            "id": "qwdtt://" + profile_id,
            "uri": "qwdtt://" + profile_id,
            "kind": QWDTT_KIND,
            "name": str(clean.get("name", "qWDTT") or "qWDTT"),
            "server": str(clean.get("peer", "") or ""),
            "port": int(clean.get("local_port", 9000) or 9000),
            "network": "turn",
            "security": "wireguard",
            "qwdtt": clean,
        }

    def _import_qwdtt_payload(self, text, activate_first=True, subscription_url=""):
        parsed = _parse_qwdtt_payload(text)
        profiles = self._sanitize_qwdtt_profiles(parsed.get("profiles", []))
        if not profiles:
            return 0
        nodes = [self._qwdtt_node_from_profile(profile) for profile in profiles]
        nodes = [node for node in nodes if node]
        if not nodes:
            return 0
        if subscription_url:
            target = str(subscription_url or "").strip()
            subs = [item for item in list(self._vless_data.get("subs", []) or []) if str(item.get("url", "") or "") != target]
            subs.append({
                "id": target,
                "url": target,
                "name": str(parsed.get("name", "") or "").strip()[:80] or str(urllib.parse.urlparse(target).netloc or "qWDTT подписка"),
                "nodes": nodes,
            })
            self._vless_data["subs"] = subs[-64:]
        else:
            known = {str(node.get("uri", "") or "") for node in nodes}
            current = [item for item in list(self._vless_data.get("manual", []) or []) if str(item.get("uri", "") or "") not in known]
            self._vless_data["manual"] = (nodes + current)[:64]
        if bool(activate_first) or not self._get_active_vless_uri():
            self._vless_data["active_uri"] = str(nodes[0].get("uri", "") or "")
            self._set_connection_mode(VLESS_KIND)
        self._save_config()
        if bool(activate_first):
            self._switch_to_vless_mode(False)
        self._refresh_settings_without_reopen(reload_main=bool(activate_first), reload_stack=True)
        return len(nodes)

    def _get_connection_mode(self):
        mode = str(self._connection_mode or AWG_KIND)
        if mode not in (VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            mode = VLESS_KIND
        return mode

    def _normalize_proxy_mode(self, mode, fallback=VLESS_KIND):
        try:
            target = str(mode or fallback)
        except:
            target = str(fallback or VLESS_KIND)
        if target not in (VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            target = str(fallback or VLESS_KIND)
        if target not in (VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            target = VLESS_KIND
        return target

    def _set_connection_mode(self, mode):
        target = self._normalize_proxy_mode(mode)
        self._connection_mode = target
        if not bool(getattr(self, "_wifi_rule_switching", False)):
            self._wifi_default_mode = target
        self._save_config()

    def _effective_vless_engine(self, node=None):
        target = node if isinstance(node, dict) else self._current_vless_node()
        kind = str((target or {}).get("kind", "") or "").strip().lower()
        if kind == "mihomo-config":
            return VLESS_ENGINE_MIHOMO
        if kind in ("singbox-config", QWDTT_KIND):
            return VLESS_ENGINE_SINGBOX
        return _normalize_vless_engine(self._vless_engine)


    def _on_vless_engine_changed(self, index):
        try:
            selected = int(index or 0)
        except:
            selected = 0
        target = VLESS_ENGINE_MIHOMO if selected == 1 else VLESS_ENGINE_SINGBOX
        current = self._current_vless_node()
        kind = str((current or {}).get("kind", "") or "").strip().lower()
        if (kind == "mihomo-config" and target != VLESS_ENGINE_MIHOMO) or (kind == "singbox-config" and target != VLESS_ENGINE_SINGBOX):
            BulletinHelper.show_error("Файловый конфиг привязан к своему ядру")
            self._refresh_settings_without_reopen()
            return False
        if target == _normalize_vless_engine(self._vless_engine):
            return True
        self._vless_engine = target
        self._save_config()

        def _restart():
            self._vless_disconnect_with_reason("vless_engine_changed", silent=True)
            if self._should_run_vless():
                self._reset_vless_retry()
                self._ensure_vless_core_then(self._vless_connect)
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

        threading.Thread(target=_restart, daemon=True).start()
        return True

    def _get_active_vless_uri(self):
        try:
            return str(self._vless_data.get("active_uri", "") or "")
        except:
            return ""

    def _get_all_vless_nodes(self):
        nodes = []
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                if isinstance(node, dict):
                    nodes.append(node)
        except:
            pass
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                for node in list(sub.get("nodes", []) or []):
                    if isinstance(node, dict):
                        nodes.append(node)
        except:
            pass
        return nodes

    def _find_vless_node(self, uri):
        target = str(uri or "")
        if not target:
            return None
        if target == VLESS_AUTO_SUBSCRIPTIONS_URI:
            nodes = self._vless_balancer_nodes()
            if len(nodes) < 2:
                return None
            first = nodes[0]
            return {
                "uri": VLESS_AUTO_SUBSCRIPTIONS_URI,
                "kind": "vless",
                "name": Z("Автовыбор"),
                "server": str(first.get("server", "") or ""),
                "port": int(first.get("port", 0) or 0),
                "network": "auto",
                "balance_nodes": nodes,
            }
        for node in self._get_all_vless_nodes():
            try:
                if str(node.get("uri", "") or "") == target:
                    return node
            except:
                continue
        return None

    def _current_vless_node(self):
        node = self._find_vless_node(self._get_active_vless_uri())
        if node is None and self._repair_active_vless_subscription_uri():
            self._vless_save_data()
            node = self._find_vless_node(self._get_active_vless_uri())
        return node


    def _repair_active_vless_subscription_uri(self):
        active_uri = self._get_active_vless_uri()
        if active_uri == VLESS_AUTO_SUBSCRIPTIONS_URI and self._find_vless_node(active_uri):
            return False
        active_key = _proxy_uri_dedup_key(active_uri) or active_uri
        if not active_key:
            return False

        manual_keys = set()
        candidates = []
        seen = set()
        preferred = ""
        try:
            current_server = str(self._current_server or "")
            current_port = int(self._current_port or 0)
        except:
            current_server = ""
            current_port = 0
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                value = str(node.get("uri", "") or "")
                key = _proxy_uri_dedup_key(value) or value
                if key:
                    manual_keys.add(key)
            if active_key in manual_keys:
                return False
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                for node in list(sub.get("nodes", []) or []):
                    if not isinstance(node, dict):
                        continue
                    value = str(node.get("uri", "") or "")
                    key = _proxy_uri_dedup_key(value) or value
                    if not key:
                        continue
                    if key == active_key:
                        return False
                    if key not in seen:
                        seen.add(key)
                        candidates.append(value)
                        if not preferred and current_server and current_port > 0:
                            try:
                                if str(node.get("server", "") or "") == current_server and int(node.get("port", 0) or 0) == current_port:
                                    preferred = value
                            except:
                                pass
        except:
            return False
        if not candidates:
            return False
        self._vless_data["active_uri"] = preferred or candidates[0]
        return True

    def _iter_vless_nodes(self):
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                if isinstance(node, dict):
                    yield node
        except:
            pass
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                for node in list(sub.get("nodes", []) or []):
                    if isinstance(node, dict):
                        yield node
        except:
            pass




    def _append_green_tail(self, base_text, tail_text):
        text = str(base_text or "")
        tail = str(tail_text or "").strip()
        if not tail:
            return text
        try:
            from android.text import SpannableStringBuilder, Spanned
            from android.text.style import ForegroundColorSpan
            from org.telegram.ui.ActionBar import Theme

            builder = SpannableStringBuilder()
            builder.append(text)
            if text:
                builder.append("  ")
            start = int(builder.length())
            builder.append(tail)
            try:
                color = int(Theme.getColor(Theme.key_windowBackgroundWhiteGreenText))
            except:
                color = 0xFF26972C
            builder.setSpan(ForegroundColorSpan(color), start, int(builder.length()), int(Spanned.SPAN_EXCLUSIVE_EXCLUSIVE))
            return builder
        except:
            if text:
                return text + "  " + tail
            return tail

    def _probe_vless_node_latency(self, node, timeout_sec=None):
        try:
            payload = {
                "server": str(node.get("server", "") or ""),
                "port": int(node.get("port", 0) or 0),
            }
        except:
            payload = {"server": "", "port": 0}
        if timeout_sec is None:
            timeout_sec = float(VLESS_NODE_PING_TIMEOUT_SEC)
        return self._probe_proxy_latency(payload, timeout_sec=float(timeout_sec))


    def _sorted_vless_nodes(self, nodes):
        try:
            return sorted(list(nodes or []), key=self._vless_sort_key)
        except:
            return list(nodes or [])

    def _sort_all_vless_nodes_by_ping(self):
        changed = False
        try:
            manual = list(self._vless_data.get("manual", []) or [])
        except:
            manual = []
        manual_sorted = self._sorted_vless_nodes(manual)
        if manual_sorted != manual:
            self._vless_data["manual"] = manual_sorted
            changed = True
        return bool(changed)

    def _refresh_vless_node_pings(self, force=False, save=False, limit=None, nodes=None, refresh_each=False):
        nodes = list(self._iter_vless_nodes()) if nodes is None else list(nodes or [])
        nodes = [node for node in nodes if str((node or {}).get("kind", "") or "").strip().lower() != QWDTT_KIND]
        if not nodes:
            return {"changed": False, "checked": 0, "alive": 0}

        now = time.time()
        targets = []

        for node in nodes:
            checked_at = self._vless_ping_checked_at(node)
            if (not force) and checked_at and (now - checked_at) < float(VLESS_NODE_PING_REFRESH_SEC):
                continue
            targets.append(node)
            if limit is not None and len(targets) >= int(limit):
                break

        def _ping_one(node):
            changed = False
            dt = self._probe_vless_node_latency(node, timeout_sec=float(VLESS_NODE_PING_TIMEOUT_SEC))
            if dt is None:
                ping = 9999
                alive = 0
            else:
                ping = max(1, int(dt))
                alive = 1

            prev_ping = self._vless_ping_value(node)
            prev_checked = self._vless_ping_checked_at(node)
            node["ping"] = int(ping)
            node["ping_checked_at"] = float(time.time())
            if prev_ping != int(ping) or abs(float(node["ping_checked_at"]) - float(prev_checked)) > 0.001:
                changed = True
            return bool(changed), int(alive)

        checked = len(targets)
        alive = 0
        changed = False
        next_ui_refresh = 0.0
        if targets:
            with ThreadPoolExecutor(max_workers=min(12, len(targets))) as ex:
                futures = [ex.submit(_ping_one, node) for node in targets]
                for future in as_completed(futures):
                    try:
                        item_changed, item_alive = future.result()
                    except:
                        item_changed, item_alive = False, 0
                    changed = bool(changed or item_changed)
                    alive += int(item_alive)
                    if refresh_each:
                        # A large subscription can complete dozens of probes
                        # at once. Rebuilding the settings stack for every
                        # result starves Telegram's UI thread; keep progress
                        # updates, but coalesce them to a few per second.
                        now = time.monotonic()
                        if now >= next_ui_refresh:
                            next_ui_refresh = now + 0.25
                            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))

        sorted_changed = self._sort_all_vless_nodes_by_ping()
        changed = bool(changed or sorted_changed)
        if save and changed:
            self._vless_save_data()
        return {"changed": bool(changed), "checked": int(checked), "alive": int(alive)}

    def _pick_fastest_vless_node(self, nodes=None):
        best = None
        best_ping = None
        source = self._iter_vless_nodes() if nodes is None else list(nodes or [])
        for node in source:
            if str((node or {}).get("kind", "") or "").strip().lower() == QWDTT_KIND:
                continue
            ping = self._vless_ping_value(node)
            checked_at = self._vless_ping_checked_at(node)
            if checked_at <= 0 or (time.time() - float(checked_at)) > float(VLESS_NODE_PING_STALE_SEC):
                continue
            if ping <= 0 or ping >= 9999:
                continue
            if best is None or int(ping) < int(best_ping):
                best = node
                best_ping = ping
        return best

    def _run_vless_ping_test(self, nodes=None, refresh_each=False):
        nodes = list(self._iter_vless_nodes()) if nodes is None else list(nodes or [])
        nodes = [node for node in nodes if str((node or {}).get("kind", "") or "").strip().lower() != QWDTT_KIND]
        if not nodes:
            BulletinHelper.show_info("Нет узлов")
            return False
        BulletinHelper.show_info("Тестирую узлы...")

        def _worker():
            info = {"changed": False, "checked": 0, "alive": 0}
            try:
                info = self._refresh_vless_node_pings(force=True, save=True, nodes=nodes, refresh_each=refresh_each)
            finally:
                fastest = self._pick_fastest_vless_node(nodes)
                run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_stack=True))
                if fastest is not None:
                    try:
                        name = str(fastest.get("name", "") or "").strip() or "Узел"
                    except:
                        name = "Узел"
                    ping = self._vless_ping_value(fastest)
                    run_on_ui_thread(lambda: BulletinHelper.show_success(f"Самый быстрый: {name} ({int(ping)} ms)"))
                else:
                    checked = int(info.get("checked", 0) or 0)
                    alive = int(info.get("alive", 0) or 0)
                    run_on_ui_thread(lambda: BulletinHelper.show_success(f"Пинг обновлен: {alive}/{checked}"))

        threading.Thread(target=_worker, daemon=True).start()
        return True























    def _build_olcrtc_link_from_profile(self, profile):
        try:
            carrier = str(profile.get("carrier", "") or self._get_olcrtc_carrier()).strip().lower() or "wbstream"
            transport = str(profile.get("transport", "") or self._get_olcrtc_transport()).strip().lower()
            room_id = str(profile.get("room_id", "") or "").strip()
            key_hex = str(profile.get("key_hex", "") or "").strip()
            token = transport
            if transport == "vp8channel":
                fps = int(profile.get("vp8_fps", 60) or 60)
                batch = int(profile.get("vp8_batch_size", 64) or 64)
                token += "<vp8-fps=%d&vp8-batch=%d>" % (fps, batch)
            name = str(profile.get("name", "") or "").strip()
            suffix = ("$" + name) if name else ""
            return "olcrtc://%s?%s@%s#%s%s" % (carrier, token, room_id, key_hex, suffix)
        except:
            return ""

    def _normalize_olcrtc_profile(self, profile):
        if not isinstance(profile, dict):
            return None
        carrier = str(profile.get("carrier", "") or "").strip().lower() or self._get_olcrtc_carrier()
        transport = str(profile.get("transport", "") or "").strip().lower() or self._get_olcrtc_transport()
        room_id = str(profile.get("room_id", "") or "").strip()
        client_id = _get_or_create_olcrtc_device_id()
        key_hex = str(profile.get("key_hex", "") or "").strip()
        if not room_id or not client_id or len(key_hex) != 64 or re.search(r"[^0-9a-fA-F]", key_hex):
            return None
        if carrier not in OLCRTC_CARRIER_ITEMS:
            carrier = self._get_olcrtc_carrier()
        supported = _olcrtc_supported_transports(carrier)
        if transport not in supported:
            transport = supported[0]
        out = {
            "id": "",
            "name": str(profile.get("name", "") or "").strip()[:64],
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "client_id": client_id,
            "key_hex": key_hex,
        }
        try:
            vp8_fps = int(profile.get("vp8_fps", 0) or 0)
            if vp8_fps > 0:
                out["vp8_fps"] = vp8_fps
        except:
            pass
        try:
            vp8_batch = int(profile.get("vp8_batch_size", profile.get("vp8_batch", 0)) or 0)
            if vp8_batch > 0:
                out["vp8_batch_size"] = vp8_batch
        except:
            pass
        out["id"] = self._olcrtc_profile_id_for(carrier, transport, room_id, client_id, key_hex)
        out["link"] = self._build_olcrtc_link_from_profile(out)
        subscription_url = str(profile.get("subscription_url", "") or "").strip()
        if subscription_url.lower().startswith(("http://", "https://")):
            out["subscription_url"] = subscription_url
            try:
                out["subscription_updated_at"] = int(profile.get("subscription_updated_at", 0) or 0)
            except:
                out["subscription_updated_at"] = 0
        if not out["name"]:
            out["name"] = self._olcrtc_profile_name(out)
        return out

    def _sanitize_olcrtc_profiles(self, profiles):
        result = []
        seen = set()
        try:
            items = list(profiles or [])
        except:
            items = []
        for item in items:
            profile = self._normalize_olcrtc_profile(item)
            if not profile:
                continue
            pid = str(profile.get("id", "") or "")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            result.append(profile)
            if len(result) >= 64:
                break
        return result

    def _find_olcrtc_profile(self, profile_id):
        target = str(profile_id or "").strip()
        if not target:
            return None
        for profile in list(self._olcrtc_profiles or []):
            try:
                if str(profile.get("id", "") or "") == target:
                    return profile
            except:
                pass
        return None

    def _active_olcrtc_profile(self):
        profile = self._find_olcrtc_profile(self._olcrtc_active_profile_id)
        if profile:
            return profile
        profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
        if profiles:
            self._olcrtc_profiles = profiles
            self._olcrtc_active_profile_id = str(profiles[0].get("id", "") or "")
            return profiles[0]
        return None



    def _upsert_olcrtc_profile(self, data, imported_link=""):
        if not isinstance(data, dict):
            return None
        link = str(imported_link or data.get("link", "") or "").strip()
        subscription_url = str(data.get("subscription_url", "") or "").strip()
        if link.lower().startswith(("http://", "https://")):
            subscription_url = link
        if not link.lower().startswith("olcrtc://"):
            link = ""
        profile = self._normalize_olcrtc_profile(dict(
            data,
            link=link,
            subscription_url=subscription_url,
            subscription_updated_at=int(time.time()),
        ))
        if not profile:
            return None
        profiles = [p for p in self._sanitize_olcrtc_profiles(self._olcrtc_profiles) if str(p.get("id", "") or "") != str(profile.get("id", "") or "")]
        profiles.insert(0, profile)
        self._olcrtc_profiles = profiles[:64]
        self._olcrtc_active_profile_id = str(profile.get("id", "") or "")
        self._set_olcrtc_legacy_settings_from_profile(profile)
        self._save_config()
        return profile

    def _activate_olcrtc_profile(self, profile_id, connect=True):
        profile = self._find_olcrtc_profile(profile_id)
        if not profile:
            BulletinHelper.show_error("Профиль не найден")
            return False
        self._olcrtc_active_profile_id = str(profile.get("id", "") or "")
        self._set_olcrtc_legacy_settings_from_profile(profile)
        self._set_connection_mode(OLCRTC_KIND)
        self._save_config()
        self._refresh_settings_without_reopen(reload_main=True)
        if connect:
            self._restart_olcrtc_from_settings()
        return True

    def _delete_olcrtc_profile(self, profile_id):
        target = str(profile_id or "").strip()
        self._olcrtc_profiles = [p for p in self._sanitize_olcrtc_profiles(self._olcrtc_profiles) if str(p.get("id", "") or "") != target]
        if str(self._olcrtc_active_profile_id or "") == target:
            self._olcrtc_active_profile_id = str(self._olcrtc_profiles[0].get("id", "") or "") if self._olcrtc_profiles else ""
            if self._olcrtc_profiles:
                self._set_olcrtc_legacy_settings_from_profile(self._olcrtc_profiles[0])
        self._save_config()
        self._refresh_settings_without_reopen(reload_main=True)

    def _active_olcrtc_link(self):
        legacy = self._normalize_olcrtc_profile({
            "carrier": self._get_olcrtc_carrier(),
            "transport": self._get_olcrtc_transport(),
            "room_id": self._get_olcrtc_room_id(),
            "client_id": self._get_olcrtc_client_id(),
            "key_hex": self._get_olcrtc_key_hex(),
        })
        profile = self._active_olcrtc_profile()
        if profile:
            try:
                profile_id = self._olcrtc_profile_id_for(profile.get("carrier"), profile.get("transport"), profile.get("room_id"), profile.get("client_id"), profile.get("key_hex"))
                legacy_id = self._olcrtc_profile_id_for(legacy.get("carrier"), legacy.get("transport"), legacy.get("room_id"), legacy.get("client_id"), legacy.get("key_hex")) if legacy else ""
                if legacy and profile_id != legacy_id:
                    return self._build_olcrtc_link_from_profile(legacy)
            except:
                pass
            return str(profile.get("link", "") or "") or self._build_olcrtc_link_from_profile(profile)
        return self._build_olcrtc_link_from_profile(legacy) if legacy else ""

    def _build_olcrtc_config_json(self):
        err = self._olcrtc_config_error()
        if err:
            return "", err
        payload = {
            "engine": "olcrtc",
            "carrier": self._get_olcrtc_carrier(),
            "transport": self._get_olcrtc_transport(),
            "room_id": self._get_olcrtc_room_id(),
            "client_id": self._get_olcrtc_client_id(),
            "key_hex": self._get_olcrtc_key_hex(),
            "socks_listen_host": VLESS_LOCAL_HOST,
            "socks_port": int(OLCRTC_LOCAL_PORT),
            "socks_user": "",
            "socks_pass": "",
            "dns_server": "1.1.1.1:53",
            "wait_ready_timeout_millis": int(float(OLCRTC_LOCAL_READY_TIMEOUT_SEC) * 1000),
        }
        if self._get_olcrtc_transport() == "vp8channel":
            payload["vp8_fps"], payload["vp8_batch_size"] = self._get_olcrtc_vp8_options()
        try:
            profile = self._active_olcrtc_profile()
            current_id = self._olcrtc_profile_id_for(
                self._get_olcrtc_carrier(),
                self._get_olcrtc_transport(),
                self._get_olcrtc_room_id(),
                self._get_olcrtc_client_id(),
                self._get_olcrtc_key_hex(),
            )
            profile_id = self._olcrtc_profile_id_for(
                profile.get("carrier"),
                profile.get("transport"),
                profile.get("room_id"),
                profile.get("client_id"),
                profile.get("key_hex"),
            ) if profile else ""
            if profile and profile_id == current_id:
                vp8_fps = int(profile.get("vp8_fps", 0) or 0)
                vp8_batch = int(profile.get("vp8_batch_size", 0) or 0)
                if vp8_fps > 0:
                    payload["vp8_fps"] = vp8_fps
                if vp8_batch > 0:
                    payload["vp8_batch_size"] = vp8_batch
        except:
            pass
        try:
            return json.dumps(payload), ""
        except Exception as exc:
            return "", str(exc)


    def _safe_olcrtc_core_text(self, method_name, allow_connecting=False):
        if not self._olcrtc_core_query_allowed(allow_connecting=allow_connecting):
            return ""
        try:
            method = getattr(self._olcrtc_core, str(method_name or ""))
        except:
            return ""
        try:
            return str(method() or "").strip()
        except Exception as exc:
            try:
                self._olcrtc_last_log = "%s failed: %s" % (str(method_name or "native"), str(exc))
            except:
                pass
            return ""








    def _should_run_vless(self):
        return bool(self._is_plugin_proxy_enabled()) and (not self._is_proxy_policy_suspended()) and self._get_connection_mode() == VLESS_KIND and bool(self._get_active_vless_uri())

    def _should_run_tgws(self):
        return bool(self._is_plugin_proxy_enabled()) and (not self._is_proxy_policy_suspended()) and self._get_connection_mode() == TGWS_KIND

    def _should_run_awg(self):
        return bool(self._is_plugin_proxy_enabled()) and (not self._is_proxy_policy_suspended()) and self._get_connection_mode() == AWG_KIND and bool(str(self._awg_conf_content or "").strip())

    def _should_run_olcrtc(self):
        return bool(self._is_plugin_proxy_enabled()) and (not self._is_proxy_policy_suspended()) and self._get_connection_mode() == OLCRTC_KIND and self._is_olcrtc_config_ready()


    def _normalize_local_socks_owner(self, owner):
        try:
            value = str(owner or "").strip().lower()
        except:
            value = ""
        if value in (VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            return value
        return ""

    def _current_mode_local_socks_owner(self):
        mode = self._get_connection_mode()
        return self._normalize_local_socks_owner(mode)

    def _local_socks_owner_can_apply(self, owner):
        target = self._normalize_local_socks_owner(owner)
        if target == VLESS_KIND:
            return self._should_run_vless()
        if target == TGWS_KIND:
            return self._should_run_tgws()
        if target == AWG_KIND:
            return self._should_run_awg()
        if target == OLCRTC_KIND:
            return self._should_run_olcrtc()
        return False

    def _local_socks_owner_snapshot(self):
        try:
            with self._local_socks_lock:
                return str(self._local_socks_owner or ""), int(self._local_socks_port or 0)
        except:
            return "", 0

    def _get_plugins_proxy_enabled(self):
        try:
            return bool(self.get_setting("proxy_plugins_via_greenpass", False))
        except:
            return False

    def _on_plugins_proxy_changed(self, enabled):
        val = bool(enabled)
        try:
            self.set_setting("proxy_plugins_via_greenpass", val, reload_settings=False)
        except:
            pass
        self._sync_plugin_proxy_bridge()
        self._refresh_settings_without_reopen()

    def _greenpass_socks_endpoint(self):
        if not bool(self._is_plugin_proxy_enabled()):
            self._plugin_proxy_last_error = "GreenPass proxy is off"
            return None
        if self._is_proxy_policy_suspended():
            self._plugin_proxy_last_error = "GreenPass proxy is suspended by network policy"
            return None

        mode = self._get_connection_mode()
        if mode == TGWS_KIND:
            self._plugin_proxy_last_error = "TGWS is Telegram-only"
            return None

        owner, local_port = self._local_socks_owner_snapshot()
        local_sources = {
            VLESS_KIND: (bool(self._vless_running), int(self._vless_port or 0)),
            AWG_KIND: (bool(self._awg_running), int(self._awg_port or 0)),
            OLCRTC_KIND: (bool(self._olcrtc_running), int(self._olcrtc_port or 0)),
        }
        if mode in local_sources:
            running, port = local_sources.get(mode)
            if owner == mode and int(local_port or 0) > 0:
                port = int(local_port)
            if running and port > 0:
                self._plugin_proxy_last_error = ""
                username = self._vless_socks_username if mode == VLESS_KIND else ""
                password = self._vless_socks_password if mode == VLESS_KIND else ""
                return {
                    "host": VLESS_LOCAL_HOST,
                    "port": int(port),
                    "username": str(username or ""),
                    "password": str(password or ""),
                    "source": str(mode),
                }
            self._plugin_proxy_last_error = "SOCKS is not ready"
            return None

        self._plugin_proxy_last_error = "SOCKS is not ready"
        return None

    def _plugin_proxy_endpoint(self):
        if not bool(self._get_plugins_proxy_enabled()):
            self._plugin_proxy_last_error = ""
            return None
        return self._greenpass_socks_endpoint()

    def _plugin_proxy_endpoint_key(self, endpoint=None):
        ep = endpoint if endpoint is not None else self._plugin_proxy_endpoint()
        if not ep:
            return ""
        try:
            return "%s:%s:%s:%s" % (
                str(ep.get("source", "") or ""),
                str(ep.get("host", "") or ""),
                int(ep.get("port", 0) or 0),
                "auth" if (ep.get("username") or ep.get("password")) else "noauth",
            )
        except:
            return ""

    def _plugin_proxy_url(self, endpoint=None):
        ep = endpoint if endpoint is not None else self._plugin_proxy_endpoint()
        if not ep:
            return ""
        try:
            host = str(ep.get("host", "") or "")
            port = int(ep.get("port", 0) or 0)
            user = str(ep.get("username", "") or "")
            password = str(ep.get("password", "") or "")
            auth = ""
            if user or password:
                auth = "%s:%s@" % (
                    urllib.parse.quote(user, safe=""),
                    urllib.parse.quote(password, safe=""),
                )
            return "socks5h://%s%s:%s" % (auth, host, port)
        except:
            return ""

    def _install_plugin_proxy_api(self):
        module = sys.modules.get(GREENPASS_PROXY_API_MODULE)
        if module is None:
            module = types.ModuleType(GREENPASS_PROXY_API_MODULE)
            sys.modules[GREENPASS_PROXY_API_MODULE] = module
        module._plugin = self

        def _current():
            plugin = getattr(module, "_plugin", None)
            if plugin is None:
                raise RuntimeError("GreenPass plugin is not loaded")
            return plugin

        def endpoint():
            ep = _current()._plugin_proxy_endpoint()
            return dict(ep or {})

        def is_available():
            return bool(_current()._plugin_proxy_endpoint())

        def requests_proxies():
            url = _current()._plugin_proxy_url()
            if not url:
                return {}
            return {"http": url, "https": url}

        def status():
            plugin = _current()
            ep = plugin._plugin_proxy_endpoint()
            return {
                "enabled": bool(plugin._get_plugins_proxy_enabled()),
                "available": bool(ep),
                "endpoint": dict(ep or {}),
                "proxy_url": plugin._plugin_proxy_url(ep),
                "error": str(plugin._plugin_proxy_last_error or ""),
            }

        module.endpoint = endpoint
        module.is_available = is_available
        module.requests_proxies = requests_proxies
        module.status = status
        module.API_VERSION = 1
        return module

    def _plugin_proxy_should_bypass_host(self, host, endpoint=None):
        try:
            h = str(host or "").strip().strip("[]").lower()
        except:
            h = ""
        if not h:
            return True
        if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        if h.startswith("127."):
            return True
        try:
            ep_host = str((endpoint or {}).get("host", "") or "").strip().strip("[]").lower()
            if ep_host and h == ep_host:
                return True
        except:
            pass
        if h in ("api.cloudflareclient.com", "web-api.vpgram.click"):
            # Never route registration requests through a broken local tunnel
            if not bool(getattr(self, "_vless_running", False)):
                return True
        return False

    def _plugin_proxy_is_greenpass_call(self):
        try:
            target = os.path.abspath(str(self._plugin_file_path or "")).replace("\\", "/").lower()
        except:
            target = ""
        try:
            target_name = os.path.basename(target)
        except:
            target_name = ""
        target_root = ""
        if target and _is_elyx_runtime():
            try:
                target_root = os.path.dirname(target).rstrip("/") + "/"
            except:
                target_root = ""

        ignored = {
            "_plugin_proxy_is_greenpass_call",
            "patched_socket_create_connection",
            "patched_urllib3_create_connection",
            "_plugin_proxy_socks_create_connection",
            "_plugin_proxy_recv_exact",
        }
        try:
            frame = sys._getframe(1)
        except:
            frame = None

        vless_active = bool(getattr(self, "_vless_running", False))
        depth = 0
        while frame is not None and depth < 48:
            try:
                code = frame.f_code
                name = str(code.co_name or "")
                filename = os.path.abspath(str(code.co_filename or "")).replace("\\", "/").lower()
                filename_name = os.path.basename(filename)
                f_locals = getattr(frame, "f_locals", None) or {}
                if f_locals.get("self") is self or f_locals.get("plugin") is self:
                    if not vless_active:
                        return True
                if name not in ignored and (
                    (target and filename == target)
                    or (target_root and filename.startswith(target_root))
                    or ((not target_root) and target_name and filename_name == target_name)
                    or ("greenpass" in filename_name)
                ):
                    if not vless_active:
                        return True
            except:
                pass
            try:
                frame = frame.f_back
            except:
                frame = None
            depth += 1
        return False

    def _plugin_proxy_recv_exact(self, sock, size):
        chunks = []
        remain = int(size or 0)
        while remain > 0:
            chunk = sock.recv(remain)
            if not chunk:
                raise OSError("SOCKS proxy closed")
            chunks.append(chunk)
            remain -= len(chunk)
        return b"".join(chunks)

    def _plugin_proxy_socks_create_connection(self, endpoint, address, timeout=None, source_address=None):
        host, port = address
        proxy_host = str(endpoint.get("host", "") or "")
        proxy_port = int(endpoint.get("port", 0) or 0)
        if not proxy_host or proxy_port <= 0:
            raise OSError("GreenPass SOCKS endpoint is unavailable")

        original = self._plugin_proxy_originals.get("socket.create_connection") or socket.create_connection
        sock = original((proxy_host, proxy_port), timeout, source_address)
        try:
            caller_timeout = sock.gettimeout()
            try:
                from android.os import Looper
                on_ui_thread = bool(Looper.myLooper() == Looper.getMainLooper())
            except:
                on_ui_thread = threading.current_thread() is threading.main_thread()
            if on_ui_thread and (caller_timeout is None or caller_timeout > PLUGIN_PROXY_UI_HANDSHAKE_TIMEOUT_SEC):
                sock.settimeout(PLUGIN_PROXY_UI_HANDSHAKE_TIMEOUT_SEC)

            user = str(endpoint.get("username", "") or "")
            password = str(endpoint.get("password", "") or "")
            if user or password:
                sock.sendall(b"\x05\x01\x02")
                reply = self._plugin_proxy_recv_exact(sock, 2)
                if reply != b"\x05\x02":
                    raise OSError("SOCKS auth method rejected")
                ub = user.encode("utf-8")[:255]
                pb = password.encode("utf-8")[:255]
                sock.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
                auth = self._plugin_proxy_recv_exact(sock, 2)
                if len(auth) != 2 or auth[1] != 0:
                    raise OSError("SOCKS auth rejected")
            else:
                sock.sendall(b"\x05\x01\x00")
                reply = self._plugin_proxy_recv_exact(sock, 2)
                if reply != b"\x05\x00":
                    raise OSError("SOCKS no-auth rejected")

            try:
                addr = socket.inet_pton(socket.AF_INET, str(host))
                atyp = b"\x01"
                host_part = addr
            except:
                try:
                    addr = socket.inet_pton(socket.AF_INET6, str(host))
                    atyp = b"\x04"
                    host_part = addr
                except:
                    hb = str(host).encode("idna")[:255]
                    atyp = b"\x03"
                    host_part = bytes([len(hb)]) + hb

            req = b"\x05\x01\x00" + atyp + host_part + struct.pack("!H", int(port) & 0xFFFF)
            sock.sendall(req)
            head = self._plugin_proxy_recv_exact(sock, 4)
            if len(head) != 4 or head[1] != 0:
                code = head[1] if len(head) > 1 else 0xFF
                raise OSError("SOCKS connect failed: 0x%02x" % code)
            atyp = head[3]
            if atyp == 1:
                self._plugin_proxy_recv_exact(sock, 4)
            elif atyp == 3:
                ln = self._plugin_proxy_recv_exact(sock, 1)[0]
                self._plugin_proxy_recv_exact(sock, ln)
            elif atyp == 4:
                self._plugin_proxy_recv_exact(sock, 16)
            else:
                raise OSError("SOCKS reply has invalid address type")
            self._plugin_proxy_recv_exact(sock, 2)
            if on_ui_thread:
                sock.settimeout(caller_timeout)
            return sock
        except:
            try:
                sock.close()
            except:
                pass
            raise

    def _install_python_http_proxy_patch(self):
        if self._plugin_proxy_python_patch_installed:
            return True
        endpoint = self._plugin_proxy_endpoint()
        if not endpoint:
            return False

        plugin = self
        originals = self._plugin_proxy_originals
        originals["socket.create_connection"] = socket.create_connection

        def patched_socket_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *args, **kwargs):
            ep = plugin._plugin_proxy_endpoint()
            try:
                host = address[0]
            except:
                host = ""
            if ep and not plugin._plugin_proxy_is_greenpass_call() and not plugin._plugin_proxy_should_bypass_host(host, ep):
                try:
                    return plugin._plugin_proxy_socks_create_connection(ep, address, timeout, source_address)
                except OSError:
                    return originals["socket.create_connection"](address, timeout, source_address, *args, **kwargs)
            return originals["socket.create_connection"](address, timeout, source_address, *args, **kwargs)

        socket.create_connection = patched_socket_create_connection

        try:
            import urllib3.util.connection as urllib3_connection
            originals["urllib3.util.connection.create_connection"] = urllib3_connection.create_connection

            def patched_urllib3_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
                ep = plugin._plugin_proxy_endpoint()
                try:
                    host = address[0]
                except:
                    host = ""
                if ep and not plugin._plugin_proxy_is_greenpass_call() and not plugin._plugin_proxy_should_bypass_host(host, ep):
                    try:
                        conn = plugin._plugin_proxy_socks_create_connection(ep, address, timeout, source_address)
                    except OSError:
                        return originals["urllib3.util.connection.create_connection"](address, timeout, source_address, socket_options)
                    try:
                        for opt in list(socket_options or []):
                            conn.setsockopt(*opt)
                    except:
                        pass
                    return conn
                return originals["urllib3.util.connection.create_connection"](address, timeout, source_address, socket_options)

            urllib3_connection.create_connection = patched_urllib3_create_connection
        except:
            pass

        self._plugin_proxy_python_patch_installed = True
        return True

    def _remove_python_http_proxy_patch(self):
        if not self._plugin_proxy_python_patch_installed:
            return
        originals = self._plugin_proxy_originals
        try:
            original = originals.get("socket.create_connection")
            if original is not None:
                socket.create_connection = original
        except:
            pass
        try:
            original = originals.get("urllib3.util.connection.create_connection")
            if original is not None:
                import urllib3.util.connection as urllib3_connection
                urllib3_connection.create_connection = original
        except:
            pass
        self._plugin_proxy_python_patch_installed = False

    def _frida_plugin_proxy_script(self, endpoint):
        host = str(endpoint.get("host", "") or "")
        port = int(endpoint.get("port", 0) or 0)
        return """
Java.perform(function () {
  var HOST = %s;
  var PORT = %s;
  var URL = Java.use('java.net.URL');
  var Proxy = Java.use('java.net.Proxy');
  var ProxyType = Java.use('java.net.Proxy$Type');
  var InetSocketAddress = Java.use('java.net.InetSocketAddress');
  var System = Java.use('java.lang.System');
  var proxy = Proxy.$new(ProxyType.valueOf('SOCKS'), InetSocketAddress.$new(HOST, PORT));

  function bypass(host) {
    host = String(host || '').toLowerCase();
    return !host || host === 'localhost' || host === '127.0.0.1' || host === '::1' ||
      host.indexOf('127.') === 0 || host === String(HOST).toLowerCase();
  }

  System.setProperty('socksProxyHost', HOST);
  System.setProperty('socksProxyPort', String(PORT));

  var openNoProxy = URL.openConnection.overload();
  var openWithProxy = URL.openConnection.overload('java.net.Proxy');
  openNoProxy.implementation = function () {
    var host = '';
    try { host = String(this.getHost() || ''); } catch (_) {}
    if (bypass(host)) {
      return openNoProxy.call(this);
    }
    return openWithProxy.call(this, proxy);
  };

  fridaGadget.onDispose(function () {
    try {
      System.clearProperty('socksProxyHost');
      System.clearProperty('socksProxyPort');
    } catch (_) {}
  });
});
""" % (json.dumps(host), int(port))

    def _register_frida_plugin_proxy_hook(self, endpoint=None):
        ep = endpoint if endpoint is not None else self._plugin_proxy_endpoint()
        if not ep:
            return False
        key = self._plugin_proxy_endpoint_key(ep)
        try:
            import frida_gadget_api
        except Exception:
            self._plugin_proxy_frida_registered = False
            return False
        try:
            if self._plugin_proxy_frida_registered and self._plugin_proxy_frida_endpoint_key == key:
                if hasattr(frida_gadget_api, "set_plugin_active"):
                    frida_gadget_api.set_plugin_active(GREENPASS_PLUGIN_PROXY_FRIDA_ID, True, reason="greenpass_proxy", autoload=True)
                return True
            result = frida_gadget_api.register_script(
                GREENPASS_PLUGIN_PROXY_FRIDA_ID,
                self._frida_plugin_proxy_script(ep),
                name=GREENPASS_PLUGIN_PROXY_NAME,
                replace=True,
                autoload=True,
            )
            self._plugin_proxy_frida_registered = bool(result.get("ok", True))
            self._plugin_proxy_frida_endpoint_key = key
            return bool(self._plugin_proxy_frida_registered)
        except Exception as exc:
            self._plugin_proxy_frida_registered = False
            self._plugin_proxy_last_error = str(exc)[:180]
            return False

    def _deactivate_frida_plugin_proxy_hook(self):
        try:
            import frida_gadget_api
            if hasattr(frida_gadget_api, "set_plugin_active"):
                frida_gadget_api.set_plugin_active(GREENPASS_PLUGIN_PROXY_FRIDA_ID, False, reason="greenpass_proxy_off", autoload=True)
        except:
            pass
        self._plugin_proxy_frida_registered = False
        self._plugin_proxy_frida_endpoint_key = ""

    def _sync_plugin_proxy_bridge(self):
        try:
            self._install_plugin_proxy_api()
        except:
            pass
        endpoint = self._plugin_proxy_endpoint()
        if bool(endpoint):
            self._install_python_http_proxy_patch()
            self._register_frida_plugin_proxy_hook(endpoint)
        else:
            self._remove_python_http_proxy_patch()
            self._deactivate_frida_plugin_proxy_hook()
    def _is_plugin_proxy_enabled(self):
        try:
            raw = self.get_setting("use_proxy", None)
            if raw is not None:
                return bool(raw)
        except:
            pass
        try:
            return bool(self._desired_use_proxy)
        except:
            pass
        return bool(_is_tg_proxy_enabled())

    def _enable_plugin_proxy_flag(self):
        self._desired_use_proxy = True
        self._save_config()
        try:
            self._set_setting_value("use_proxy", True, reload_settings=False)
        except:
            pass


    def _is_dont_use_with_vpn_enabled(self):
        try:
            return bool(self.get_setting("dont_use_with_vpn", True))
        except:
            return True

    def _normalize_wifi_ssid(self, value):
        try:
            ssid = str(value or "").strip()
        except:
            return ""
        if len(ssid) >= 2 and ssid[0] == '"' and ssid[-1] == '"':
            ssid = ssid[1:-1]
        ssid = ssid.strip()
        if not ssid or ssid.lower() in ("<unknown ssid>", "unknown ssid", "0x"):
            return ""
        return ssid[:64]

    def _sanitize_excluded_wifi_ssids(self, values):
        if not isinstance(values, (list, tuple)):
            values = []
        result = []
        seen = set()
        for value in values:
            ssid = self._normalize_wifi_ssid(value)
            if not ssid or ssid in seen:
                continue
            seen.add(ssid)
            result.append(ssid)
            if len(result) >= 64:
                break
        return result

    def _sanitize_wifi_mode_rules(self, values):
        if not isinstance(values, dict):
            return {}
        result = {}
        for raw_ssid, raw_mode in values.items():
            ssid = self._normalize_wifi_ssid(raw_ssid)
            mode = str(raw_mode or "")
            if not ssid or mode not in ("off", VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
                continue
            result[ssid] = mode
            if len(result) >= 64:
                break
        return result

    def _active_wifi_state(self):
        try:
            ctx = ApplicationLoader.applicationContext
            cm = ctx.getSystemService("connectivity")
            active = cm.getActiveNetwork() if cm is not None else None
            networks = [active] if active is not None else []
            try:
                for network in list(cm.getAllNetworks() or []):
                    if network not in networks:
                        networks.append(network)
            except:
                pass
            wifi_caps = []
            for network in networks:
                try:
                    caps = cm.getNetworkCapabilities(network)
                    if caps is not None and bool(caps.hasTransport(1)):
                        wifi_caps.append(caps)
                except:
                    pass
            if not wifi_caps:
                self._current_wifi_ssid_cache = ""
                return False, ""

            candidates = []
            for caps in wifi_caps:
                try:
                    candidates.append(caps.getTransportInfo())
                except:
                    pass
            try:
                wifi = ctx.getApplicationContext().getSystemService("wifi")
                candidates.append(wifi.getConnectionInfo() if wifi is not None else None)
            except:
                pass
            for info in candidates:
                if info is None:
                    continue
                try:
                    ssid = self._normalize_wifi_ssid(info.getSSID())
                except:
                    ssid = ""
                if ssid:
                    self._current_wifi_ssid_cache = ssid
                    return True, ssid
            self._current_wifi_ssid_cache = ""
            return True, ""
        except:
            self._current_wifi_ssid_cache = ""
            return False, ""

    def _is_proxy_policy_suspended(self):
        return bool(
            getattr(self, "_proxy_suspended_by_vpn", False)
            or getattr(self, "_proxy_suspended_by_wifi", False)
        )

    def _is_system_vpn_active(self):
        try:
            ctx = ApplicationLoader.applicationContext
            cm = ctx.getSystemService("connectivity")
            if cm is None:
                return False
            network = cm.getActiveNetwork()
            if network is None:
                return False
            caps = cm.getNetworkCapabilities(network)
            return bool(caps is not None and caps.hasTransport(4))
        except:
            pass
        return False

    def _apply_vpn_policy(self):
        try:
            if not self._vpn_policy_lock.acquire(blocking=False):
                return
        except:
            return
        try:
            was_suspended = self._is_proxy_policy_suspended()
            previous_vpn = bool(self._proxy_suspended_by_vpn)
            previous_wifi = bool(self._proxy_suspended_by_wifi)
            wants_proxy = bool(self._desired_use_proxy) or bool(self._is_plugin_proxy_enabled())
            previous_ssid = str(getattr(self, "_current_wifi_ssid_cache", "") or "")
            wifi_active, ssid = self._active_wifi_state()
            if not ssid and previous_ssid and bool(getattr(self, "_vless_backgrounded", False)):
                wifi_active, ssid = True, previous_ssid
                self._current_wifi_ssid_cache = previous_ssid
            rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
            self._wifi_mode_rules = rules
            self._excluded_wifi_ssids = [name for name, mode in rules.items() if mode == "off"]
            rule_mode = rules.get(ssid, "") if wifi_active and ssid else ""
            previous_rule_ssid = str(getattr(self, "_wifi_rule_active_ssid", "") or "")
            self._wifi_rule_active_ssid = ssid if rule_mode else ""
            target_mode = ""
            if rule_mode and rule_mode != "off":
                target_mode = rule_mode
            elif previous_rule_ssid and not rule_mode:
                target_mode = self._normalize_proxy_mode(self._wifi_default_mode, self._connection_mode)
            self._proxy_suspended_by_vpn = bool(
                wants_proxy and self._is_dont_use_with_vpn_enabled() and self._is_system_vpn_active()
            )
            self._proxy_suspended_by_wifi = bool(
                wants_proxy and rule_mode == "off"
            )
            is_suspended = self._is_proxy_policy_suspended()
            if target_mode and target_mode != self._get_connection_mode():
                self._switch_mode_for_wifi_rule(
                    target_mode,
                    connect=bool(
                        wants_proxy
                        and not is_suspended
                        and not was_suspended
                        and self._thread is not None
                    ),
                )
            changed = (
                previous_vpn != bool(self._proxy_suspended_by_vpn)
                or previous_wifi != bool(self._proxy_suspended_by_wifi)
            )
            if is_suspended and not was_suspended:
                message = (
                    "WIFI %s — прокси приостановлен" % ssid
                    if self._proxy_suspended_by_wifi
                    else "VPN активен — прокси приостановлен"
                )
                self._suspend_proxy_for_policy(message)
            elif was_suspended and not is_suspended:
                self._resume_proxy_after_policy()
            elif changed:
                run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        finally:
            try:
                self._vpn_policy_lock.release()
            except:
                pass

    def _switch_mode_for_wifi_rule(self, mode, connect=True):
        target = self._normalize_proxy_mode(mode, self._wifi_default_mode)
        self._wifi_rule_switching = True
        try:
            self._set_connection_mode(target)
        finally:
            self._wifi_rule_switching = False
        if not connect:
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
            return
        switch = {
            VLESS_KIND: self._switch_to_vless_mode,
            TGWS_KIND: self._switch_to_tgws_mode,
            AWG_KIND: self._switch_to_awg_mode,
            OLCRTC_KIND: self._switch_to_olcrtc_mode,
        }[target]
        try:
            threading.Thread(target=lambda: switch(False), daemon=True).start()
        except:
            switch(False)
        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))

    def _suspend_proxy_for_policy(self, message):
        self._save_config()
        for disconnect in (self._vless_disconnect_with_reason, self._tgws_disconnect_with_reason, self._awg_disconnect_with_reason, self._olcrtc_disconnect_with_reason):
            try:
                disconnect("network_policy_suspend", silent=True)
            except:
                pass
        try:
            _set_tg_proxy_enabled(False)
        except:
            pass
        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        run_on_ui_thread(lambda message=message: BulletinHelper.show_info(message))

    def _resume_proxy_after_policy(self):
        self._save_config()
        if not bool(self._desired_use_proxy):
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
            return
        try:
            if self._is_vless_mode_selected():
                self._reset_vless_retry()
                self._ensure_vless_core_then(self._vless_connect)
            elif self._is_tgws_mode_selected():
                self._tgws_connect()
            elif self._is_awg_mode_selected():
                self._ensure_awg_core_then(self._awg_connect)
            elif self._is_olcrtc_mode_selected():
                self._ensure_olcrtc_core_then(self._olcrtc_connect)
        except:
            pass
        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        run_on_ui_thread(lambda: BulletinHelper.show_info("Прокси восстановлен"))

    def _on_dont_use_with_vpn_changed(self, enabled):
        try:
            self.set_setting("dont_use_with_vpn", bool(enabled), reload_settings=False)
        except:
            pass
        threading.Thread(target=self._apply_vpn_policy, daemon=True).start()


    def _after_excluded_wifi_change(self):
        self._wifi_mode_rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        self._excluded_wifi_ssids = [
            ssid for ssid, mode in self._wifi_mode_rules.items() if mode == "off"
        ]
        self._save_config()
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        threading.Thread(target=self._apply_vpn_policy, daemon=True).start()

    def _wifi_rule_mode_title(self, mode):
        return "Без прокси" if str(mode or "") == "off" else self._settings_mode_title(mode)

    def _set_wifi_rule(self, value, mode):
        ssid = self._normalize_wifi_ssid(value)
        if not ssid:
            BulletinHelper.show_error("Укажите SSID сети")
            return False
        target = str(mode or "")
        if target not in ("off", VLESS_KIND, TGWS_KIND, AWG_KIND, OLCRTC_KIND):
            return False
        rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        rules[ssid] = target
        self._wifi_mode_rules = rules
        self._after_excluded_wifi_change()
        BulletinHelper.show_success("Правило WIFI сохранено")
        return True

    def _add_current_wifi_to_excluded(self):
        wifi_active, ssid = self._active_wifi_state()
        if not ssid:
            message = "SSID недоступен" if wifi_active else "WIFI не подключён"
            BulletinHelper.show_error(message)
            return False
        return self._open_wifi_rule_picker(ssid)



    def _remove_excluded_wifi_ssid(self, value):
        ssid = self._normalize_wifi_ssid(value)
        rules = self._sanitize_wifi_mode_rules(self._wifi_mode_rules)
        if ssid not in rules:
            return False
        rules.pop(ssid, None)
        self._wifi_mode_rules = rules
        self._after_excluded_wifi_change()
        return True




    def _get_calls_proxy_preference(self):
        try:
            raw = self.get_setting("proxy_calls_via_proxy", None)
            if raw is not None:
                return bool(raw)
        except:
            pass
        try:
            prefs = MessagesController.getGlobalMainSettings()
            return bool(prefs.getBoolean("proxy_enabled_calls", False))
        except:
            return False





    def _save_tgws_voip_relay_config(self, config):
        relay_ip, relay_port, secret = config
        self._tgws_voip_relay_retry_after = 0.0
        self.set_setting("tgws_voip_relay_ip", relay_ip, reload_settings=False)
        self.set_setting("tgws_voip_relay_port", str(relay_port), reload_settings=False)
        self.set_setting("tgws_voip_relay_hmac", secret, reload_settings=False)
        self._set_tgws_voip_relay_enabled(True, reload_settings=True)
        BulletinHelper.show_success("Voice Relay переключён")
        return True

    def _show_tgws_voip_relay_confirmation(self, config, ping_ms):
        if not self._active:
            return False
        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment else None
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть подтверждение")
            return False
        relay_ip, relay_port, _ = config
        ping_text = "%d мс" % ping_ms if ping_ms is not None else "нет ответа"
        builder = AlertDialogBuilder(activity)
        builder.set_title("Сменить Voice Relay?")
        builder.set_message("Сервер: %s:%d\nПинг: %s" % (relay_ip, relay_port, ping_text))

        def on_yes(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass
            self._save_tgws_voip_relay_config(config)

        def on_no(dlg, which):
            try:
                dlg.dismiss()
            except:
                pass

        builder.set_positive_button("Сменить", on_yes)
        builder.set_negative_button("Отмена", on_no)
        builder.set_cancelable(True)
        builder.show()
        return True

    def _apply_tgws_voip_relay_link(self, uri):
        config, error = _parse_tgws_voip_relay_link(uri)
        if config is None:
            BulletinHelper.show_error(error)
            return False
        BulletinHelper.show_info("Проверяю Voice Relay...")

        def worker():
            ping_ms = _ping_tgws_voip_relay(config)
            run_on_ui_thread(lambda: self._show_tgws_voip_relay_confirmation(config, ping_ms))

        threading.Thread(target=worker, daemon=True).start()
        return True




    def _rewrite_webrtc_join_response(self, payload):
        if self._is_proxy_policy_suspended() or not self._get_tgws_voip_relay_enabled():
            return payload
        try:
            data = json.loads(str(payload))
            candidates = data.get("transport", {}).get("candidates", [])
            if not isinstance(candidates, list):
                return payload
            relay_candidates = []
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                target_ip = str(candidate.get("ip", "") or "")
                if not _is_telegram_reflector_ip(target_ip):
                    continue
                relay_candidates.append((candidate, target_ip, int(candidate.get("port", 0))))
            relays = self._tgws_allocate_voip_relays(
                [(target_ip, target_port) for _, target_ip, target_port in relay_candidates]
            )
            fallback = next((relay for relay in relays if relay), None)
            if fallback is None:
                return payload
            for (candidate, _, _), relay in zip(relay_candidates, relays):
                relay = relay or fallback
                candidate["ip"] = str(relay[0])
                candidate["port"] = str(int(relay[1]))
            return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        except:
            return payload

    def _rewrite_voip_endpoints(self, endpoints, endpoint_cls):
        if self._is_proxy_policy_suspended() or not self._get_tgws_voip_relay_enabled():
            return 0
        try:
            relay_endpoints = []
            for index in range(len(endpoints)):
                endpoint = endpoints[index]
                target_ip = str(getattr(endpoint, "ipv4", "") or "")
                if not _is_telegram_reflector_ip(target_ip) or bool(getattr(endpoint, "tcp", False)):
                    continue
                relay_endpoints.append((index, endpoint, target_ip, int(endpoint.port)))
            relays = self._tgws_allocate_voip_relays(
                [(target_ip, target_port) for _, _, target_ip, target_port in relay_endpoints]
            )
            fallback = next((relay for relay in relays if relay), None)
            if fallback is None:
                return 0
            replacements = []
            for (index, endpoint, _, _), relay in zip(relay_endpoints, relays):
                relay = relay or fallback
                replacement = endpoint_cls(
                    bool(endpoint.isRtc),
                    int(endpoint.id),
                    str(relay[0]),
                    "",
                    int(relay[1]),
                    int(endpoint.type),
                    endpoint.peerTag,
                    bool(endpoint.turn),
                    bool(endpoint.stun),
                    getattr(endpoint, "username", None),
                    getattr(endpoint, "password", None),
                    False,
                )
                try:
                    replacement.reflectorId = int(endpoint.reflectorId)
                except:
                    pass
                replacements.append((index, endpoint, replacement))
            applied = []
            try:
                for index, original, replacement in replacements:
                    endpoints[index] = replacement
                    applied.append((index, original))
            except:
                for index, original in applied:
                    try:
                        endpoints[index] = original
                    except:
                        pass
                return 0
            return len(replacements)
        except:
            return 0

    def _plugins_controller_instance(self):
        try:
            PC = find_class("com.exteragram.messenger.plugins.PluginsController")
        except:
            PC = None
        if PC is None:
            return None
        try:
            return PC.getInstance()
        except:
            return None

    def _plugin_settings_id(self):
        candidates = []
        try:
            candidates.append(str(getattr(self, "id", "") or ""))
        except:
            pass
        for item in [__id__, __name__, "GreenPass", "greenpass"]:
            try:
                candidates.append(str(item or ""))
            except:
                pass

        inst = self._plugins_controller_instance()
        seen = set()
        if inst is not None:
            for candidate in candidates:
                if not candidate or candidate in seen:
                    continue
                seen.add(candidate)
                try:
                    if hasattr(inst, "plugins") and inst.plugins.get(candidate) is not None:
                        return candidate
                except:
                    pass

        for candidate in candidates:
            if candidate:
                return candidate
        return str(__id__)

    def _set_setting_value(self, key, value, reload_settings=False):
        setting_key = str(key or "")
        if value is None:
            return False
        inst = self._plugins_controller_instance()
        pid = self._plugin_settings_id()
        if inst is not None and pid and setting_key:
            try:
                engine = inst.getPluginEngine(pid)
            except:
                engine = None
            if engine is not None:
                try:
                    engine.setPluginSetting(pid, setting_key, value)
                    if reload_settings:
                        try:
                            if setting_key == "__reload__":
                                inst.loadPluginSettings(pid)
                            else:
                                self._reload_settings_ui()
                        except:
                            pass
                    return True
                except:
                    pass
            try:
                inst.setPluginSetting(pid, setting_key, value)
                if reload_settings:
                    try:
                        if setting_key == "__reload__":
                            inst.loadPluginSettings(pid)
                        else:
                            self._reload_settings_ui()
                    except:
                        pass
                return True
            except:
                pass

        try:
            direct_reload = bool(reload_settings and setting_key == "__reload__")
            self.set_setting(setting_key, value, reload_settings=direct_reload)
            if reload_settings and setting_key != "__reload__":
                try:
                    self._reload_settings_ui()
                except:
                    pass
            return True
        except:
            return False






    def _provider_vless_sub_name(self, provider_idx, url, total_urls=1):
        name = str(self._vless_provider_name(provider_idx) or "").strip()
        if name and int(total_urls) <= 1:
            return name
        try:
            host = str(urllib.parse.urlparse(str(url or "")).netloc or "").strip()
        except:
            host = ""
        if name and host:
            return f"{name} • {host}"
        if name:
            return name
        return host or "Серверы"

    def _apply_local_socks_proxy(self, port, enable, owner=None, expected_port=None, username="", password="", secret=""):
        try:
            target_port = int(port or 0)
        except:
            target_port = 0
        try:
            expected = int(expected_port or 0)
        except:
            expected = 0
        target_owner = self._normalize_local_socks_owner(owner)
        if bool(enable) and not target_owner:
            target_owner = self._current_mode_local_socks_owner()

        with self._local_socks_lock:
            current_owner = str(self._local_socks_owner or "")
            current_port = int(self._local_socks_port or 0)

            if bool(enable):
                if target_port <= 0 or not target_owner:
                    return False
                if not self._local_socks_owner_can_apply(target_owner):
                    return False
                self._local_socks_owner = target_owner
                self._local_socks_port = int(target_port)
            else:
                if target_owner and current_owner and current_owner != target_owner:
                    return False
                if expected > 0 and current_port > 0 and current_port != expected:
                    return False

            ok = self._apply_local_socks_proxy_unlocked(
                target_port,
                bool(enable),
                owner=target_owner,
                username=username,
                password=password,
                secret=secret,
            )
            if ok:
                if bool(enable):
                    self._local_socks_owner = target_owner
                    self._local_socks_port = int(target_port)
                elif (not target_owner) or (not current_owner) or current_owner == target_owner:
                    self._local_socks_owner = ""
                    self._local_socks_port = 0
            elif bool(enable):
                self._local_socks_owner = current_owner
                self._local_socks_port = current_port
            return bool(ok)

    def _local_proxy_settings(self, proxy):
        """Return the wrapped ProxySettings object across Telegram forks."""
        if proxy is None:
            return None
        try:
            settings = getattr(proxy, "settings", None)
            if settings is not None:
                return settings
        except:
            pass
        try:
            getter = getattr(proxy, "getSettings", None)
            if callable(getter):
                settings = getter()
                if settings is not None:
                    return settings
        except:
            pass
        try:
            return proxy.getClass().getField("settings").get(proxy)
        except:
            return None

    def _local_proxy_values(self, proxy):
        """Read proxy fields from both legacy ProxyInfo and ProxySettings APIs."""
        settings = self._local_proxy_settings(proxy)
        sources = [source for source in (proxy, settings) if source is not None]

        def read(names, default):
            for source in sources:
                for name in names:
                    try:
                        value = getattr(source, name)
                        if callable(value):
                            value = value()
                        if value is not None:
                            return value
                    except:
                        continue
            return default

        try:
            port = int(read(("port", "getPort"), 0) or 0)
        except:
            port = 0
        return {
            "address": str(read(("address", "getAddress"), "") or ""),
            "port": port,
            "username": str(read(("username", "user", "getUser"), "") or ""),
            "password": str(read(("password", "getPassword"), "") or ""),
            "secret": str(read(("secret", "getSecret"), "") or ""),
        }

    def _new_local_proxy_info(self, host, port, username="", password="", secret=""):
        """Build ProxyInfo across Telegram's legacy and ProxySettings constructors."""
        try:
            proxy_info_class = find_class("org.telegram.messenger.SharedConfig$ProxyInfo")
        except:
            proxy_info_class = None
        if proxy_info_class is None:
            try:
                proxy_info_class = SharedConfig.ProxyInfo
            except:
                proxy_info_class = None

        for settings_path in ("org.telegram.utils.proxy.ProxySettings", "org.telegram.proxy.ProxySettings"):
            try:
                settings_class = find_class(settings_path)
                builder = settings_class.builder()
                builder.setAddress(str(host))
                builder.setPort(int(port))
                builder.setUser(str(username or ""))
                builder.setPassword(str(password or ""))
                builder.setSecret(str(secret or ""))
                try:
                    proxy_type_class = find_class(settings_path + "$Type")
                    socks5_type = getattr(proxy_type_class, "SOCKS5")
                    builder.setType(socks5_type)
                except:
                    # SOCKS5 is the ProxySettings builder's default type.
                    pass
                settings = builder.build()
                if proxy_info_class is None:
                    proxy_info_class = find_class("org.telegram.messenger.SharedConfig$ProxyInfo")
                return proxy_info_class(settings)
            except:
                continue

        if proxy_info_class is not None:
            try:
                return proxy_info_class(str(host), int(port), str(username or ""), str(password or ""), str(secret or ""))
            except:
                pass
        return None

    def _set_native_proxy_settings(self, enabled, proxy=None, host="", port=0, username="", password="", secret=""):
        """Call the native connection API using whichever overload this app exposes."""
        if not bool(enabled):
            try:
                ConnectionsManager.setProxySettings(False, None)
                return True
            except:
                try:
                    ConnectionsManager.setProxySettings(False, "", 0, "", "", "")
                    return True
                except:
                    return False

        try:
            settings = self._local_proxy_settings(proxy)
            if settings is not None:
                ConnectionsManager.setProxySettings(True, settings)
                return True
        except:
            pass
        try:
            values = self._local_proxy_values(proxy) if proxy is not None else {}
            ConnectionsManager.setProxySettings(
                True,
                str(values.get("address", host) or host),
                int(values.get("port", port) or port),
                str(values.get("username", username) or username),
                str(values.get("password", password) or password),
                str(values.get("secret", secret) or secret),
            )
            return True
        except:
            return False

    def _apply_local_socks_proxy_unlocked(self, port, enable, owner=None, username="", password="", secret=""):
        try:
            self._load_proxy_list_safe()
        except:
            pass

        try:
            editor = MessagesController.getGlobalMainSettings().edit()
        except:
            editor = None

        proxy_user = str(username or "") if enable else ""
        proxy_pass = str(password or "") if enable else ""
        proxy_secret = str(secret or "") if enable else ""
        try:
            calls_proxy_enabled = bool(enable and (not proxy_secret) and self._get_calls_proxy_preference())
        except:
            calls_proxy_enabled = False

        existing_local_proxy = None
        try:
            proxy_list = getattr(SharedConfig, "proxyList", None)
            if proxy_list is not None and enable:
                stale_local = []
                for i in range(int(proxy_list.size())):
                    try:
                        item = proxy_list.get(i)
                        values = self._local_proxy_values(item)
                        if values["address"] != VLESS_LOCAL_HOST:
                            continue
                        same_proxy = (
                            values["port"] == int(port)
                            and values["username"] == proxy_user
                            and values["password"] == proxy_pass
                            and values["secret"] == proxy_secret
                        )
                        if same_proxy and existing_local_proxy is None:
                            existing_local_proxy = item
                        else:
                            stale_local.append(item)
                    except:
                        continue
                for item in stale_local:
                    try:
                        SharedConfig.deleteProxy(item)
                    except:
                        pass
        except:
            existing_local_proxy = None

        if enable and existing_local_proxy is not None:
            try:
                if getattr(SharedConfig, "currentProxy", None) == existing_local_proxy and bool(getattr(SharedConfig, "proxyEnabled", False)) and self._is_local_proxy_applied(port):
                    _log_diag("INFO", f"Native proxy settings already active on port {port}")
                    return True
            except:
                pass

        if enable:
            proxy_obj = existing_local_proxy
            if proxy_obj is None:
                proxy_obj = self._new_local_proxy_info(VLESS_LOCAL_HOST, int(port), proxy_user, proxy_pass, proxy_secret)
            if proxy_obj is None:
                return False

            if existing_local_proxy is None:
                try:
                    added_proxy = SharedConfig.addProxy(proxy_obj)
                    if added_proxy is not None:
                        values = self._local_proxy_values(added_proxy)
                        if (
                            values["address"] == VLESS_LOCAL_HOST
                            and values["port"] == int(port)
                            and values["username"] == proxy_user
                            and values["password"] == proxy_pass
                            and values["secret"] == proxy_secret
                        ):
                            proxy_obj = added_proxy
                except:
                    pass

                # Telegram forks differ on whether addProxy() returns the
                # inserted row and on when proxyList is replaced. Read the live
                # list, then fall back to inserting the row if needed.
                try:
                    proxy_list = getattr(SharedConfig, "proxyList", None)
                    items = []
                    if proxy_list is not None:
                        try:
                            size = int(proxy_list.size())
                            items = [proxy_list.get(index) for index in range(size)]
                        except:
                            try:
                                items = list(proxy_list)
                            except:
                                items = []
                    registered = False
                    for item in items:
                        values = self._local_proxy_values(item)
                        if (
                            values["address"] == VLESS_LOCAL_HOST
                            and values["port"] == int(port)
                            and values["username"] == proxy_user
                            and values["password"] == proxy_pass
                            and values["secret"] == proxy_secret
                        ):
                            proxy_obj = item
                            registered = True
                            break
                    if not registered and proxy_list is not None:
                        try:
                            add_row = getattr(proxy_list, "add", None)
                            if callable(add_row):
                                add_row(proxy_obj)
                                registered = True
                        except:
                            pass
                        if not registered:
                            try:
                                append_row = getattr(proxy_list, "append", None)
                                if callable(append_row):
                                    append_row(proxy_obj)
                                    registered = True
                            except:
                                pass
                except:
                    pass

            try:
                SharedConfig.currentProxy = proxy_obj
                SharedConfig.proxyEnabled = True
            except:
                pass

            if editor is not None:
                try:
                    settings = self._local_proxy_settings(proxy_obj)
                    settings_saved = False
                    if settings is not None:
                        try:
                            # Newer Telegram builds store proxy fields and type
                            # through ProxySettings, including clearing stale
                            # fields left by other proxy modes.
                            settings.toSharedPreferences(editor)
                            settings_saved = True
                        except:
                            pass
                    if not settings_saved:
                        editor.putString("proxy_ip", VLESS_LOCAL_HOST)
                        editor.putInt("proxy_port", int(port))
                        editor.putString("proxy_user", proxy_user)
                        editor.putString("proxy_pass", proxy_pass)
                        editor.putString("proxy_secret", proxy_secret)
                        editor.putInt("proxy_type", 0)
                    editor.putBoolean("proxy_enabled", True)
                    editor.putBoolean("proxy_enabled_calls", bool(calls_proxy_enabled))
                    editor.putBoolean("proxy_calls_enabled", bool(calls_proxy_enabled))
                    editor.putBoolean("calls_use_proxy", bool(calls_proxy_enabled))
                except:
                    pass
        else:
            try:
                SharedConfig.proxyEnabled = False
            except:
                pass
            if editor is not None:
                try:
                    editor.putBoolean("proxy_enabled", False)
                    editor.putBoolean("proxy_enabled_calls", False)
                    editor.putBoolean("proxy_calls_enabled", False)
                    editor.putBoolean("calls_use_proxy", False)
                except:
                    pass

        try:
            if editor is not None:
                editor.commit()
        except:
            try:
                if editor is not None:
                    editor.apply()
            except:
                pass

        try:
            if hasattr(SharedConfig, "saveProxyList"):
                SharedConfig.saveProxyList()
        except:
            pass

        try:
            SharedConfig.saveConfig()
        except:
            pass

        native_applied = False
        try:
            native_applied = bool(self._set_native_proxy_settings(
                bool(enable),
                proxy=proxy_obj if enable else None,
                host=VLESS_LOCAL_HOST,
                port=int(port or 0),
                username=proxy_user,
                password=proxy_pass,
                secret=proxy_secret,
            ))
        except:
            native_applied = False
        _log_diag("INFO" if native_applied else "ERROR", f"Native proxy settings applied: {native_applied} (port={port}, enable={enable}, owner={owner})")

        def _notify():
            try:
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged)
            except:
                pass

        try:
            run_on_ui_thread(_notify, 300)
        except:
            _notify()
        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        return native_applied


    def _is_local_proxy_applied(self, port, owner=None):
        try:
            expected_port = int(port or 0)
        except:
            expected_port = 0
        if expected_port <= 0:
            return False

        try:
            current = SharedConfig.currentProxy
        except:
            current = None
        if current is None:
            return False

        current_values = self._local_proxy_values(current)
        current_host = current_values["address"]
        current_port = current_values["port"]
        if current_host != VLESS_LOCAL_HOST or current_port != expected_port:
            return False

        try:
            prefs = MessagesController.getGlobalMainSettings()
            if not bool(prefs.getBoolean("proxy_enabled", False)):
                return False
            if str(prefs.getString("proxy_ip", "") or "") != VLESS_LOCAL_HOST:
                return False
            if int(prefs.getInt("proxy_port", 0) or 0) != expected_port:
                return False
        except:
            return False
        target_owner = self._normalize_local_socks_owner(owner)
        if target_owner:
            current_owner, current_owner_port = self._local_socks_owner_snapshot()
            if current_owner and current_owner != target_owner:
                return False
            if current_owner_port > 0 and current_owner_port != expected_port:
                return False
        return True

    def _is_local_vless_proxy_applied(self, port):
        if not self._is_local_proxy_applied(port, owner=str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND)):
            return False
        try:
            current_values = self._local_proxy_values(SharedConfig.currentProxy)
            return (current_values["username"] == str(self._vless_socks_username or "")
                    and current_values["password"] == str(self._vless_socks_password or "")
                    and not current_values["secret"])
        except:
            return False


    def _reuse_running_vless_if_ready(self, target_key):
        if not target_key or str(getattr(self, "_vless_active_config_key", "") or "") != str(target_key):
            return False
        try:
            port = int(self._vless_port or 0)
        except:
            port = 0
        if port <= 0 or not bool(self._vless_running):
            return False
        username = str(getattr(self, "_vless_socks_username", "") or "")
        password = str(getattr(self, "_vless_socks_password", "") or "")
        if not _check_vless_socks_ready(port, timeout=0.35, username=username, password=password):
            return False
        if not self._is_local_vless_proxy_applied(port):
            if not self._vless_apply_tg_proxy(port, True, username=username, password=password):
                return False
        self._reset_vless_retry()
        self._set_vless_connection_state(False, "")
        run_on_ui_thread(self._refresh_settings_without_reopen)
        return True


    def _is_local_tgws_proxy_applied(self, port):
        return self._is_local_proxy_applied(port, owner=TGWS_KIND)






    def _is_local_olcrtc_proxy_applied(self, port):
        return self._is_local_proxy_applied(port, owner=OLCRTC_KIND)

    def _clear_local_socks_proxy_if_port(self, port, owner=None):
        try:
            expected_port = int(port or 0)
        except:
            expected_port = 0
        if expected_port <= 0:
            return False
        target_owner = self._normalize_local_socks_owner(owner)
        if target_owner:
            current_owner, current_owner_port = self._local_socks_owner_snapshot()
            if current_owner and current_owner != target_owner:
                return False
            if current_owner_port > 0 and current_owner_port != expected_port:
                return False
        try:
            if not self._is_local_proxy_applied(expected_port, owner=target_owner):
                return False
        except:
            return False
        return self._apply_local_socks_proxy(0, False, owner=target_owner, expected_port=expected_port)

    def _stop_all_proxy_cores(self, target_port=10804):
        try:
            _stop_global_go_core()
        except:
            pass
        try:
            if getattr(self, "_vless_core", None) is not None:
                self._vless_core.stop()
        except:
            pass
        try:
            if getattr(self, "_awg_core", None) is not None:
                self._awg_core.stop()
        except:
            pass
        try:
            if getattr(self, "_olcrtc_core", None) is not None:
                self._olcrtc_core.stop()
        except:
            pass
        try:
            if getattr(self, "_tgws_core", None) is not None:
                self._tgws_core.stop()
        except:
            pass

    def _download_libvless_with_progress(self):
        return self._install_libsingbox_bundle(allow_network=True)

    def _download_libawg_with_progress(self):
        return self._install_libsingbox_bundle(allow_network=True)

    def _next_vless_generation(self):
        with self._vless_transition_lock:
            self._vless_generation = int(self._vless_generation or 0) + 1
            return int(self._vless_generation)

    def _same_vless_generation(self, generation):
        with self._vless_transition_lock:
            return int(self._vless_generation or 0) == int(generation)

    def _pick_vless_runtime_port(self):
        preferred = int(VLESS_LOCAL_PORT)
        avoid_preferred = bool(getattr(self, "_vless_avoid_preferred_port_once", False))
        self._vless_avoid_preferred_port_once = False
        if (not avoid_preferred) and _wait_vless_port_closed(preferred, timeout_sec=1.5, poll_sec=0.1):
            return preferred
        reserved = set(int(value) for value in list(TGWS_RESERVED_PORTS or []))
        for _ in range(24):
            try:
                candidate = int(_get_free_port())
            except:
                continue
            if candidate in reserved:
                continue
            if _wait_vless_port_closed(candidate, timeout_sec=0.05, poll_sec=0.05):
                return candidate
        return 0


    def _reset_vless_retry(self):
        self._vless_retry_failures = 0
        self._vless_retry_after = 0.0


    def _delay_vless_retry(self):
        self._vless_retry_failures = int(self._vless_retry_failures or 0) + 1
        self._vless_retry_after = time.monotonic() + _vless_retry_delay(self._vless_retry_failures)

    def _auto_reconnect_vless(self):
        if bool(self._vless_backgrounded):
            return False
        if time.monotonic() < float(self._vless_retry_after or 0.0):
            return False
        if bool(getattr(self, "_vless_connect_worker_active", False)):
            return False
        if self._restore_running_vless_proxy():
            return True
        if int(self._vless_port or 0) > 0 and not bool(self._vless_running):
            self._vless_disconnect(silent=True, cancel_pending=False)
        self._ensure_vless_core_then(self._vless_connect)
        return True

    def _restore_running_vless_proxy(self, force_reapply=False, check_tunnel=False):
        port = int(self._vless_port or 0)
        if not bool(self._vless_running) or port <= 0:
            return False
        username = str(getattr(self, "_vless_socks_username", "") or "")
        password = str(getattr(self, "_vless_socks_password", "") or "")
        if not _check_vless_socks_ready(port, timeout=0.35, username=username, password=password):
            return False
        if bool(check_tunnel) and not _check_vless_tunnel_ready(port, timeout=1.5, username=username, password=password):
            return False
        if bool(force_reapply) or not self._is_local_vless_proxy_applied(port):
            if not self._vless_apply_tg_proxy(port, True, username=username, password=password):
                return False
        self._reset_vless_retry()
        self._set_vless_connection_state(False, "")
        run_on_ui_thread(self._refresh_settings_without_reopen)
        return True

    def _resume_vless_after_background(self, backgrounded_for=0.0):
        if not self._should_run_vless():
            return False
        expected_uri = str(self._get_active_vless_uri() or "")
        verify_tunnel = expected_uri == VLESS_AUTO_SUBSCRIPTIONS_URI and float(backgrounded_for or 0.0) >= 30.0
        self._vless_resume_recovery_token = int(getattr(self, "_vless_resume_recovery_token", 0) or 0) + 1
        recovery_token = int(self._vless_resume_recovery_token)
        self._vless_resume_reconnect = False
        deadline = time.monotonic() + float(VLESS_RESUME_LOCAL_GRACE_SEC)
        while self._should_run_vless() and str(self._get_active_vless_uri() or "") == expected_uri:
            if self._restore_running_vless_proxy(force_reapply=True, check_tunnel=verify_tunnel):
                return True
            if time.monotonic() >= deadline:
                break
            time.sleep(0.25)
        if not self._should_run_vless() or str(self._get_active_vless_uri() or "") != expected_uri:
            return False
        if verify_tunnel:
            self._reset_vless_retry()
        elif time.monotonic() < float(self._vless_retry_after or 0.0):
            return False
        try:
            self._vless_disconnect(silent=True, cancel_pending=False)
        except:
            pass
        self._vless_resume_reconnect = expected_uri == VLESS_AUTO_SUBSCRIPTIONS_URI
        self._ensure_vless_core_then(self._vless_connect)
        if verify_tunnel:
            self._schedule_vless_auto_resume_recovery(expected_uri, recovery_token)
        return False

    def _schedule_vless_auto_resume_recovery(self, expected_uri, recovery_token):
        def _worker():
            time.sleep(float(VLESS_RESUME_AUTO_RECOVERY_DELAY_SEC))
            if (
                int(getattr(self, "_vless_resume_recovery_token", 0) or 0) != int(recovery_token)
                or bool(getattr(self, "_vless_backgrounded", False))
                or not self._should_run_vless()
                or str(self._get_active_vless_uri() or "") != str(expected_uri or "")
            ):
                return
            if self._restore_running_vless_proxy(force_reapply=True, check_tunnel=True):
                return
            self._reset_vless_retry()
            self._vless_resume_reconnect = False
            try:
                self._vless_disconnect(silent=True, cancel_pending=False)
            except:
                pass
            self._ensure_vless_core_then(self._vless_connect)

        threading.Thread(target=_worker, daemon=True).start()

    def _abort_vless_generation(self, generation, port):
        with self._vless_transition_lock:
            if int(self._vless_generation or 0) != int(generation) or int(self._vless_port or 0) != int(port or 0):
                return False
            self._vless_generation = int(self._vless_generation or 0) + 1
            self._vless_running = False
            self._vless_port = 0
            self._vless_socks_username = ""
            self._vless_active_config_key = ""
            owner = str(getattr(self, "_vless_local_owner", VLESS_KIND) or VLESS_KIND)
            self._vless_local_owner = VLESS_KIND
            try:
                self._vless_core.stop()
            except:
                pass
            if int(port or 0) > 0:
                self._clear_local_socks_proxy_if_port(port, owner=owner)
            self._delay_vless_retry()
            return True


    def _save_vless_manual_node(self, node):
        if not isinstance(node, dict):
            return None
        node_key = _proxy_uri_dedup_key(node.get("uri", "")) or str(node.get("uri", "") or "")

        manual = []
        try:
            manual = list(self._vless_data.get("manual", []) or [])
        except:
            manual = []

        filtered = []
        for item in manual:
            try:
                item_key = _proxy_uri_dedup_key(item.get("uri", "")) or str(item.get("uri", "") or "")
                if item_key != node_key:
                    filtered.append(item)
            except:
                continue
        filtered.insert(0, node)
        self._vless_data["manual"] = filtered[:64]
        self._vless_data["active_uri"] = str(node.get("uri", "") or "")
        self._vless_save_data()
        return node

    def _validate_core_config_for_import(self, config_json, protocol_label):
        label = str(protocol_label or "Прокси")
        if not self._has_libvless_addon():
            return "Нужно ядро прокси"
        result = self._vless_core.validate(config_json)
        if result is None:
            if self._libsingbox_addon_status() == "outdated" and self._effective_vless_engine() == VLESS_ENGINE_SINGBOX:
                return ""
            return "Обновите ядро: проверка конфигурации недоступна"
        error = str(result or "").strip()
        if not error:
            return ""
        low = error.lower()
        if any(token in low for token in ("not included", "unknown outbound", "unsupported outbound", "not registered")):
            return "Протокол %s не поддерживается текущим ядром" % label
        return "Ошибка конфига %s: %s" % (label, error[:320])

    def _validate_proxy_uri_for_import(self, uri):
        scheme = _proxy_uri_scheme(uri)
        spec = PROXY_PROTOCOL_REGISTRY.get(scheme)
        label = str((spec or {}).get("label", scheme or "Прокси") or "Прокси")
        if not spec:
            return "Протокол %s не поддерживается плагином" % (scheme or "неизвестен")
        if _normalize_vless_engine(self._vless_engine) == VLESS_ENGINE_MIHOMO:
            try:
                config_json = _build_mihomo_core_config(
                    links=[uri],
                    local_port=VLESS_LOCAL_PORT,
                    work_dir=os.path.join(self._vless_dir, "mihomo"),
                    socks_username="greenpass",
                    socks_password=str(self._vless_socks_password or ""),
                )
            except Exception:
                config_json = None
        else:
            config_json, _ = _build_registered_proxy_config(uri, VLESS_LOCAL_PORT)
        if not config_json:
            return "Плагин не умеет собрать конфиг %s" % label
        return self._validate_core_config_for_import(config_json, label)













    def _next_olcrtc_generation(self):
        try:
            self._olcrtc_generation = int(getattr(self, "_olcrtc_generation", 0) or 0) + 1
        except:
            self._olcrtc_generation = 1
        return int(self._olcrtc_generation or 0)

    def _same_olcrtc_generation(self, generation):
        try:
            return int(getattr(self, "_olcrtc_generation", 0) or 0) == int(generation)
        except:
            return False

    def _stop_olcrtc_core_async(self):
        def _worker():
            try:
                with self._olcrtc_stop_lock:
                    if bool(getattr(self, "_olcrtc_stop_in_progress", False)):
                        return
                    self._olcrtc_stop_in_progress = True
                try:
                    self._olcrtc_core.stop()
                except Exception:
                    pass
            finally:
                try:
                    with self._olcrtc_stop_lock:
                        self._olcrtc_stop_in_progress = False
                except:
                    pass

        try:
            threading.Thread(target=_worker, daemon=True).start()
        except:
            try:
                self._olcrtc_core.stop()
            except Exception:
                pass





    def _restart_olcrtc_from_settings(self):
        self._set_connection_mode(OLCRTC_KIND)
        if not self._is_olcrtc_config_ready():
            self._set_olcrtc_last_error(self._olcrtc_config_error(), event="restart_config_error")
            BulletinHelper.show_error(self._olcrtc_config_error())
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
            return
        self._upsert_olcrtc_profile({
            "carrier": self._get_olcrtc_carrier(),
            "transport": self._get_olcrtc_transport(),
            "room_id": self._get_olcrtc_room_id(),
            "client_id": self._get_olcrtc_client_id(),
            "key_hex": self._get_olcrtc_key_hex(),
        })
        BulletinHelper.show_info("Запускаю olcRTC...")
        self._olcrtc_feedback_requested = True
        self._enable_plugin_proxy_flag()
        self._ensure_olcrtc_core_then(self._olcrtc_connect)
        self._refresh_settings_without_reopen(reload_main=True)

    def _download_olcrtc_addon(self):
        if self._has_olcrtc_core_addon():
            BulletinHelper.show_info("Ядро olcRTC уже установлено")
            self._refresh_settings_without_reopen(reload_main=True)
            return
        if self._olcrtc_prepare_in_progress:
            BulletinHelper.show_info("Ядро olcRTC уже готовится")
            return

        self._olcrtc_prepare_in_progress = True
        BulletinHelper.show_info("Готовлю olcRTC...")

        def _worker():
            try:
                ok = self._install_libzvonki_bundle(allow_network=True)
                if ok:
                    run_on_ui_thread(lambda: BulletinHelper.show_success("Ядро установлено — перезапустите приложение"))
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True))
                else:
                    self._set_olcrtc_last_error("core download failed", event="download_core_failed", installed=ok)
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось загрузить olcRTC"))
            finally:
                self._olcrtc_prepare_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()




    def _on_olcrtc_status_tap(self):
        self._copy_active_olcrtc_link()




    def _process_awg_file_uri(self, uri):
        try:
            activity = None
            try:
                fragment = get_last_fragment()
                if fragment is not None:
                    activity = fragment.getParentActivity()
            except:
                activity = None
            if activity is None:
                try:
                    AU = find_class("org.telegram.messenger.AndroidUtilities")
                    activity = AU.getActivity()
                except:
                    activity = None
            if activity is None:
                raise Exception("activity is missing")

            resolver = activity.getContentResolver()
            file_name = "AWG.conf"
            try:
                raw_name = str(uri.getPath() or "").split("/")[-1]
                if ":" in raw_name:
                    raw_name = raw_name.split(":")[-1]
                if raw_name:
                    file_name = raw_name
            except:
                pass
            if not file_name.lower().endswith(".conf"):
                file_name += ".conf"

            BufferedReader = jclass("java.io.BufferedReader") if jclass is not None else find_class("java.io.BufferedReader")
            InputStreamReader = jclass("java.io.InputStreamReader") if jclass is not None else find_class("java.io.InputStreamReader")
            reader = BufferedReader(InputStreamReader(resolver.openInputStream(uri)))
            lines = []
            line = reader.readLine()
            while line is not None:
                lines.append(str(line))
                line = reader.readLine()
            reader.close()

            content = "\n".join(lines) + "\n"
            self._awg_conf_name = file_name
            self._awg_conf_content = content
            self._save_config()
            run_on_ui_thread(lambda: BulletinHelper.show_success("AWG конфиг загружен"))
            if self._is_awg_mode_selected():
                self._enable_plugin_proxy_flag()
                self._ensure_awg_core_then(self._awg_connect)
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True))
        except Exception as exc:
            err_text = str(exc)
            run_on_ui_thread(lambda err_text=err_text: BulletinHelper.show_error("Ошибка чтения AWG: %s" % err_text))

    # ---- AWG IPv4 and Health Check ----

    @staticmethod
    def _awg_conf_has_ipv6(conf_text):
        section = ""
        for raw in str(conf_text or "").splitlines():
            line = str(raw or "").strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue
            if section != "interface" or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if key.lower() == "address" and ":" in value:
                return True
        return False

    def _update_awg_ipv4_state(self):
        try:
            conf = str(getattr(self, "_awg_started_conf", "") or self._awg_conf_content or "")
            want = bool(
                self._awg_running
                and self._should_run_awg()
                and conf.strip()
                and not self._awg_conf_has_ipv6(conf)
            )
            old = bool(getattr(self, "_awg_ipv4_only", False))
            self._awg_ipv4_only = want
            if want:
                self._install_ipv6_hook()
                self._force_ipv4_strategy()
            if want != old:
                self._check_all_connections()
        except Exception:
            pass

    def _on_awg_connected(self):
        try:
            self._update_awg_ipv4_state()
        except Exception:
            pass
        try:
            self._start_awg_health_loop()
        except Exception:
            pass

    def _start_awg_health_loop(self):
        try:
            thread = self._awg_health_thread
            if thread is not None and thread.is_alive() and not self._awg_health_stop.is_set():
                return
            self._awg_health_gen = int(self._awg_health_gen or 0) + 1
            gen = int(self._awg_health_gen)
            stop = threading.Event()
            self._awg_health_stop = stop
            thread = threading.Thread(target=self._awg_health_loop, args=(gen, stop), daemon=True)
            self._awg_health_thread = thread
            thread.start()
        except Exception:
            pass

    def _stop_awg_health_loop(self):
        try:
            self._awg_health_gen = int(self._awg_health_gen or 0) + 1
            self._awg_health_stop.set()
            self._awg_health_thread = None
        except Exception:
            pass

    def _awg_network_online(self):
        try:
            return bool(ApplicationLoader.isNetworkOnline())
        except Exception:
            return True

    def _awg_probe_once(self):
        def _recv_exact(sock, count):
            data = b""
            while len(data) < count:
                chunk = sock.recv(count - len(data))
                if not chunk:
                    break
                data += chunk
            return data

        port = int(self._awg_port or AWG_LOCAL_PORT)
        for host, dport in (("149.154.167.50", 443), ("149.154.175.50", 443)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(10.0)
                    sock.connect((VLESS_LOCAL_HOST, port))
                    sock.sendall(b"\x05\x01\x00")
                    if _recv_exact(sock, 2) != b"\x05\x00":
                        continue
                    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + int(dport).to_bytes(2, "big"))
                    head = _recv_exact(sock, 4)
                    if len(head) == 4 and head[0] == 5 and head[1] == 0:
                        return True
            except Exception:
                pass
        return False

    def _awg_health_loop(self, gen, stop):
        fails = 0
        stop.wait(5)
        while (not stop.is_set()) and self._active and gen == int(self._awg_health_gen or 0):
            delay = 60.0
            try:
                if (
                    (not self._should_run_awg())
                    or bool(self._awg_connecting)
                    or (not self._awg_running)
                    or bool(self._awg_health_recovering)
                    or self._is_proxy_policy_suspended()
                    or (not self._awg_network_online())
                ):
                    fails = 0
                elif self._awg_probe_once():
                    fails = 0
                    self._awg_health_restarts = 0
                    self._awg_refresh_failures = 0
                elif not self._awg_network_online():
                    fails = 0
                else:
                    fails += 1
                    delay = 15.0
                    if fails >= 3:
                        fails = 0
                        if not stop.is_set() and gen == int(self._awg_health_gen or 0):
                            self._awg_health_recover()
                        delay = 20.0
            except Exception:
                pass
            stop.wait(delay)

    def _awg_reconnect_async(self):
        try:
            if self._should_run_awg():
                self._ensure_awg_core_then(self._awg_connect)
        except Exception:
            pass

    def _awg_free_source(self):
        try:
            value = str(self.get_setting("awg_free_source", AWG_SOURCE_DEFAULT) or AWG_SOURCE_DEFAULT).strip().lower()
        except Exception:
            value = AWG_SOURCE_DEFAULT
        return value if value in AWG_SOURCES_ORDER else AWG_SOURCE_DEFAULT

    def _awg_free_source_index(self):
        src = self._awg_free_source()
        try:
            return AWG_SOURCES_ORDER.index(src)
        except Exception:
            return 0

    def _on_awg_free_source_changed(self, index):
        try:
            idx = int(index)
            source = AWG_SOURCES_ORDER[idx] if 0 <= idx < len(AWG_SOURCES_ORDER) else AWG_SOURCE_DEFAULT
        except Exception:
            source = AWG_SOURCE_DEFAULT
        try:
            self._set_setting_value("awg_free_source", source, reload_settings=False)
        except Exception:
            try:
                self.set_setting("awg_free_source", source, reload_settings=False)
            except Exception:
                pass
        if bool(self._awg_conf_is_free):
            self._refresh_free_awg_config_from_settings(source=source)
        return True

    def _awg_download_and_wait(self, source=None):
        done = threading.Event()
        result = [False]

        def _cb(ok):
            result[0] = bool(ok)
            done.set()

        self._download_free_awg_config(refreshed=True, on_done=_cb, source=source)
        done.wait(30)
        return result[0]

    def _awg_health_recover(self):
        self._awg_health_recovering = True
        try:
            now = time.time()
            backoff = min(600.0 * (2 ** int(self._awg_refresh_failures or 0)), 3600.0)
            if bool(self._awg_conf_is_free) and now - float(self._awg_last_refresh_ts or 0.0) >= backoff:
                self._awg_last_refresh_ts = now
                self._awg_refresh_failures = int(self._awg_refresh_failures or 0) + 1
                self._awg_disconnect(silent=True, reason="health_refresh", stop_core=True)
                if not self._awg_download_and_wait():
                    self._awg_reconnect_async()
                return
            if int(self._awg_health_restarts or 0) < 1:
                self._awg_health_restarts = 1
                self._awg_disconnect(silent=True, reason="health_restart", stop_core=True)
                self._awg_reconnect_async()
                return
            self._awg_health_restarts = 0
            self._awg_health_hold_until = now + 600.0
            self._awg_disconnect(silent=True, reason="health_dead", stop_core=True)
            run_on_ui_thread(lambda: BulletinHelper.show_error("AWG сервер не отвечает"))
            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
        except Exception:
            pass
        finally:
            self._awg_health_recovering = False

    def _refresh_free_awg_config_from_settings(self, source=None):
        def _work():
            self._awg_health_recovering = True
            try:
                self._awg_last_refresh_ts = time.time()
                self._awg_health_hold_until = 0.0
                if self._awg_running or bool(getattr(self._awg_core, "started", False)):
                    self._awg_disconnect(silent=True, reason="health_refresh", stop_core=True)
                use_source = source if source is not None else self._awg_free_source()
                is_warp = str(use_source).startswith("warp")
                source_title = AWG_SOURCES_MAP.get(use_source, {}).get("title", use_source)
                if is_warp:
                    msg = Z("Регистрирую %s…") % source_title
                else:
                    msg = Z("Скачиваю новый конфиг AWG...")
                run_on_ui_thread(lambda msg=msg: BulletinHelper.show_info(msg))
                if not self._awg_download_and_wait(source=use_source):
                    self._awg_reconnect_async()
            except Exception:
                pass
            finally:
                self._awg_health_recovering = False

        threading.Thread(target=_work, daemon=True).start()

    def _download_free_awg_config(self, refreshed=False, on_done=None, source=None):
        source = str(source or self._awg_free_source() or AWG_SOURCE_VPGRAM).strip().lower()
        if source not in AWG_SOURCES_ORDER:
            source = AWG_SOURCE_VPGRAM
        is_warp = source.startswith("warp")

        def _done(ok):
            if on_done is not None:
                try:
                    on_done(bool(ok))
                except Exception:
                    pass

        if bool(getattr(self, "_awg_config_downloading", False)):
            _done(False)
            return
        self._awg_config_downloading = True
        source_info = AWG_SOURCES_MAP.get(source, {})
        source_title = source_info.get("title", source)
        if not refreshed:
            msg = Z("Регистрирую %s…") if is_warp else Z("Получаю конфиг: %s…")
            BulletinHelper.show_info(msg % source_title)

        def _check_udp_endpoint(conf_text, timeout=3.0):
            """Return (host, port, reachable) from the first [Peer] Endpoint in the config."""
            try:
                for raw_line in conf_text.splitlines():
                    line = raw_line.strip()
                    if line.lower().startswith("endpoint"):
                        val = line.split("=", 1)[1].strip()
                        if val.startswith("[") and "]:" in val:
                            h, pt = val[1:].rsplit("]:", 1)
                        else:
                            h, pt = val.rsplit(":", 1)
                        p = int(pt)
                        # UDP reachability: send empty packet, wait briefly for ICMP port-unreachable
                        # or just confirm the socket can be created (route exists).
                        # We try a quick connect-then-recv with SO_RCVTIMEO.
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.settimeout(timeout)
                        try:
                            s.connect((h, p))
                            s.send(b"\x00")
                            try:
                                s.recv(1)
                            except socket.timeout:
                                # No ICMP rejection → likely reachable (or firewall drops silently)
                                return h, p, True
                            except OSError:
                                # ICMP port-unreachable → host reachable, UDP port closed
                                return h, p, True
                        except OSError:
                            # Connection refused / network unreachable
                            return h, p, False
                        finally:
                            try:
                                s.close()
                            except Exception:
                                pass
            except Exception:
                pass
            return None, None, True  # Can't determine — assume ok

        def _worker():
            ok = False
            try:
                proxy_url = None
                if bool(getattr(self, "_vless_running", False)):
                    try:
                        ep = self._greenpass_socks_endpoint()
                    except Exception:
                        ep = None
                    if not ep:
                        port = int(getattr(self, "_vless_port", 0) or 0)
                        if port > 0:
                            user = str(getattr(self, "_vless_socks_username", "") or "greenpass")
                            pwd = str(getattr(self, "_vless_socks_password", "") or "")
                            ep = {"host": "127.0.0.1", "port": port, "username": user, "password": pwd}
                    if ep:
                        import urllib.parse as _up
                        h = str(ep.get("host", "127.0.0.1") or "127.0.0.1")
                        p = int(ep.get("port", 0) or 0)
                        u = str(ep.get("username", "") or "")
                        pw = str(ep.get("password", "") or "")
                        if p > 0:
                            if u and pw:
                                proxy_url = "http://%s:%s@%s:%d" % (
                                    _up.quote(u, safe=""), _up.quote(pw, safe=""), h, p)
                            else:
                                proxy_url = "http://%s:%d" % (h, p)

                if is_warp:
                    cfg_info = AWG_SOURCES_MAP.get(source, {})
                    filename = cfg_info.get("filename", WARP_CONF_NAME)
                    ep = cfg_info.get("endpoint", WARP_DEFAULT_ENDPOINT)
                    text = generate_warp_conf(endpoint=ep, proxy_url=proxy_url)
                else:
                    filename, text = self._fetch_vpgram_awg_config(proxy_url=proxy_url)

                # Check if the peer endpoint is reachable via UDP before applying
                ep_host, ep_port, ep_reachable = _check_udp_endpoint(text, timeout=3.0)
                if not ep_reachable and ep_host:
                    warn_msg = Z("AWG эндпоинт %s:%s недоступен — туннель не поднимется") % (ep_host, ep_port)
                    run_on_ui_thread(lambda warn_msg=warn_msg: BulletinHelper.show_error(warn_msg))
                    # Still save the config — user may want to keep it
                    self._awg_conf_name = filename
                    self._awg_conf_content = text
                    self._awg_conf_is_free = True
                    self._save_config()
                    run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True))
                    _done(False)
                    return

                # Endpoint is reachable — save config
                self._awg_conf_name = filename
                self._awg_conf_content = text
                self._awg_conf_is_free = True
                self._awg_health_restarts = 0
                self._awg_health_hold_until = 0.0
                self._save_config()

                # If AWG is already actively connected, don't restart — just report config saved
                awg_already_connected = (
                    bool(getattr(self, "_awg_running", False))
                    and bool(getattr(self, "_awg_socks_ready", False))
                )
                if self._is_awg_mode_selected():
                    if awg_already_connected:
                        # Конфиг сохранён; текущее подключение сохраняется.
                        # Пользователь может вручную нажать "Переподключить AWG" для применения.
                        saved_label = Z("Конфиг сохранён — нажмите ↺ для применения") if refreshed else Z("AWG конфиг получен — нажмите ↺")
                        run_on_ui_thread(lambda saved_label=saved_label: BulletinHelper.show_success(saved_label))
                    else:
                        run_on_ui_thread(lambda: BulletinHelper.show_success(Z("Конфиг AWG обновлён") if refreshed else Z("AWG конфиг получен")))
                        self._enable_plugin_proxy_flag()
                        self._ensure_awg_core_then(self._awg_connect)
                else:
                    run_on_ui_thread(lambda: BulletinHelper.show_success(Z("Конфиг AWG обновлён") if refreshed else Z("AWG конфиг получен")))
                run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True))
                ok = True
            except Exception as exc:
                reason = getattr(exc, "reason", None)
                if isinstance(exc, ssl.SSLCertVerificationError) or isinstance(reason, ssl.SSLCertVerificationError):
                    cert_msg = "Не удалось проверить сертификат сервера WARP" if is_warp else "Не удалось проверить сертификат сервера AWG"
                    run_on_ui_thread(lambda cert_msg=cert_msg: BulletinHelper.show_error(cert_msg))
                else:
                    err_text = str(exc)
                    fail_fmt = "Не удалось зарегистрировать WARP: %s" if is_warp else "Не удалось получить AWG: %s"
                    run_on_ui_thread(lambda err_text=err_text, fail_fmt=fail_fmt: BulletinHelper.show_error(fail_fmt % err_text))
            finally:
                self._awg_config_downloading = False
                _done(ok)

        threading.Thread(target=_worker, daemon=True).start()

    def _fetch_vpgram_awg_config(self, proxy_url=None):
        device_seed = hashlib.sha1(("%s:%s" % (time.time(), random.random())).encode("utf-8")).hexdigest()[:16]
        req = urllib.request.Request(
            "https://web-api.vpgram.click/client-api/v1/download-anonymous-key",
            headers={"X-Device-Id": device_seed},
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        def _do_fetch(purl):
            handlers = []
            if purl:
                handlers.append(urllib.request.ProxyHandler({"http": purl, "https": purl}))
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(req, timeout=12) as resp:
                return resp.read(256 * 1024), str(resp.headers.get("content-disposition", "") or "")

        raw = None
        cd = ""
        try:
            raw, cd = _do_fetch(proxy_url)
        except Exception:
            if proxy_url:
                try:
                    raw, cd = _do_fetch(None)
                except Exception:
                    pass
            if raw is None:
                raise

        text = raw.decode("utf-8", errors="ignore")
        filename = "VPgram_Free.conf"
        try:
            if "filename=" in cd:
                name = cd.split("filename=", 1)[1].strip("\"' ")
                if name:
                    filename = name
        except:
            pass
        if "[Interface]" not in text or "[Peer]" not in text:
            raise Exception("ответ не похож на .conf")
        return filename, text

    def _clear_awg_config(self):
        self._awg_disconnect_with_reason("clear_awg_config", silent=True)
        self._awg_conf_name = ""
        self._awg_conf_content = ""
        self._save_config()
        self._refresh_settings_without_reopen(reload_main=True)

    def _restart_awg_from_settings(self):
        self._set_connection_mode(AWG_KIND)
        self._enable_plugin_proxy_flag()
        self._awg_disconnect_with_reason("restart_awg", silent=True)
        self._ensure_awg_config_then_connect()
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _activate_vless_uri(self, uri, enable_plugin=True, reload_settings=True):
        existing = self._find_vless_node(uri)
        existing_kind = str((existing or {}).get("kind", "") or "").strip().lower()
        existing_from_subscription = False
        if existing:
            try:
                target_uri = str(existing.get("uri", "") or "")
                existing_from_subscription = any(
                    str(item.get("uri", "") or "") == target_uri
                    for sub in list(self._vless_data.get("subs", []) or [])
                    if isinstance(sub, dict)
                    for item in list(sub.get("nodes", []) or [])
                    if isinstance(item, dict)
                )
            except:
                existing_from_subscription = False
        if existing_from_subscription:
            node = existing
            self._vless_data["active_uri"] = str(node.get("uri", "") or "")
            self._vless_save_data()
        elif list((existing or {}).get("balance_nodes", []) or []):
            node = existing
            self._vless_data["active_uri"] = str(node.get("uri", "") or "")
            self._vless_save_data()
        elif existing_kind == QWDTT_KIND:
            node = self._save_vless_manual_node(existing)
        elif existing_kind == "mihomo-config":
            try:
                prepared = _build_mihomo_core_config(
                    config_text=str((existing or {}).get("raw_config", "") or ""),
                    local_port=VLESS_LOCAL_PORT,
                    work_dir=os.path.join(self._vless_dir, "mihomo"),
                    socks_username="greenpass",
                    socks_password=str(self._vless_socks_password or ""),
                )
            except Exception as exc:
                BulletinHelper.show_error("Ошибка конфига Mihomo: %s" % str(exc))
                return False
            validation_error = self._validate_core_config_for_import(prepared, "Mihomo config")
            if validation_error:
                BulletinHelper.show_error(validation_error)
                return False
            self._vless_engine = VLESS_ENGINE_MIHOMO
            node = self._save_vless_manual_node(existing)
        elif existing_kind == "singbox-config":
            try:
                prepared = _prepare_singbox_file_config(str((existing or {}).get("raw_config", "") or ""), VLESS_LOCAL_PORT)
            except Exception as exc:
                BulletinHelper.show_error("Ошибка конфига sing-box: %s" % str(exc))
                return False
            validation_error = self._validate_core_config_for_import(prepared, "sing-box config")
            if validation_error:
                BulletinHelper.show_error(validation_error)
                return False
            self._vless_engine = VLESS_ENGINE_SINGBOX
            node = self._save_vless_manual_node(existing)
        else:
            validation_error = self._validate_proxy_uri_for_import(uri)
            if validation_error:
                BulletinHelper.show_error(validation_error)
                return False
            node = self._add_vless_manual_node(uri)
        if not node:
            BulletinHelper.show_error("Неверная ссылка")
            return

        self._vless_resume_recovery_token = int(getattr(self, "_vless_resume_recovery_token", 0) or 0) + 1

        try:
            self._current_server = str(node.get("server", "") or "")
            self._current_port = int(node.get("port", 0) or 0)
        except:
            pass
        self._set_connection_mode(VLESS_KIND)
        try:
            self._tgws_disconnect_with_reason("activate_vless_uri", silent=True)
        except:
            pass
        try:
            self._awg_disconnect_with_reason("activate_vless_uri", silent=True)
        except:
            pass
        try:
            self._olcrtc_disconnect_with_reason("activate_vless_uri", silent=True)
        except:
            pass

        if enable_plugin:
            try:
                self._enable_plugin_proxy_flag()
            except:
                pass

        self._reset_vless_retry()
        self._set_vless_connection_state(True, "")
        self._ensure_vless_core_then(self._vless_connect)
        if bool(reload_settings):
            self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)


    def _clear_vless_nodes(self):
        self._vless_data = {"manual": [], "subs": [], "active_uri": ""}
        self._vless_disconnect_with_reason("clear_vless_nodes", silent=True)
        self._save_config()
        self._refresh_settings_without_reopen()
        BulletinHelper.show_success("Узлы очищены")


    def _first_vless_uri(self):
        for node in self._get_all_vless_nodes():
            try:
                uri = str(node.get("uri", "") or "")
            except:
                uri = ""
            if uri:
                return uri
        return ""


    def _connect_best_vless_node(self):
        if self._find_vless_node(VLESS_AUTO_SUBSCRIPTIONS_URI) is None:
            BulletinHelper.show_info("Для автовыбора нужны минимум два узла из подписок")
            return False
        self._activate_vless_uri(VLESS_AUTO_SUBSCRIPTIONS_URI, enable_plugin=True)
        BulletinHelper.show_success("Автовыбор включён")
        return True

    def _remove_vless_uri(self, uri):
        target_uri = str(uri or "")
        if not target_uri:
            return False

        removed = False
        was_active = target_uri == self._get_active_vless_uri()

        manual = []
        try:
            for node in list(self._vless_data.get("manual", []) or []):
                try:
                    if str(node.get("uri", "") or "") == target_uri:
                        removed = True
                        continue
                except:
                    pass
                manual.append(node)
        except:
            manual = []

        subs = []
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                nodes = []
                for node in list(sub.get("nodes", []) or []):
                    try:
                        if str(node.get("uri", "") or "") == target_uri:
                            removed = True
                            continue
                    except:
                        pass
                    nodes.append(node)
                if not nodes:
                    continue
                sub_copy = dict(sub)
                sub_copy["nodes"] = nodes
                subs.append(sub_copy)
        except:
            subs = []

        if not removed:
            return False

        self._vless_data["manual"] = manual
        self._vless_data["subs"] = subs
        if was_active:
            self._vless_data["active_uri"] = self._first_vless_uri()
        self._vless_save_data()

        if was_active:
            next_uri = self._get_active_vless_uri()
            if self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND:
                if next_uri:
                    self._ensure_vless_core_then(self._vless_connect)
                else:
                    self._vless_disconnect_with_reason("remove_vless_node", silent=True)
        self._refresh_settings_without_reopen()
        BulletinHelper.show_success("Узел удален")
        return True


    def _refresh_vless_subscriptions(self):
        urls = []
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                url = str(sub.get("url", "") or "")
                if url and url not in urls:
                    urls.append(url)
        except:
            pass
        if not urls:
            BulletinHelper.show_info("Нет подписок")
            return

        BulletinHelper.show_info("Обновляю подписки...")

        def _worker():
            changed = 0
            for url in urls:
                nodes = _fetch_vless_nodes(url)
                if not nodes:
                    continue
                try:
                    for sub in list(self._vless_data.get("subs", []) or []):
                        if str(sub.get("url", "") or "") == url:
                            sub["nodes"] = nodes
                            changed += 1
                except:
                    continue
            if changed:
                self._repair_active_vless_subscription_uri()
            self._vless_save_data()
            if changed and self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND and self._get_active_vless_uri():
                self._ensure_vless_core_then(self._vless_connect)
            run_on_ui_thread(self._refresh_settings_without_reopen)
            run_on_ui_thread(lambda: BulletinHelper.show_success(f"Подписок обновлено: {changed}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _install_singbox_as_vless_core(self, on_progress=None):
        return self._install_libsingbox_bundle(allow_network=True, on_progress=on_progress)




    def _delete_vless_addon(self):
        try:
            self._vless_disconnect_with_reason("delete_vless_addon", silent=True)
        except:
            pass

        ok = False
        try:
            path = self._libvless_so_path()
            if os.path.exists(path):
                os.remove(path)
            self._libsingbox_validation_cache = None
            ok = True
        except:
            ok = False

        self._reload_vless_core()
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        if ok:
            BulletinHelper.show_success("Ядро прокси удалено")
        else:
            BulletinHelper.show_error("Не удалось удалить ядро прокси")

    def _probe_proxy_latency(self, proxy, timeout_sec=2.0):
        sock = None
        try:
            host = str(proxy.get("server", ""))
            port = int(proxy.get("port", 0))
            if not host or port <= 0:
                return None

            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(timeout_sec))
            res = sock.connect_ex((host, port))
            if res != 0:
                return None
            return (time.time() - start) * 1000.0
        except:
            return None
        finally:
            try:
                if sock is not None:
                    sock.close()
            except:
                pass

    def _load_proxy_list_safe(self):
        try:
            if hasattr(SharedConfig, "loadProxyList"):
                SharedConfig.loadProxyList()
        except:
            pass

    def _should_arm_proxy_transition_killswitch(self, enabled, address, port, username, password, secret):
        return True

    def _proxy_transition_accounts(self):
        # Every logged-in account keeps its own connection, not only the one on screen.
        # Only activated slots: getInstance() on an unused slot would spin up its native connection.
        accounts = []
        try:
            accounts.append(int(UserConfig.selectedAccount))
        except:
            accounts.append(0)
        try:
            count = int(UserConfig.MAX_ACCOUNT_COUNT)
        except:
            count = 0
        for i in range(count):
            if i in accounts:
                continue
            try:
                if UserConfig.getInstance(i).isClientActivated():
                    accounts.append(i)
            except:
                pass
        return accounts

    def _is_app_backgrounded(self):
        if bool(getattr(self, "_vless_backgrounded", False)):
            return True
        try:
            return bool(ApplicationLoader.mainInterfacePaused)
        except:
            return False

    def _set_proxy_transition_network_paused(self, paused):
        if paused:
            accounts = self._proxy_transition_accounts()
            self._proxy_transition_paused_accounts = list(accounts)
        else:
            accounts = list(getattr(self, "_proxy_transition_paused_accounts", None) or [])
            self._proxy_transition_paused_accounts = []
            # In background the app keeps its own connections paused and resumes them itself
            # on return to foreground; resuming here would override that.
            if self._is_app_backgrounded():
                return
        for account in accounts:
            try:
                cm = ConnectionsManager.getInstance(account)
                if cm is not None:
                    cm.setAppPaused(bool(paused), False)
            except:
                pass

    def _acquire_proxy_transition_killswitch(self, reason=""):
        with self._proxy_transition_state_lock:
            lease = int(self._proxy_transition_next_lease)
            self._proxy_transition_next_lease += 1
            should_pause = not bool(self._proxy_transition_active_leases)
            self._proxy_transition_active_leases.add(lease)

        if should_pause:
            try:
                self._set_proxy_transition_network_paused(True)
            except:
                pass

        def _failsafe_release():
            try:
                time.sleep(float(PROXY_TRANSITION_KILLSWITCH_FAILSAFE_SEC))
            except:
                pass
            self._release_proxy_transition_killswitch(lease)

        try:
            threading.Thread(target=_failsafe_release, daemon=True).start()
        except:
            pass
        return lease

    def _release_proxy_transition_killswitch(self, lease, delay_sec=0.0):
        if lease is None:
            return

        def _release():
            try:
                wait_sec = float(delay_sec or 0.0)
            except:
                wait_sec = 0.0
            if wait_sec > 0:
                try:
                    time.sleep(wait_sec)
                except:
                    pass

            with self._proxy_transition_state_lock:
                if lease not in self._proxy_transition_active_leases:
                    return
                self._proxy_transition_active_leases.discard(lease)
                should_resume = not bool(self._proxy_transition_active_leases)

            if should_resume:
                try:
                    self._set_proxy_transition_network_paused(False)
                except:
                    pass

        if float(delay_sec or 0.0) > 0:
            try:
                threading.Thread(target=_release, daemon=True).start()
                return
            except:
                pass
        _release()

    def _release_all_proxy_transition_killswitches(self):
        should_resume = False
        with self._proxy_transition_state_lock:
            if self._proxy_transition_active_leases:
                should_resume = True
            self._proxy_transition_active_leases.clear()
            self._proxy_transition_param_leases = {}
        if should_resume:
            try:
                self._set_proxy_transition_network_paused(False)
            except:
                pass

    def _remember_proxy_transition_param_lease(self, param, lease):
        if lease is None:
            return
        with self._proxy_transition_state_lock:
            self._proxy_transition_param_leases[id(param)] = lease

    def _pop_proxy_transition_param_lease(self, param):
        with self._proxy_transition_state_lock:
            return self._proxy_transition_param_leases.pop(id(param), None)

    def _maybe_acquire_proxy_transition_killswitch_from_args(self, args):
        if not args or len(args) < 6:
            return None
        try:
            enabled = bool(args[0])
        except:
            enabled = False
        address = args[1] if len(args) > 1 else ""
        port = args[2] if len(args) > 2 else 0
        username = args[3] if len(args) > 3 else ""
        password = args[4] if len(args) > 4 else ""
        secret = args[5] if len(args) > 5 else ""
        if not self._should_arm_proxy_transition_killswitch(enabled, address, port, username, password, secret):
            return None
        return self._acquire_proxy_transition_killswitch("setProxySettings")

    def on_plugin_load(self):
        self._active = True
        try:
            self._webproxy.on_plugin_load()
        except Exception as error:
            try:
                self.log("WEB proxy unavailable: %s" % error)
            except Exception:
                pass
        self._repair_greenpass_settings_nulls()
        self._install_settings_theme_observer()
        try:
            _set_subscription_hwid_custom(self.get_setting("subscription_hwid_custom", ""))
        except:
            pass
        if self._core_restart_required():
            try:
                self._set_setting_value("use_proxy", False, reload_settings=False)
                _set_tg_proxy_enabled(False)
            except:
                pass
            run_on_ui_thread(lambda: BulletinHelper.show_info("Обновление готово — перезапустите приложение. Настройки сохранены"))
        elif self._core_restart_resumed:
            try:
                self._set_setting_value("use_proxy", bool(self._desired_use_proxy), reload_settings=False)
            except:
                pass
        self._install_plugin_proxy_api()

        try:
            self.add_menu_item(
                MenuItemData(
                    menu_type=MenuItemType.CHAT_ACTION_MENU,
                    item_id=self._chat_menu_item_id,
                    text=Z("Настройки GreenPass"),
                    icon="msg_settings",
                    priority=1000,
                    on_click=self._open_plugin_settings,
                )
            )
        except:
            pass

        try:
            self.add_menu_item(
                MenuItemData(
                    menu_type=MenuItemType.DRAWER_MENU,
                    item_id=self._drawer_menu_item_id,
                    text=Z("Настройки GreenPass"),
                    icon="msg_settings",
                    priority=1000,
                    on_click=self._open_plugin_settings,
                )
            )
        except:
            pass

        self._install_proxy_button_hooks()
        self._install_sync_hooks()
        self._install_proxy_killswitch_hook()
        if not self._ipv6_enabled():
            self._install_ipv6_hook()
        self._install_awg_activity_result_hook()
        self._install_browser_vless_hook()
        self._install_voip_relay_link_hook()
        self._install_text_vless_hook()
        self._install_cell_vless_hook()
        self._install_greenpass_file_open_hook()
        self._install_voip_relay_hook()
        try:
            self._apply_vpn_policy()
        except:
            pass
        self._refresh_current_dialogs_proxy_button()
        self._start_thread()
        self._sync_plugin_proxy_bridge()
        self._olcrtc_subscription_last_poll = time.time()
        if self._olcrtc_subscriptions_stale():
            self._refresh_olcrtc_subscriptions(silent=True)

        if (not self._is_proxy_policy_suspended()) and self._is_plugin_proxy_enabled() and self._is_vless_mode_selected():
            self._ensure_vless_core_then(self._vless_connect)
        elif (not self._is_proxy_policy_suspended()) and self._is_plugin_proxy_enabled() and self._is_tgws_mode_selected():
            self._tgws_connect()
        elif self._is_awg_mode_selected():
            if (not self._is_proxy_policy_suspended()) and self._is_plugin_proxy_enabled():
                self._ensure_awg_config_then_connect()
            elif not str(self._awg_conf_content or "").strip():
                self._download_free_awg_config()
        elif (not self._is_proxy_policy_suspended()) and self._is_plugin_proxy_enabled() and self._is_olcrtc_mode_selected():
            self._ensure_olcrtc_core_then(self._olcrtc_connect)

        try:
            mc_class = find_class("org.telegram.messenger.MessagesController")
            if mc_class:
                self.hook_all_methods(mc_class, "sortDialogs", HideProxySponsorDialogHook())

            for i in range(UserConfig.MAX_ACCOUNT_COUNT):
                run_on_ui_thread(lambda i=i: NotificationCenter.getInstance(i).postNotificationName(NotificationCenter.dialogsNeedReload))

            self._maybe_hide_proxy_sponsor_dialog()
        except Exception:
            pass

    # ---- IPv6 policy ----

    def _ipv6_enabled(self):
        try:
            return bool(self.get_setting("ipv6_enabled", True))
        except Exception:
            return True

    def _active_account_ids(self):
        ids = []
        for account in range(int(UserConfig.MAX_ACCOUNT_COUNT)):
            try:
                if UserConfig.getInstance(account).isClientActivated():
                    ids.append(account)
            except Exception:
                pass
        return ids

    def _should_force_ipv4(self):
        try:
            return (not self._ipv6_enabled()) or bool(getattr(self, "_awg_ipv4_only", False))
        except Exception:
            return False

    def _force_ipv4_strategy(self):
        for account in self._active_account_ids():
            try:
                ConnectionsManager.native_setIpStrategy(account, 0)
            except Exception:
                pass

    def _check_all_connections(self):
        def apply():
            for account in self._active_account_ids():
                try:
                    ConnectionsManager.getInstance(account).checkConnection()
                except Exception:
                    pass
        run_on_ui_thread(apply)

    def _on_ipv6_changed(self, enabled):
        try:
            self.set_setting("ipv6_enabled", bool(enabled), reload_settings=False)
        except Exception:
            pass
        if not enabled:
            self._install_ipv6_hook()
        self._check_all_connections()
        run_on_ui_thread(lambda: BulletinHelper.show_info("IPv6 включён" if enabled else "IPv6 выключен"))

    def _install_ipv6_hook(self):
        if bool(getattr(self, "_ipv6_hook_installed", False)):
            return
        try:
            cm_class = find_class("org.telegram.tgnet.ConnectionsManager")
        except Exception:
            cm_class = None
        if cm_class is None:
            return
        try:
            self.hook_all_methods(cm_class, "checkConnection", _Ipv6PolicyHook(self))
            self._ipv6_hook_installed = True
        except Exception:
            pass

    def _install_sync_hooks(self):
        if self._sync_hooks_installed:
            return
        try:
            NC = find_class("org.telegram.messenger.NotificationCenter")
            if NC:
                try:
                    self.hook_all_methods(NC, "postNotificationName", _ProxySettingsChangedNotifyHook(self))
                except:
                    pass
            self._sync_hooks_installed = True
        except:
            pass

    def _install_voip_relay_hook(self):
        if self._voip_relay_hook_installed and self._webrtc_relay_hook_installed:
            return
        try:
            if not self._voip_relay_hook_installed:
                instance_cls = find_class("org.telegram.messenger.voip.Instance")
                endpoint_cls = jclass("org.telegram.messenger.voip.Instance$Endpoint") if jclass is not None else find_class("org.telegram.messenger.voip.Instance$Endpoint")
                if instance_cls is not None and endpoint_cls is not None:
                    self.hook_all_methods(instance_cls, "makeInstance", _VoipEndpointRewriteHook(self, endpoint_cls))
                    self._voip_relay_hook_installed = True
            if not self._webrtc_relay_hook_installed:
                native_instance_cls = find_class("org.telegram.messenger.voip.NativeInstance")
                if native_instance_cls is not None:
                    self.hook_all_methods(native_instance_cls, "setJoinResponsePayload", _WebRtcJoinResponseRewriteHook(self))
                    self._webrtc_relay_hook_installed = True
        except:
            pass

    def _install_proxy_button_hooks(self):
        if self._proxy_button_hooks_installed:
            return
        try:
            DA = find_class("org.telegram.ui.DialogsActivity")
            if not DA:
                return
            try:
                self.hook_all_methods(DA, "updateProxyButton", _ForceDialogsProxyButtonHook(self))
            except:
                pass
            try:
                self.hook_all_methods(DA, "showSearch", _DialogsShowSearchForceProxyHook(self))
            except:
                pass
            try:
                self.hook_all_methods(DA, "showDoneItem", _DialogsShowDoneItemForceProxyHook(self))
            except:
                pass
            self._proxy_button_hooks_installed = True
        except:
            pass

    def _install_browser_vless_hook(self):
        if self._browser_vless_hook_installed:
            return
        try:
            browser_cls = Browser if Browser is not None else find_class("org.telegram.messenger.browser.Browser")
        except:
            browser_cls = None
        if browser_cls is None:
            return
        try:
            self.hook_all_methods(browser_cls, "openUrl", _BrowserOpenUrlHook(self))
            self._browser_vless_hook_installed = True
        except:
            pass

    def _install_voip_relay_link_hook(self):
        if self._voip_relay_link_hook_installed:
            return
        try:
            launch_cls = find_class("org.telegram.ui.LaunchActivity")
            if launch_cls is not None:
                self.hook_all_methods(launch_cls, "handleIntent", _VoipRelayLinkIntentHook(self))
                self._voip_relay_link_hook_installed = True
        except:
            pass

    def _install_text_vless_hook(self):
        if self._text_vless_hook_installed:
            return
        try:
            AU = find_class("org.telegram.messenger.AndroidUtilities")
        except:
            AU = None
        if AU is None:
            return

        installed = False
        try:
            self.hook_all_methods(AU, "addLinksSafe", _AddVlessTextLinksHook(self))
            installed = True
        except:
            pass
        try:
            self.hook_all_methods(AU, "addLinks", _AddVlessTextLinksHook(self))
            installed = True
        except:
            pass
        self._text_vless_hook_installed = bool(installed)

    def _install_cell_vless_hook(self):
        if self._cell_vless_hook_installed:
            return

        installed = False
        try:
            CMC = find_class("org.telegram.ui.Cells.ChatMessageCell")
        except:
            CMC = None
        if CMC is not None:
            try:
                self.hook_all_methods(CMC, "setMessageObject", _BindVlessTextLinksHook(self))
                installed = True
            except:
                pass

        try:
            CAC = find_class("org.telegram.ui.Cells.ChatActionCell")
        except:
            CAC = None
        if CAC is not None:
            try:
                self.hook_all_methods(CAC, "setMessageObject", _BindVlessTextLinksHook(self))
                installed = True
            except:
                pass

        self._cell_vless_hook_installed = bool(installed)

    def _install_greenpass_file_open_hook(self):
        if self._greenpass_file_hook_installed:
            return
        try:
            AU = find_class("org.telegram.messenger.AndroidUtilities")
        except:
            AU = None
        if AU is None:
            return
        try:
            self.hook_all_methods(AU, "openForView", _GreenPassOpenForViewHook(self))
            self._greenpass_file_hook_installed = True
        except Exception:
            pass

    def _parse_olcrtc_import_text(self, text):
        raw = str(text or "").strip()
        if not raw:
            return None, "Буфер обмена пуст"

        data = None
        try:
            data = json.loads(raw)
        except:
            data = None

        if data is None and "{" in raw and "}" in raw:
            try:
                data = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
            except:
                data = None

        if isinstance(data, dict):
            if isinstance(data.get("olcrtc"), dict):
                data = data.get("olcrtc")
            profile = _olcrtc_profile_from_json(data, default_client_id=_get_or_create_olcrtc_device_id())
            if profile:
                return profile, ""
            carrier = _olcrtc_carrier_alias(data.get("carrier", data.get("provider", ""))) or str(data.get("carrier", data.get("provider", "")) or "").strip()
            transport = _olcrtc_transport_alias(data.get("transport", "")) or str(data.get("transport", "") or "").strip()
            out = {
                "carrier": carrier,
                "transport": transport,
                "room_id": str(data.get("room_id", data.get("room", "")) or "").strip(),
                "client_id": str(data.get("client_id", data.get("device_id", "")) or "").strip() or _get_or_create_olcrtc_device_id(),
                "key_hex": str(data.get("key_hex", data.get("key", "")) or "").strip(),
            }
            return out, ""

        return _parse_olcrtc_uri_to_data(raw, default_client_id=_get_or_create_olcrtc_device_id())

    def _import_olcrtc_profiles(self, profiles, imported_link="", activate_first=False, connect_first=False):
        items = []
        try:
            items = [p for p in list(profiles or []) if isinstance(p, dict)]
        except:
            items = []
        first_profile = None
        imported = 0
        previous_active_id = str(self._olcrtc_active_profile_id or "")
        for data in reversed(items):
            profile = self._upsert_olcrtc_profile(data, imported_link=imported_link)
            if not profile:
                continue
            first_profile = profile
            imported += 1
        if imported <= 0:
            return 0
        if bool(activate_first) and first_profile:
            self._olcrtc_active_profile_id = str(first_profile.get("id", "") or "")
            self._set_olcrtc_legacy_settings_from_profile(first_profile)
            self._set_connection_mode(OLCRTC_KIND)
            self._save_config()
            if bool(connect_first):
                self._enable_plugin_proxy_flag()
                self._ensure_olcrtc_core_then(self._olcrtc_connect)
        elif previous_active_id:
            previous = self._find_olcrtc_profile(previous_active_id)
            if previous:
                self._olcrtc_active_profile_id = previous_active_id
                self._set_olcrtc_legacy_settings_from_profile(previous)
                self._save_config()
        self._refresh_settings_without_reopen(reload_stack=True, reload_main=bool(activate_first))
        return int(imported)

    def _try_import_olcrtc_subscription_text(self, url, text, activate_first=False):
        profiles = _extract_olcrtc_subscription_profiles(text, default_client_id=_get_or_create_olcrtc_device_id())
        if not profiles:
            return 0
        now = int(time.time())
        for profile in profiles:
            profile["subscription_url"] = str(url or "").strip()
            profile["subscription_updated_at"] = now
        return self._import_olcrtc_profiles(profiles, imported_link=str(url or "").strip(), activate_first=bool(activate_first), connect_first=bool(activate_first))



    def _refresh_olcrtc_subscriptions(self, silent=False):
        urls = self._olcrtc_subscription_urls()
        if not urls or bool(getattr(self, "_olcrtc_subscription_refresh_in_progress", False)):
            return False
        self._olcrtc_subscription_refresh_in_progress = True

        def _worker():
            refreshed = {}
            for url in urls:
                text = _fetch_olcrtc_subscription_text(url, timeout_sec=15.0)
                profiles = _extract_olcrtc_subscription_profiles(text, default_client_id=_get_or_create_olcrtc_device_id()) if text else []
                if profiles:
                    refreshed[url] = profiles

            def _finish():
                self._olcrtc_subscription_refresh_in_progress = False
                if not refreshed:
                    if not silent:
                        BulletinHelper.show_error("Не удалось обновить olcRTC подписки")
                    return
                profiles = self._sanitize_olcrtc_profiles(self._olcrtc_profiles)
                now = int(time.time())
                for url, items in refreshed.items():
                    profiles = [p for p in profiles if str(p.get("subscription_url", "") or "") != url]
                    for item in items:
                        item["subscription_url"] = url
                        item["subscription_updated_at"] = now
                        profile = self._normalize_olcrtc_profile(item)
                        if profile:
                            profiles.append(profile)
                self._olcrtc_profiles = self._sanitize_olcrtc_profiles(profiles)
                active = self._find_olcrtc_profile(self._olcrtc_active_profile_id)
                if not active and self._olcrtc_profiles:
                    active = self._olcrtc_profiles[0]
                    self._olcrtc_active_profile_id = str(active.get("id", "") or "")
                if active:
                    self._set_olcrtc_legacy_settings_from_profile(active)
                self._save_config()
                self._refresh_settings_without_reopen(reload_stack=True, reload_main=True)
                if not silent:
                    BulletinHelper.show_success("olcRTC подписки обновлены")

            run_on_ui_thread(_finish)

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _apply_olcrtc_import_data(self, data, connect=True, imported_link=""):
        if not isinstance(data, dict):
            BulletinHelper.show_error("Неверный olcRTC конфиг")
            return False
        carrier = str(data.get("carrier", "") or "").strip().lower() or self._get_olcrtc_carrier()
        transport = str(data.get("transport", "") or "").strip().lower() or self._get_olcrtc_transport()
        room_id = str(data.get("room_id", "") or "").strip()
        client_id = str(data.get("client_id", "") or "").strip() or _get_or_create_olcrtc_device_id()
        key_hex = str(data.get("key_hex", "") or "").strip()

        self._set_setting_value("olcrtc_carrier", self._olcrtc_index_for_item(carrier, OLCRTC_CARRIER_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_transport", self._olcrtc_index_for_item(transport, OLCRTC_TRANSPORT_ITEMS, 0), reload_settings=False)
        self._set_setting_value("olcrtc_room_id", room_id, reload_settings=False)
        self._set_setting_value("olcrtc_client_id", client_id, reload_settings=False)
        self._set_setting_value("olcrtc_key_hex", key_hex, reload_settings=False)
        if "vp8_fps" in data:
            self._set_setting_value("olcrtc_vp8_fps", str(data.get("vp8_fps", 60) or 60), reload_settings=False)
        if "vp8_batch_size" in data:
            self._set_setting_value("olcrtc_vp8_batch_size", str(data.get("vp8_batch_size", 64) or 64), reload_settings=False)
        profile = self._upsert_olcrtc_profile({
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "client_id": client_id,
            "key_hex": key_hex,
            "name": str(data.get("name", "") or "").strip(),
            "vp8_fps": data.get("vp8_fps", 60),
            "vp8_batch_size": data.get("vp8_batch_size", 64),
        }, imported_link=imported_link)
        if not profile:
            BulletinHelper.show_error("Неверный olcRTC конфиг")
            self._refresh_settings_without_reopen()
            return False
        self._set_connection_mode(OLCRTC_KIND)
        if connect:
            if not self._is_olcrtc_config_ready():
                BulletinHelper.show_error(self._olcrtc_config_error())
                self._refresh_settings_without_reopen()
                return False
            try:
                self._vless_disconnect_with_reason("import_olcrtc_uri", silent=True)
            except:
                pass
            try:
                self._tgws_disconnect_with_reason("import_olcrtc_uri", silent=True)
            except:
                pass
            try:
                self._awg_disconnect_with_reason("import_olcrtc_uri", silent=True)
            except:
                pass
            self._enable_plugin_proxy_flag()
            self._olcrtc_feedback_requested = True
            self._ensure_olcrtc_core_then(self._olcrtc_connect)
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        room_short = room_id[:32] if room_id else "конфиг"
        BulletinHelper.show_success("olcRTC: " + room_short)
        return True

    def _import_olcrtc_from_clipboard(self):
        blob = self._get_clipboard_text()
        raw = str(blob or "").strip()
        if raw.lower().startswith(("http://", "https://")):
            def _worker():
                text = _fetch_olcrtc_subscription_text(raw, timeout_sec=15.0)
                def _finish():
                    count = self._try_import_olcrtc_subscription_text(
                        raw,
                        text,
                        activate_first=not bool(self._olcrtc_profiles),
                    ) if text else 0
                    if count:
                        BulletinHelper.show_success("olcRTC: импортировано %d" % int(count))
                    else:
                        BulletinHelper.show_error("В подписке нет olcRTC конфигов")
                run_on_ui_thread(_finish)
            threading.Thread(target=_worker, daemon=True).start()
            return True
        data, err = self._parse_olcrtc_import_text(blob)
        if err:
            BulletinHelper.show_error(err)
            return False
        return self._apply_olcrtc_import_data(data, connect=True, imported_link=str(blob or "").strip())




    def _handle_tgws_link(self, uri="tg://ws", confirm=False):
        if bool(confirm):
            return self._confirm_tgws_link(uri)
        try:
            self._switch_to_tgws_mode()
            BulletinHelper.show_success("TG WS включен")
            return True
        except Exception as exc:
            BulletinHelper.show_error("TG WS: %s" % str(exc))
            return False

    def _handle_import_uri(self, uri, confirm=False):
        text = str(uri or "").strip()
        low = text.lower()
        if low.startswith(("wdtt://", "qwdtt://", "qwdtt:config?")):
            profile = _parse_qwdtt_uri(text)
            if not profile:
                BulletinHelper.show_error("Неверная qWDTT ссылка")
                return False
            if bool(confirm):
                return self._confirm_qwdtt_link(profile, text)
            saved = self._save_qwdtt_profile(profile, activate=True)
            if not saved:
                return False
            self._switch_to_vless_mode()
            return True
        if low.startswith("olcrtc://"):
            data, err = self._parse_olcrtc_import_text(text)
            if err:
                BulletinHelper.show_error(err)
                return False
            if bool(confirm):
                return self._confirm_olcrtc_link(data, text)
            return self._apply_olcrtc_import_data(data, connect=True, imported_link=text)
        if low.startswith("tg://relay?"):
            return self._apply_tgws_voip_relay_link(text)
        if low.startswith("tg://ws"):
            return self._handle_tgws_link(text, confirm=confirm)
        return self._show_vless_import_sheet(text)

    def _show_vless_import_sheet(self, uri):
        details = _parse_proxy_uri_details(uri)
        if not details:
            try:
                match = re.match(r"^([a-z][a-z0-9+.-]*)://", str(uri or "").strip(), re.IGNORECASE)
                scheme = str(match.group(1) or "").lower() if match else ""
            except:
                scheme = ""
            if scheme and scheme not in PROXY_PROTOCOL_REGISTRY:
                BulletinHelper.show_error("Протокол %s не поддерживается плагином" % scheme)
            else:
                BulletinHelper.show_error("Неверная ссылка")
            return

        fragment = get_last_fragment()
        activity = None
        try:
            if fragment is not None:
                activity = fragment.getParentActivity()
        except:
            activity = None
        if activity is None:
            BulletinHelper.show_error("Не удалось открыть импорт ссылки")
            return

        try:
            protocol_label = _proxy_protocol_label(details)
            has_core = self._has_libvless_addon()
            initial_status = "Проверяю доступность…" if has_core else "Для проверки нужно ядро прокси"
            initial_kind = "checking" if has_core else "error"
            dialog, update_status = self._open_proxy_import_preview(
                activity,
                uri,
                details,
                initial_status,
                initial_kind,
            )
            if dialog is None or update_status is None:
                fallback = AlertDialogBuilder(activity)
                fallback.set_title(str(details.get("name", protocol_label) or protocol_label)[:80])
                fallback.set_message("%s:%s\n%s" % (
                    str(details.get("server", "") or ""),
                    str(details.get("port", "") or ""),
                    initial_status,
                ))

                def _fallback_connect(dlg, which):
                    try:
                        dlg.dismiss()
                    except:
                        pass
                    self._activate_vless_uri(uri, enable_plugin=True)

                fallback.set_positive_button("Подключить", _fallback_connect)
                fallback.set_negative_button("Отмена", lambda dlg, which: dlg.dismiss())
                fallback.show()
                return
            if not has_core:
                return

            def _check_status():
                validation_error = self._validate_proxy_uri_for_import(uri)
                if validation_error:
                    run_on_ui_thread(lambda validation_error=validation_error: update_status(validation_error, "error"))
                    return
                try:
                    ping = self._probe_proxy_latency({
                        "server": str(details.get("server", "") or ""),
                        "port": int(details.get("port", 0) or 0),
                    }, timeout_sec=float(VLESS_REMOTE_CHECK_TIMEOUT_SEC))
                except:
                    ping = None

                if ping is None or int(ping) <= 0:
                    status_text = "Сервер не ответил на проверку"
                    status_kind = "error"
                else:
                    status_text = f"Сервер доступен • {int(ping)} ms"
                    status_kind = "ok"
                run_on_ui_thread(lambda: update_status(status_text, status_kind))

            threading.Thread(target=_check_status, daemon=True).start()
        except Exception as e:
            BulletinHelper.show_error(f"Ошибка импорта: {e}")





    def _go_core_switch_blocked(self, target_kind):
        """Unified libgreenpass.so supports in-process engine switching."""
        if not self._core_restart_required():
            return False
        BulletinHelper.show_info("Ядро обновлено — перезапустите приложение")
        return True





    def _install_awg_activity_result_hook(self):
        if self._awg_activity_hook_installed:
            return
        if Integer is None:
            return
        try:
            launch_cls = find_class("org.telegram.ui.LaunchActivity")
            intent_cls = find_class("android.content.Intent")
            method = launch_cls.getClass().getDeclaredMethod("onActivityResult", Integer.TYPE, Integer.TYPE, intent_cls)
            self.hook_method(method, _AwgActivityResultHook(self))
            self._awg_activity_hook_installed = True
        except Exception:
            pass

    def _install_proxy_killswitch_hook(self):
        if self._proxy_killswitch_hook_installed:
            return
        try:
            cm_class = find_class("org.telegram.tgnet.ConnectionsManager")
        except:
            cm_class = None
        if cm_class is None:
            return
        try:
            self.hook_all_methods(cm_class, "setProxySettings", _ProxyTransitionKillSwitchHook(self))
            self._proxy_killswitch_hook_installed = True
        except:
            pass

    def _find_vless_subscription(self, sub_url):
        target = str(sub_url or "").strip()
        if not target:
            return None
        try:
            for sub in list(self._vless_data.get("subs", []) or []):
                if not isinstance(sub, dict):
                    continue
                if str(sub.get("url", "") or "").strip() == target:
                    return sub
        except:
            pass
        return None

    def _update_vless_subscription(self, url, silent=False):
        target = str(url or "").strip()
        if not target:
            return False
        sub = self._find_vless_subscription(target)
        if sub is None:
            if not silent:
                BulletinHelper.show_error("Подписка не найдена")
            return False
        if not silent:
            BulletinHelper.show_info("Обновляю подписку...")

        def _worker():
            nodes = _fetch_vless_nodes(target)
            if not nodes:
                if not silent:
                    run_on_ui_thread(lambda: BulletinHelper.show_error("Не удалось обновить подписку"))
                return
            try:
                sub["nodes"] = nodes
            except:
                return
            self._repair_active_vless_subscription_uri()
            self._vless_save_data()
            if self._is_plugin_proxy_enabled() and self._get_connection_mode() == VLESS_KIND and self._get_active_vless_uri():
                self._ensure_vless_core_then(self._vless_connect)
            run_on_ui_thread(self._refresh_settings_without_reopen)
            if not silent:
                run_on_ui_thread(lambda: BulletinHelper.show_success(f"Узлов обновлено: {len(nodes)}"))

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _delete_vless_subscription(self, url):
        target = str(url or "").strip()
        if not target:
            return False

        removed = False
        active_uri = self._get_active_vless_uri()
        removed_active = False
        subs = []
        for sub in list(self._vless_data.get("subs", []) or []):
            if not isinstance(sub, dict):
                continue
            sub_url = str(sub.get("url", "") or "").strip()
            if sub_url != target:
                subs.append(sub)
                continue
            removed = True
            for node in list(sub.get("nodes", []) or []):
                try:
                    if str(node.get("uri", "") or "") == active_uri:
                        removed_active = True
                        break
                except:
                    continue

        if not removed:
            return False

        self._vless_data["subs"] = subs
        if active_uri == VLESS_AUTO_SUBSCRIPTIONS_URI:
            removed_active = True
            if self._find_vless_node(active_uri) is None:
                self._vless_data["active_uri"] = self._first_vless_uri()
        if removed_active:
            if active_uri != VLESS_AUTO_SUBSCRIPTIONS_URI:
                self._vless_data["active_uri"] = self._first_vless_uri()
        self._vless_save_data()

        if removed_active and self._get_connection_mode() == VLESS_KIND:
            next_uri = self._get_active_vless_uri()
            if self._is_plugin_proxy_enabled() and next_uri:
                self._ensure_vless_core_then(self._vless_connect)
            else:
                self._vless_disconnect_with_reason("remove_vless_subscription", silent=True)

        self._refresh_settings_without_reopen()
        BulletinHelper.show_success("Подписка удалена")
        return True







    def _refresh_current_dialogs_proxy_button(self):
        try:
            frag = get_last_fragment()
            if frag is None:
                return
            try:
                n = str(frag.getClass().getName() or "")
            except:
                n = ""
            if n == "org.telegram.ui.DialogsActivity":
                if self._is_plugin_proxy_enabled():
                    _force_show_dialogs_proxy_button(frag)
                else:
                    try:
                        if hasattr(frag, "updateProxyButton"):
                            frag.updateProxyButton(False, False)
                    except:
                        try:
                            if hasattr(frag, "updateProxyButton"):
                                frag.updateProxyButton()
                        except:
                            pass
        except:
            pass

    def _on_use_proxy_changed(self, enabled):
        val = bool(enabled)
        self._desired_use_proxy = bool(val)
        self._save_config()
        try:
            self._set_setting_value("use_proxy", val, reload_settings=True)
        except:
            pass

        if val:
            try:
                self._apply_vpn_policy()
            except:
                pass
            if self._is_proxy_policy_suspended():
                try:
                    self._sync_plugin_proxy_bridge()
                except:
                    pass
                self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
                self._refresh_current_dialogs_proxy_button()
                return
            if self._is_vless_mode_selected():
                self._reset_vless_retry()
                self._ensure_vless_core_then(self._vless_connect)
            elif self._is_tgws_mode_selected():
                self._tgws_connect()
            elif self._is_awg_mode_selected():
                self._ensure_awg_config_then_connect()
            elif self._is_olcrtc_mode_selected():
                self._ensure_olcrtc_core_then(self._olcrtc_connect)
        else:
            self._proxy_suspended_by_vpn = False
            self._proxy_suspended_by_wifi = False
            _set_tg_proxy_enabled(False)
            try:
                self._vless_disconnect_with_reason("use_proxy_disabled", silent=True)
            except:
                pass
            try:
                self._tgws_disconnect_with_reason("use_proxy_disabled", silent=True)
            except:
                pass
            try:
                self._awg_disconnect_with_reason("use_proxy_disabled", silent=True)
            except:
                pass
            try:
                self._olcrtc_disconnect_with_reason("use_proxy_disabled", silent=True)
            except:
                pass
            try:
                prefs = MessagesController.getGlobalMainSettings()
                ed = prefs.edit()
                ed.putBoolean("proxy_enabled_calls", False)
                ed.commit()
            except:
                pass

        try:
            self._sync_plugin_proxy_bridge()
        except:
            pass
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)
        self._refresh_current_dialogs_proxy_button()

    def on_plugin_unload(self):
        try:
            self._webproxy.on_plugin_unload()
        except Exception:
            pass
        self._active = False
        self._remove_settings_theme_observer()
        try:
            self._stop_awg_health_loop()
        except:
            pass
        try:
            self._worker_stop.set()
        except:
            pass
        # Elyx unloads on the UI thread and removes hooks/menu items itself.
        # Native StopCore and thread joins here can block or crash plugin deletion.
        try:
            self._vless_generation = int(self._vless_generation or 0) + 1
            self._tgws_generation = int(self._tgws_generation or 0) + 1
            self._next_olcrtc_generation()
        except:
            pass
        try:
            self._release_all_proxy_transition_killswitches()
        except:
            pass
        try:
            self._remove_python_http_proxy_patch()
        except:
            pass
        try:
            self._deactivate_frida_plugin_proxy_hook()
        except:
            pass
        try:
            owner, port = self._local_socks_owner_snapshot()
            if port > 0:
                self._clear_local_socks_proxy_if_port(port, owner=owner)
        except:
            pass
        try:
            self._vless_running = False
            self._tgws_running = False
            self._tgws_ready = False
            self._awg_running = False
            self._awg_connecting = False
            self._olcrtc_running = False
        except:
            pass
        try:
            module = sys.modules.get(GREENPASS_PROXY_API_MODULE)
            if getattr(module, "_plugin", None) is self:
                module._plugin = None
        except:
            pass

    def on_app_event(self, event):
        if event == AppEvent.PAUSE or event == AppEvent.STOP:
            if not bool(getattr(self, "_vless_backgrounded", False)):
                self._vless_backgrounded_at = time.time()
            self._vless_backgrounded = True
            self._tgws_backgrounded = True
            self._olcrtc_backgrounded = True
            self._olcrtc_feedback_requested = False
            if self._is_tgws_mode_selected() and self._is_plugin_proxy_enabled():
                self._tgws_unapply_local_proxy_for_background()
            return
        if event == AppEvent.RESUME or event == AppEvent.START:
            self._install_proxy_button_hooks()
            self._install_sync_hooks()
            self._install_proxy_killswitch_hook()
            self._install_awg_activity_result_hook()
            self._install_browser_vless_hook()
            self._install_text_vless_hook()
            self._install_cell_vless_hook()
            self._install_greenpass_file_open_hook()
            self._install_voip_relay_hook()
            self._refresh_current_dialogs_proxy_button()

            was_vless_backgrounded = bool(getattr(self, "_vless_backgrounded", False))
            backgrounded_at = float(getattr(self, "_vless_backgrounded_at", 0.0) or time.time())
            vless_backgrounded_for = max(0.0, time.time() - backgrounded_at) if was_vless_backgrounded else 0.0
            was_backgrounded = bool(getattr(self, "_tgws_backgrounded", False))
            self._vless_backgrounded = False
            self._vless_backgrounded_at = 0.0
            self._tgws_backgrounded = False
            self._olcrtc_backgrounded = False
            def _resume_bg():
                try:
                    self._apply_vpn_policy()
                except:
                    pass
                if self._is_proxy_policy_suspended():
                    self._olcrtc_resume_checking = False
                    self._olcrtc_health_stale = False
                    return
                if not self._is_plugin_proxy_enabled():
                    self._olcrtc_resume_checking = False
                    self._olcrtc_health_stale = False
                    return
                if self._is_vless_mode_selected():
                    if was_vless_backgrounded:
                        self._resume_vless_after_background(vless_backgrounded_for)
                    elif not self._is_vless_connection_ready(self._vless_port, check_tunnel=False):
                        self._auto_reconnect_vless()
                elif self._is_tgws_mode_selected():
                    old_ready = bool(getattr(self, "_tgws_ready", False))
                    ready_now = bool(self._tgws_ensure_local_proxy())
                    if was_backgrounded or old_ready != ready_now:
                        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                    elif not ready_now and not bool(getattr(self, "_tgws_connecting", False)):
                        self._tgws_heal_if_due()
                        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                elif self._should_run_awg() and not self._restore_running_awg_proxy(force_reapply=True):
                    self._ensure_awg_core_then(self._awg_connect)
                elif self._should_run_olcrtc():
                    port = int(self._olcrtc_port or OLCRTC_LOCAL_PORT)
                    local_alive = self._olcrtc_local_ready(port, check_tunnel=False, reason="resume")
                    core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                    if local_alive and self._olcrtc_state_needs_restart(core_state):
                        local_alive = False
                    if local_alive:
                        self._olcrtc_dead_checks = 0
                        self._olcrtc_port = port
                        self._olcrtc_running = True
                        self._olcrtc_connecting = False
                        self._olcrtc_health_stale = False
                        self._olcrtc_resume_checking = False
                        run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                    else:
                        self._olcrtc_running = False
                        self._olcrtc_resume_checking = False
                        self._olcrtc_health_stale = False
                        self._set_olcrtc_last_log("resume health check failed", event="resume_health_failed", port=port)
                        core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                        if core_state not in ("starting", "handshake", "stopping") and not bool(getattr(self, "_olcrtc_connecting", False)):
                            self._ensure_olcrtc_core_then(self._olcrtc_connect)
            try:
                threading.Thread(target=_resume_bg, daemon=True).start()
            except:
                pass

            self._maybe_hide_proxy_sponsor_dialog()

    def _maybe_hide_proxy_sponsor_dialog(self):
        try:
            now = int(time.time())
            if now - int(self._last_proxy_sponsor_hide or 0) < 30:
                return

            prefs = MessagesController.getGlobalMainSettings()
            promo_id = int(prefs.getLong("proxy_dialog", 0))
            promo_type = int(prefs.getInt("promo_dialog_type", -1))
            proxy_type = int(getattr(MessagesController, "PROMO_TYPE_PROXY", 0))
            if promo_id == 0 or promo_type != proxy_type:
                return

            self._last_proxy_sponsor_hide = now

            def _hide_all():
                for i in range(UserConfig.MAX_ACCOUNT_COUNT):
                    try:
                        mc = MessagesController.getInstance(i)
                        if not mc:
                            continue

                        try:
                            from hook_utils import get_private_field, set_private_field
                            promo_dialog = None
                            try:
                                promo_dialog = get_private_field(mc, "promoDialog")
                            except:
                                promo_dialog = None
                            if promo_dialog is None:
                                try:
                                    promo_dialog = mc.dialogs_dict.get(promo_id)
                                except:
                                    promo_dialog = None
                                if promo_dialog is not None:
                                    try:
                                        set_private_field(mc, "promoDialog", promo_dialog)
                                    except:
                                        pass
                        except:
                            pass

                        try:
                            if hasattr(mc, "hidePromoDialog"):
                                mc.hidePromoDialog()
                        except:
                            pass
                    except:
                        pass

            run_on_ui_thread(_hide_all)
        except:
            pass

    def _start_thread(self):
        if self._thread and self._thread.is_alive():
            return
        try:
            self._worker_stop.clear()
        except:
            pass
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self):
        self._worker_stop.wait(2)
        if self._worker_stop.is_set() or (not self._active):
            return
        try:
            self._run_autoupdate_check(force=False)
        except:
            pass
        try:
            self._update_outdated_core_in_background()
        except:
            pass
        try:
            self._apply_vpn_policy()
        except:
            pass
        if self._is_plugin_proxy_enabled() and not self._is_proxy_policy_suspended():
            try:
                self._maybe_run_vless_auto_ping()
            except:
                pass
            if self._is_vless_mode_selected():
                if not self._vless_running or (self._vless_port and not _check_vless_port(self._vless_port)):
                    self._auto_reconnect_vless()
            elif self._is_tgws_mode_selected():
                self._tgws_ensure_local_proxy()
            elif self._should_run_awg():
                if not self._restore_running_awg_proxy():
                    self._ensure_awg_core_then(self._awg_connect)
            elif self._should_run_olcrtc():
                if (not bool(getattr(self, "_olcrtc_backgrounded", False))) and (not bool(getattr(self, "_olcrtc_connecting", False))):
                    port = int(self._olcrtc_port or OLCRTC_LOCAL_PORT)
                    local_alive = self._olcrtc_local_ready(port, check_tunnel=False, reason="worker_start")
                    core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                    if local_alive and self._olcrtc_state_needs_restart(core_state):
                        local_alive = False
                    if local_alive:
                        self._olcrtc_dead_checks = 0
                        self._olcrtc_port = port
                        self._olcrtc_running = True
                        self._olcrtc_health_stale = False
                        self._olcrtc_resume_checking = False
                    else:
                        self._olcrtc_running = False
                        self._ensure_olcrtc_core_then(self._olcrtc_connect)

        while self._active:
            try:
                self._worker_stop.wait(30)
                if self._worker_stop.is_set() or (not self._active):
                    break

                try:
                    self._apply_vpn_policy()
                except:
                    pass
                now = time.time()
                if now - float(getattr(self, "_olcrtc_subscription_last_poll", 0.0) or 0.0) >= 3600.0:
                    self._olcrtc_subscription_last_poll = now
                    if self._olcrtc_subscriptions_stale():
                        self._refresh_olcrtc_subscriptions(silent=True)
                if self._is_proxy_policy_suspended():
                    continue

                try:
                    self._maybe_run_vless_auto_ping(now=now)
                except:
                    pass

                try:
                    self._run_autoupdate_check(force=False)
                except:
                    pass

                if not self._is_plugin_proxy_enabled():
                    continue

                if self._is_vless_mode_selected():
                    port = int(self._vless_port or 0)
                    if not self._vless_running or port <= 0 or not _check_vless_port(port):
                        self._auto_reconnect_vless()
                    elif not self._is_local_vless_proxy_applied(port):
                        self._restore_running_vless_proxy()
                    continue

                if self._is_tgws_mode_selected():
                    backgrounded = bool(getattr(self, "_tgws_backgrounded", False))
                    if not backgrounded:
                        old_ready = bool(getattr(self, "_tgws_ready", False))
                        ready_now = self._tgws_ensure_local_proxy()
                        if old_ready != bool(ready_now):
                            run_on_ui_thread(lambda: self._refresh_settings_without_reopen(reload_main=True, reload_stack=True))
                        if (not ready_now) and (not backgrounded) and (not bool(getattr(self, "_tgws_connecting", False))):
                            self._tgws_heal_if_due()
                    continue

                if self._should_run_awg():
                    if not self._restore_running_awg_proxy():
                        self._ensure_awg_core_then(self._awg_connect)
                    continue

                if self._should_run_olcrtc():
                    if bool(getattr(self, "_olcrtc_backgrounded", False)):
                        continue
                    port = int(self._olcrtc_port or OLCRTC_LOCAL_PORT)
                    local_alive = self._olcrtc_local_ready(port, check_tunnel=False, reason="worker")
                    core_state = str(self._olcrtc_core_status_data().get("state", "") or "").lower()
                    if local_alive and self._olcrtc_state_needs_restart(core_state):
                        local_alive = False
                    if local_alive:
                        self._olcrtc_dead_checks = 0
                        self._olcrtc_port = port
                        self._olcrtc_running = True
                        self._olcrtc_connecting = False
                        self._olcrtc_health_stale = False
                        self._olcrtc_resume_checking = False
                    elif bool(getattr(self, "_olcrtc_connecting", False)) or core_state in ("starting", "handshake", "stopping"):
                        self._olcrtc_dead_checks = 0
                    else:
                        self._olcrtc_running = False
                        self._olcrtc_resume_checking = False
                        self._olcrtc_dead_checks = int(getattr(self, "_olcrtc_dead_checks", 0) or 0) + 1
                        if self._olcrtc_dead_checks >= 2:
                            self._olcrtc_dead_checks = 0
                            self._ensure_olcrtc_core_then(self._olcrtc_connect)
                    continue

            except Exception:
                self._worker_stop.wait(60)
                if self._worker_stop.is_set() or (not self._active):
                    break







    def _restart_tgws_from_settings(self):
        self._set_connection_mode(TGWS_KIND)
        if self._is_plugin_proxy_enabled():
            try:
                self._tgws_disconnect_with_reason("restart", silent=True)
            except:
                pass
            self._tgws_connect()
        else:
            self._on_use_proxy_changed(True)
        self._refresh_settings_without_reopen(reload_main=True, reload_stack=True)

    def _on_olcrtc_carrier_changed(self, idx):
        try:
            i = int(idx)
        except:
            i = 0
        if i < 0 or i >= len(OLCRTC_CARRIER_ITEMS):
            i = 0
        self._set_setting_value("olcrtc_carrier", i, reload_settings=False)
        supported = _olcrtc_supported_transports(OLCRTC_CARRIER_ITEMS[i])
        transport = self._olcrtc_item_by_setting("olcrtc_transport", OLCRTC_TRANSPORT_ITEMS, 0)
        if transport not in supported:
            transport = supported[0]
            self._set_setting_value("olcrtc_transport", self._olcrtc_index_for_item(transport, OLCRTC_TRANSPORT_ITEMS, 0), reload_settings=False)
        self._refresh_settings_without_reopen(reload_stack=True)
        if self._is_plugin_proxy_enabled() and self._is_olcrtc_mode_selected() and (bool(self._olcrtc_running) or bool(self._olcrtc_connecting)):
            self._restart_olcrtc_from_settings()

    def _on_olcrtc_transport_changed(self, idx):
        try:
            i = int(idx)
        except:
            i = 0
        choices = self._olcrtc_transport_choices()
        if i < 0 or i >= len(choices):
            i = 0
        transport = choices[i]
        self._set_setting_value("olcrtc_transport", self._olcrtc_index_for_item(transport, OLCRTC_TRANSPORT_ITEMS, 0), reload_settings=False)
        self._refresh_settings_without_reopen(reload_stack=True)
        if self._is_plugin_proxy_enabled() and self._is_olcrtc_mode_selected() and (bool(self._olcrtc_running) or bool(self._olcrtc_connecting)):
            self._restart_olcrtc_from_settings()


    def _builtin_vless_sub_sources(self):
        items = []
        for provider_idx in sorted(VLESS_PROVIDER_SUBS.keys()):
            try:
                urls = list(VLESS_PROVIDER_SUBS.get(provider_idx, []) or [])
            except:
                urls = []
            total_urls = len(urls)
            for url in urls:
                value = str(url or "").strip()
                if not value:
                    continue
                items.append({
                    "name": self._provider_vless_sub_name(provider_idx, value, total_urls=total_urls) or "Подписка",
                    "url": value,
                })
        return items

