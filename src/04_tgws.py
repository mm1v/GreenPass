# --- bundled from greenpass.tgws.py ---

def _tgws_ip_range(start, end, dc, is_media=False):
    return (
        struct.unpack("!I", socket.inet_aton(start))[0],
        struct.unpack("!I", socket.inet_aton(end))[0],
        int(dc),
        bool(is_media),
    )


_TGWS_IP_RANGE_TO_DC = [
    _tgws_ip_range("91.105.192.0", "91.105.193.255", 203, False),
    _tgws_ip_range("91.108.4.0", "91.108.23.255", 5, True),
    _tgws_ip_range("91.108.56.0", "91.108.59.255", 5, True),
    _tgws_ip_range("185.76.151.0", "185.76.151.255", 5, True),
    _tgws_ip_range("149.154.160.0", "149.154.163.255", 2, True),
    _tgws_ip_range("149.154.164.0", "149.154.166.255", 4, True),
    _tgws_ip_range("149.154.167.0", "149.154.167.255", 2, False),
    _tgws_ip_range("149.154.171.0", "149.154.171.255", 5, False),
    _tgws_ip_range("149.154.175.0", "149.154.175.99", 1, False),
    _tgws_ip_range("149.154.175.100", "149.154.175.199", 3, False),
]


def _tgws_dc_from_dst_ip(ip):
    try:
        ip_s = str(ip or "").strip()
    except:
        ip_s = ""
    if not ip_s:
        return None
    exact = _TGWS_IP_TO_DC.get(ip_s)
    if exact is not None:
        return int(exact[0]), bool(exact[1])
    try:
        raw = struct.unpack("!I", socket.inet_aton(ip_s))[0]
        for lo, hi, dc, is_media in _TGWS_IP_RANGE_TO_DC:
            if lo <= raw <= hi:
                return int(dc), bool(is_media)
    except:
        pass
    return None

_TGWS_PROTO_ABRIDGED_INT = 0xEFEFEFEF
_TGWS_PROTO_INTERMEDIATE_INT = 0xEEEEEEEE
_TGWS_PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD


def _tgws_unique_values(*values):
    out = []
    seen = set()
    for value in values:
        try:
            trimmed = str(value or "").strip()
        except:
            trimmed = ""
        if not trimmed or trimmed in seen:
            continue
        seen.add(trimmed)
        out.append(trimmed)
    return out


def _tgws_set_socket_options(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(TGWS_SOCKET_BUFFER_SIZE))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(TGWS_SOCKET_BUFFER_SIZE))
    except:
        pass


def _tgws_xor_mask(data, mask):
    if not mask:
        return data
    buf = bytearray(data)
    for idx in range(len(buf)):
        buf[idx] ^= mask[idx & 3]
    return bytes(buf)


def _tgws_build_frame(opcode, payload, mask=True):
    try:
        body = bytes(payload or b"")
    except:
        body = b""
    out = bytearray()
    out.append(0x80 | (int(opcode) & 0x0F))
    length = len(body)
    mask_bit = 0x80 if mask else 0x00
    if length < 126:
        out.append(mask_bit | length)
    elif length <= 0xFFFF:
        out.append(mask_bit | 126)
        out.extend(struct.pack(">H", length))
    else:
        out.append(mask_bit | 127)
        out.extend(struct.pack(">Q", length))
    if mask:
        mask_key = os.urandom(4)
        out.extend(mask_key)
        body = _tgws_xor_mask(body, mask_key)
    out.extend(body)
    return bytes(out)


def _tgws_read_exact(reader, size):
    buf = b""
    need = int(size or 0)
    while len(buf) < need:
        chunk = reader.read(need - len(buf))
        if not chunk:
            raise EOFError("unexpected eof")
        buf += chunk
    return buf


def _tgws_recv_exact(conn, size):
    data = b""
    need = int(size or 0)
    while len(data) < need:
        chunk = conn.recv(need - len(data))
        if not chunk:
            raise EOFError("unexpected eof")
        data += chunk
    return data


def _tgws_is_telegram_ip(ip):
    try:
        ip_s = str(ip or "")
    except Exception:
        ip_s = ""
    try:
        if ":" in ip_s:
            try:
                socket.inet_pton(socket.AF_INET6, ip_s)
                return True
            except Exception:
                pass
    except Exception:
        pass
    try:
        raw = struct.unpack("!I", socket.inet_aton(ip_s))[0]
        for lo, hi in _TGWS_TG_RANGES:
            if lo <= raw <= hi:
                return True
    except:
        pass
    return False


def _tgws_is_http_transport(data):
    try:
        raw = bytes(data or b"")
    except:
        raw = b""
    return raw[:5] == b"POST " or raw[:4] == b"GET " or raw[:5] == b"HEAD " or raw[:8] == b"OPTIONS "


def _tgws_keystream_java(key_bytes, iv_bytes, size):
    if JavaCipher is None or SecretKeySpec is None or IvParameterSpec is None:
        raise RuntimeError("Java crypto unavailable")
    cipher = JavaCipher.getInstance("AES/CTR/NoPadding")
    cipher.init(JavaCipher.ENCRYPT_MODE, SecretKeySpec(bytes(key_bytes), "AES"), IvParameterSpec(bytes(iv_bytes)))
    result = cipher.doFinal(b"\x00" * int(size))
    try:
        return bytes(result)
    except:
        return bytes(bytearray(result))


class _TgWsAesCtrStream:
    def __init__(self, key_bytes, iv_bytes):
        if JavaCipher is None or SecretKeySpec is None or IvParameterSpec is None:
            raise RuntimeError("Java crypto unavailable")
        self._cipher = JavaCipher.getInstance("AES/CTR/NoPadding")
        self._cipher.init(JavaCipher.ENCRYPT_MODE, SecretKeySpec(bytes(key_bytes), "AES"), IvParameterSpec(bytes(iv_bytes)))

    def xor(self, data):
        raw = bytes(data or b"")
        if not raw:
            return b""
        result = self._cipher.update(raw)
        try:
            return bytes(result)
        except:
            return bytes(bytearray(result))


def _tgws_proxy_secret_hex():
    try:
        value = re.sub(r"[^0-9a-fA-F]", "", str(TGWS_PROXY_SECRET_HEX or ""))
    except:
        value = ""
    if len(value) != 32:
        value = "00000000000000000000000000000000"
    return value.lower()


def _tgws_proxy_secret_for_telegram():
    return "dd" + _tgws_proxy_secret_hex()


def _tgws_random_relay_init():
    while True:
        raw = bytearray(os.urandom(64))
        if raw[0] == 0xEF:
            continue
        first4 = bytes(raw[:4])
        if first4 in (b"HEAD", b"POST", b"GET ", b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"):
            continue
        if raw[0] == 0x16 and raw[1] == 0x03 and raw[2] == 0x01 and raw[3] == 0x02:
            continue
        if raw[4] == 0 and raw[5] == 0 and raw[6] == 0 and raw[7] == 0:
            continue
        return bytes(raw)


def _tgws_raw_proxy_session(handshake):
    raw = bytes(handshake or b"")
    if len(raw) < 64:
        return None
    secret = bytes.fromhex(_tgws_proxy_secret_hex())
    clt_dec_key = hashlib.sha256(raw[8:40] + secret).digest()
    clt_dec = _TgWsAesCtrStream(clt_dec_key, raw[40:56])
    decrypted = clt_dec.xor(raw[:64])
    try:
        proto = struct.unpack("<I", decrypted[56:60])[0]
        dc_raw = struct.unpack("<h", decrypted[60:62])[0]
    except:
        return None
    if proto not in (_TGWS_PROTO_ABRIDGED_INT, _TGWS_PROTO_INTERMEDIATE_INT, _TGWS_PROTO_PADDED_INTERMEDIATE_INT):
        return None
    dc = abs(int(dc_raw))
    if dc <= 0 or dc > 1000:
        return None
    is_media = bool(dc_raw < 0)

    clt_enc_prekey_iv = bytes(raw[8 + 47 - i] for i in range(48))
    clt_enc_key = hashlib.sha256(clt_enc_prekey_iv[:32] + secret).digest()
    clt_enc = _TgWsAesCtrStream(clt_enc_key, clt_enc_prekey_iv[32:])

    relay_init = bytearray(_tgws_random_relay_init())
    tg_dec_prekey_iv = bytes(relay_init[8 + 47 - i] for i in range(48))
    tg_enc = _TgWsAesCtrStream(relay_init[8:40], relay_init[40:56])
    tg_dec = _TgWsAesCtrStream(tg_dec_prekey_iv[:32], tg_dec_prekey_iv[32:])

    dc_idx = -dc if is_media else dc
    tail_plain = struct.pack("<Ih", int(proto), int(dc_idx)) + os.urandom(2)
    encrypted_full = tg_enc.xor(bytes(relay_init))
    for i in range(8):
        relay_init[56 + i] = tail_plain[i] ^ (encrypted_full[56 + i] ^ relay_init[56 + i])
    return dc, is_media, int(proto), bytes(relay_init), (clt_dec, clt_enc, tg_enc, tg_dec)


def _tgws_init_info(data):
    try:
        raw = bytes(data or b"")
        if len(raw) < 64:
            return None, False, None
        key = raw[8:40]
        iv = raw[40:56]
        keystream = _tgws_keystream_java(key, iv, 64)
        plain = bytes(a ^ b for a, b in zip(raw[56:64], keystream[56:64]))
        proto = struct.unpack("<I", plain[0:4])[0]
        dc_raw = struct.unpack("<h", plain[4:6])[0]
        if proto in (_TGWS_PROTO_ABRIDGED_INT, _TGWS_PROTO_INTERMEDIATE_INT, _TGWS_PROTO_PADDED_INTERMEDIATE_INT):
            dc = abs(int(dc_raw))
            if 1 <= dc <= 1000:
                return dc, bool(dc_raw < 0), int(proto)
    except:
        pass
    return None, False, None


def _tgws_resolve_ipv4(hostname):
    try:
        hn = str(hostname or "").strip()
        if not hn:
            return None
        try:
            if ":" in hn:
                return None
            socket.inet_aton(hn)
            return hn
        except Exception:
            pass
        for family, _, _, _, sockaddr in socket.getaddrinfo(hn, None, socket.AF_INET, socket.SOCK_STREAM):
            if family == socket.AF_INET:
                return str(sockaddr[0])
    except Exception:
        return None
    return None


def _tgws_default_dc(dc_ip_map):
    try:
        mapping = dc_ip_map or {}
        if not isinstance(mapping, dict):
            return None
        for key in ("2", "1", "4", "3", "5"):
            if key in mapping and str(mapping.get(key) or "").strip():
                return int(key)
        for key, value in mapping.items():
            if str(value or "").strip():
                try:
                    dc = int(key)
                    if dc > 0:
                        return dc
                except Exception:
                    pass
    except Exception:
        pass
    return None


def _tgws_dc_target(dc_ip_map, dc, is_media=False):
    try:
        mapping = dc_ip_map or {}
        if not isinstance(mapping, dict):
            return ""
        dc_num = abs(int(dc or 0))
        if dc_num <= 0:
            return ""
        keys = []
        if bool(is_media):
            keys.append(str(-dc_num))
        keys.append(str(dc_num))
        for key in keys:
            target = str(mapping.get(key, "") or "").strip()
            if target:
                return target
    except:
        pass
    return ""


def _tgws_normalize_dc_ip_map(dc_ip_map, with_defaults=True):
    result = dict(TGWS_DEFAULT_DC_IP) if bool(with_defaults) else {}
    try:
        if isinstance(dc_ip_map, dict):
            items = dc_ip_map.items()
        else:
            items = []
        for key, value in items:
            try:
                dc_num = int(str(key).strip())
            except:
                continue
            if dc_num == 0:
                continue
            target = str(value or "").strip()
            if not target:
                continue
            result[str(dc_num)] = target
    except:
        pass
    return result


def _tgws_patch_init_dc(data, dc_value):
    try:
        raw = bytes(data or b"")
    except Exception:
        return data
    if len(raw) < 64:
        return data
    try:
        key = raw[8:40]
        iv = raw[40:56]
        keystream = _tgws_keystream_java(key, iv, 64)
        replacement = struct.pack("<h", int(dc_value))
        patched = bytearray(raw[:64])
        patched[60] = keystream[60] ^ replacement[0]
        patched[61] = keystream[61] ^ replacement[1]
        if len(raw) > 64:
            return bytes(patched) + raw[64:]
        return bytes(patched)
    except Exception:
        return data


class _TgWsMsgSplitter:
    def __init__(self, init_data, proto_int=None):
        raw = bytes(init_data or b"")
        key = raw[8:40]
        iv = raw[40:56]
        if JavaCipher is None or SecretKeySpec is None or IvParameterSpec is None:
            raise RuntimeError("Java crypto unavailable")
        cipher = JavaCipher.getInstance("AES/CTR/NoPadding")
        cipher.init(JavaCipher.ENCRYPT_MODE, SecretKeySpec(bytes(key), "AES"), IvParameterSpec(bytes(iv)))
        try:
            cipher.update(b"\x00" * 64)
        except Exception:
            pass
        if proto_int is None:
            _, _, proto_int = _tgws_init_info(init_data)
        self._cipher = cipher
        self._proto = int(proto_int or 0)
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk):
        data = bytes(chunk or b"")
        if not data:
            return []
        if self._disabled:
            return [data]
        try:
            plain = self._cipher.update(data)
            try:
                plain = bytes(plain)
            except Exception:
                plain = bytes(bytearray(plain))
        except Exception:
            self._disabled = True
            return [data]

        self._cipher_buf.extend(data)
        self._plain_buf.extend(plain)

        parts = []
        while self._cipher_buf:
            packet_len = self._next_packet_len()
            if packet_len is None:
                break
            if packet_len <= 0:
                parts.append(bytes(self._cipher_buf))
                self._cipher_buf.clear()
                self._plain_buf.clear()
                self._disabled = True
                break
            parts.append(bytes(self._cipher_buf[:packet_len]))
            del self._cipher_buf[:packet_len]
            del self._plain_buf[:packet_len]
        return parts

    def flush(self):
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _next_packet_len(self):
        if not self._plain_buf:
            return None
        if self._proto == _TGWS_PROTO_ABRIDGED_INT:
            return self._next_abridged_len()
        if self._proto in (_TGWS_PROTO_INTERMEDIATE_INT, _TGWS_PROTO_PADDED_INTERMEDIATE_INT):
            return self._next_intermediate_len()
        return 0

    def _next_abridged_len(self):
        first = self._plain_buf[0]
        if first in (0x7F, 0xFF):
            if len(self._plain_buf) < 4:
                return None
            payload_len = int.from_bytes(bytes(self._plain_buf[1:4]), "little") * 4
            header_len = 4
        else:
            payload_len = (int(first) & 0x7F) * 4
            header_len = 1
        if payload_len <= 0:
            return 0
        packet_len = header_len + payload_len
        if len(self._plain_buf) < packet_len:
            return None
        return packet_len

    def _next_intermediate_len(self):
        if len(self._plain_buf) < 4:
            return None
        payload_len = struct.unpack_from("<I", bytes(self._plain_buf[:4]), 0)[0] & 0x7FFFFFFF
        if payload_len <= 0:
            return 0
        packet_len = 4 + payload_len
        if len(self._plain_buf) < packet_len:
            return None
        return packet_len


def _tgws_ws_domains(dc, is_media):
    try:
        dc_num = int(dc or 0)
    except:
        dc_num = 0
    if dc_num == 203:
        dc_num = 2
    if not bool(is_media):
        return [f"kws{dc_num}.web.telegram.org", f"kws{dc_num}-1.web.telegram.org"]
    return [f"kws{dc_num}-1.web.telegram.org", f"kws{dc_num}.web.telegram.org"]


def _tgws_socks_reply(status):
    return bytes((0x05, int(status) & 0xFF, 0x00, 0x01, 0, 0, 0, 0, 0, 0))


class _TgWsHandshakeError(Exception):
    def __init__(self, status_code, status_line, headers=None, location=None):
        self.status_code = int(status_code or 0)
        self.status_line = str(status_line or "")
        self.headers = headers or {}
        self.location = location
        Exception.__init__(self, "HTTP %s: %s" % (self.status_code, self.status_line))

    @property
    def is_redirect(self):
        return int(self.status_code or 0) in (301, 302, 303, 307, 308)


def _tgws_is_redirect_error(exc):
    try:
        if bool(getattr(exc, "is_redirect", False)):
            return True
    except:
        pass
    try:
        text = str(exc or "")
        return text.startswith("HTTP") and any((" %s" % code) in text for code in (301, 302, 303, 307, 308))
    except:
        return False


def _tgws_is_timeout_error(exc):
    return isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in str(exc or "").lower()


def _tgws_read_socks_address(conn, atyp):
    atyp = int(atyp or 0)
    if atyp == 0x01:
        host = socket.inet_ntoa(_tgws_recv_exact(conn, 4))
        port = int.from_bytes(_tgws_recv_exact(conn, 2), "big")
        return host, port
    if atyp == 0x03:
        size = _tgws_recv_exact(conn, 1)[0]
        host = _tgws_recv_exact(conn, size).decode("utf-8", errors="ignore")
        port = int.from_bytes(_tgws_recv_exact(conn, 2), "big")
        return host, port
    if atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, _tgws_recv_exact(conn, 16))
        port = int.from_bytes(_tgws_recv_exact(conn, 2), "big")
        return host, port
    raise ValueError("unsupported atyp")


class _TgWsRawWebSocket:
    def __init__(self, sock, reader):
        self.sock = sock
        self.reader = reader
        self._lock = threading.Lock()
        self._closed = False
        self._frag = bytearray()

    @staticmethod
    def connect(connect_host, sni_host, timeout=TGWS_WS_CONNECT_TIMEOUT_SEC, path="/apiws", sni=None):
        sock = socket.create_connection((str(connect_host), 443), timeout=float(timeout))
        wrapped = None
        reader = None
        try:
            _tgws_set_socket_options(sock)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            wrapped = ctx.wrap_socket(sock, server_hostname=str(sni or sni_host or ""))
            _tgws_set_socket_options(wrapped)
            wrapped.settimeout(float(timeout))
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            req = "\r\n".join([
                "GET " + str(path or "/apiws") + " HTTP/1.1",
                "Host: " + str(sni_host or ""),
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Sec-WebSocket-Key: " + key,
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Protocol: binary",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "",
                "",
            ]).encode("utf-8")
            wrapped.sendall(req)
            reader = wrapped.makefile("rb")
            status_line = reader.readline().decode("utf-8", errors="replace").strip()
            parts = status_line.split(" ", 2)
            code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            headers = {}
            while True:
                line = reader.readline().decode("utf-8", errors="replace")
                if not line or line in ("\r\n", "\n"):
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[str(k).strip().lower()] = str(v).strip()
            if code != 101:
                raise _TgWsHandshakeError(code, status_line or "bad websocket handshake", headers, headers.get("location"))
            wrapped.settimeout(None)
            return _TgWsRawWebSocket(wrapped, reader)
        except:
            try:
                if reader is not None:
                    reader.close()
            except:
                pass
            try:
                if wrapped is not None:
                    wrapped.close()
                else:
                    sock.close()
            except:
                pass
            raise

    def send(self, payload):
        with self._lock:
            if self._closed:
                raise EOFError("websocket closed")
            self.sock.sendall(_tgws_build_frame(0x2, payload, mask=True))

    def send_batch(self, parts):
        with self._lock:
            if self._closed:
                raise EOFError("websocket closed")
            for payload in list(parts or []):
                self.sock.sendall(_tgws_build_frame(0x2, payload, mask=True))

    def _read_frame(self):
        header = _tgws_read_exact(self.reader, 2)
        fin = bool(header[0] & 0x80)
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", _tgws_read_exact(self.reader, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", _tgws_read_exact(self.reader, 8))[0]
        mask_key = b""
        if masked:
            mask_key = _tgws_read_exact(self.reader, 4)
        if int(length) > 16 * 1024 * 1024:
            raise ValueError("websocket frame too large")
        payload = _tgws_read_exact(self.reader, length)
        if masked:
            payload = _tgws_xor_mask(payload, mask_key)
        return opcode, payload, fin

    def recv(self):
        while True:
            opcode, payload, fin = self._read_frame()
            if opcode == 0x8:
                self.close()
                return None
            if opcode == 0x9:
                self._write_control(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in (0x0, 0x1, 0x2):
                if fin and not self._frag:
                    return payload
                self._frag.extend(payload)
                if len(self._frag) > 16 * 1024 * 1024:
                    raise ValueError("websocket message too large")
                if not fin:
                    continue
                message = bytes(self._frag)
                self._frag.clear()
                return message

    def _write_control(self, opcode, payload):
        with self._lock:
            if self._closed:
                return
            self.sock.sendall(_tgws_build_frame(opcode, payload, mask=True))

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self.sock.settimeout(0.2)
            except:
                pass
            try:
                self.sock.sendall(_tgws_build_frame(0x8, b"", mask=True))
            except:
                pass
            try:
                self.reader.close()
            except:
                pass
            try:
                self.sock.close()
            except:
                pass


class _TgWsWsPool:
    def __init__(self, size=TGWS_WS_POOL_SIZE):
        self.size = int(size or 0)
        self.idle = {}
        self.refilling = set()
        self.rotating = set()
        self.refill_failures = {}
        self.refill_after = {}
        self.try_fronting_first = True
        self.generation = 0
        self.lock = threading.Lock()

    def reset(self):
        with self.lock:
            self.generation += 1
            buckets = list(self.idle.values())
            self.idle.clear()
            self.refilling.clear()
            self.rotating.clear()
            self.refill_failures.clear()
            self.refill_after.clear()
            self.try_fronting_first = False
        for bucket in buckets:
            for ws, _ in list(bucket or []):
                try:
                    ws.close()
                except:
                    pass

    def warmup(self, dc_ip):
        try:
            mapping = dict(dc_ip or {})
        except:
            mapping = {}
        for dc, target in mapping.items():
            try:
                raw_dc = int(dc)
            except:
                continue
            dc_num = abs(int(raw_dc))
            if dc_num <= 0:
                continue
            target_ip = str(target or "").strip()
            if not target_ip:
                continue
            if raw_dc < 0:
                media_modes = (True,)
            else:
                media_override = str(mapping.get(str(-dc_num), "") or "").strip()
                media_modes = (False,) if media_override else (False, True)
            for is_media in media_modes:
                self._schedule_refill((dc_num, bool(is_media), target_ip), target_ip, _tgws_ws_domains(dc_num, is_media))

    def get(self, dc, is_media, target_ip, domains, allow_refill=True):
        target = str(target_ip or "").strip()
        if not target:
            return None
        key = (int(dc), bool(is_media), target)
        now = time.monotonic()
        ready_ws = None
        with self.lock:
            bucket = self.idle.setdefault(key, [])
            while bucket:
                ws, created = bucket.pop(0)
                try:
                    expired = (now - float(created)) > float(TGWS_WS_POOL_MAX_AGE_SEC)
                    closed = bool(getattr(ws, "_closed", False))
                except:
                    expired = True
                    closed = True
                if expired or closed:
                    try:
                        ws.close()
                    except:
                        pass
                    continue
                ready_ws = ws
                break
        if ready_ws is not None:
            self.report_success(key)
        if bool(allow_refill):
            self._schedule_refill(key, target, domains)
        return ready_ws

    def report_success(self, key):
        with self.lock:
            self.refill_failures.pop(key, None)
            self.refill_after.pop(key, None)

    def _schedule_refill(self, key, target_ip, domains):
        if self.size <= 0:
            return
        target = str(target_ip or "").strip()
        if not target:
            return
        with self.lock:
            if key in self.refilling or time.monotonic() < float(self.refill_after.get(key, 0.0) or 0.0):
                return
            self.refilling.add(key)
            generation = int(self.generation)
        threading.Thread(target=self._refill, args=(key, target, list(domains or []), generation), daemon=True).start()

    def _refill(self, key, target_ip, domains, generation):
        connected = 0
        try:
            with self.lock:
                if int(generation) != int(self.generation):
                    return
                bucket = self.idle.setdefault(key, [])
                needed = max(0, int(self.size) - len(bucket))
                if needed <= 0:
                    return
            for _ in range(needed):
                with self.lock:
                    if int(generation) != int(self.generation):
                        return
                ws = self._connect_one(target_ip, domains)
                if ws is None:
                    continue
                with self.lock:
                    if int(generation) != int(self.generation):
                        try:
                            ws.close()
                        except:
                            pass
                        return
                    self.idle.setdefault(key, []).append((ws, time.monotonic()))
                    connected += 1
                self._schedule_rotation(key, target_ip, domains, generation)
            with self.lock:
                if int(generation) == int(self.generation):
                    if connected:
                        self.refill_failures.pop(key, None)
                        self.refill_after.pop(key, None)
                    else:
                        failures = int(self.refill_failures.get(key, 0) or 0) + 1
                        self.refill_failures[key] = failures
                        delay = min(
                            float(TGWS_WS_POOL_REFILL_BACKOFF_INITIAL_SEC) * (2 ** min(max(failures - 1, 0), 12)),
                            float(TGWS_WS_POOL_REFILL_BACKOFF_MAX_SEC),
                        )
                        self.refill_after[key] = time.monotonic() + delay
        finally:
            with self.lock:
                if int(generation) == int(self.generation):
                    self.refilling.discard(key)

    def _schedule_rotation(self, key, target_ip, domains, generation):
        with self.lock:
            if int(generation) != int(self.generation) or key in self.rotating:
                return
            self.rotating.add(key)
        threading.Thread(target=self._rotate, args=(key, target_ip, list(domains or []), generation), daemon=True).start()

    def _rotate(self, key, target_ip, domains, generation):
        try:
            while True:
                with self.lock:
                    if int(generation) != int(self.generation):
                        return
                    bucket = list(self.idle.get(key, []) or [])
                if not bucket:
                    return
                expires_at = min(float(created) + float(TGWS_WS_POOL_MAX_AGE_SEC) for _, created in bucket)
                time.sleep(min(float(TGWS_WS_POOL_CHECK_INTERVAL_SEC), max(0.0, expires_at - time.monotonic())))
                expired = []
                with self.lock:
                    if int(generation) != int(self.generation):
                        return
                    ready = []
                    now = time.monotonic()
                    for ws, created in list(self.idle.get(key, []) or []):
                        if (now - float(created)) >= float(TGWS_WS_POOL_MAX_AGE_SEC) or bool(getattr(ws, "_closed", False)):
                            expired.append(ws)
                        else:
                            ready.append((ws, created))
                    self.idle[key] = ready
                for ws in expired:
                    try:
                        ws.close()
                    except:
                        pass
                if expired and len(ready) < int(self.size):
                    self._schedule_refill(key, target_ip, domains)
        finally:
            with self.lock:
                if int(generation) == int(self.generation):
                    self.rotating.discard(key)

    def _connect_one(self, target_ip, domains):
        for domain in list(domains or []):
            with self.lock:
                fronting_first = bool(self.try_fronting_first)
            if fronting_first:
                ws = self._connect_fronted(target_ip, domain)
                if ws is not None:
                    return ws
            try:
                ws = _TgWsRawWebSocket.connect(target_ip, domain, timeout=TGWS_WS_CONNECT_TIMEOUT_SEC)
                with self.lock:
                    self.try_fronting_first = False
                return ws
            except Exception as exc:
                if _tgws_is_timeout_error(exc) or isinstance(exc, ConnectionResetError):
                    if fronting_first:
                        return None
                    return self._connect_fronted(target_ip, domain)
                if _tgws_is_redirect_error(exc):
                    continue
                return None
        return None

    def _connect_fronted(self, target_ip, domain):
        try:
            ws = _TgWsRawWebSocket.connect(target_ip, domain, timeout=7.0, sni=TGWS_FRONTING_SNI)
        except Exception:
            return None
        with self.lock:
            self.try_fronting_first = True
        return ws


class TgWsCore:
    def __init__(self):
        self.listener = None
        self.listener_thread = None
        self.listener_generation = 0
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.tracked = set()
        self.fail_until = {}
        self.fail_count = {}
        self.ip_fail_until = {}
        self.ws_blacklist = set()
        self.ws_blacklist_until = {}
        self.ws_domain_pref = {}
        self.cf_domain_pref = {}
        self.ws_pool = _TgWsWsPool()
        self.pool_size = int(TGWS_WS_POOL_SIZE)
        self.cfproxy_enabled = bool(TGWS_CFPROXY_ENABLED)
        self.cfproxy_priority = bool(TGWS_CFPROXY_PRIORITY)
        self.cfproxy_domains = list(TGWS_CFPROXY_DEFAULT_DOMAINS)
        self.cfproxy_worker_domain = str(TGWS_CFPROXY_WORKER_DOMAIN or "")
        self.cfproxy_refresh_thread = None
        self.cfproxy_refresh_stop = threading.Event()
        self.cf_429_until = {}
        self._heal_lock = threading.Lock()
        self.port = 0
        self.dc_ip = dict(TGWS_DEFAULT_DC_IP)

    def is_available(self):
        return JavaCipher is not None

    def _reset_cf_domain_pref(self):
        domains = list(self.cfproxy_domains or [])
        if not domains:
            self.cf_domain_pref = {}
            return
        try:
            self.cf_domain_pref = {dc: random.choice(domains) for dc in (1, 2, 3, 4, 5, 203)}
        except:
            self.cf_domain_pref = {}

    def _apply_cfproxy_domains(self, domains):
        pool = _tgws_normalize_domain_pool(domains)
        if len(pool) < int(TGWS_CFPROXY_MIN_VALID_DOMAINS):
            return False
        try:
            if set(pool) == set(list(self.cfproxy_domains or [])):
                return False
        except:
            if pool == list(self.cfproxy_domains or []):
                return False
        self.cfproxy_domains = pool
        self._reset_cf_domain_pref()
        return True

    def _refresh_cfproxy_domains(self, stop_event=None):
        try:
            event = stop_event
            if event is not None and event.is_set():
                return False
            fetched = _tgws_fetch_cfproxy_domains()
            if event is not None and event.is_set():
                return False
            return self._apply_cfproxy_domains(fetched)
        except:
            return False

    def _cfproxy_refresh_loop(self, stop_event=None):
        event = stop_event or self.stop_event
        if not event.is_set():
            self._refresh_cfproxy_domains(event)
        try:
            while not event.wait(float(TGWS_CFPROXY_REFRESH_INTERVAL_SEC)):
                self._refresh_cfproxy_domains(event)
        except:
            pass

    def self_heal(self):
        if not self._heal_lock.acquire(blocking=False):
            return
        try:
            try:
                self.ws_blacklist.clear()
            except:
                pass
            try:
                self.ws_blacklist_until.clear()
            except:
                pass
            try:
                self.fail_until.clear()
            except:
                pass
            try:
                self.fail_count.clear()
            except:
                pass
            try:
                self.ip_fail_until.clear()
            except:
                pass
            try:
                self.ws_domain_pref.clear()
            except:
                pass
            try:
                self.cf_429_until.clear()
            except:
                pass
            try:
                self.ws_pool.reset()
                self.ws_pool.warmup(self.dc_ip)
            except:
                pass
            try:
                self._refresh_cfproxy_domains()
            except:
                pass
        finally:
            self._heal_lock.release()

    def _track(self, closer):
        with self.lock:
            self.tracked.add(closer)

    def _untrack(self, closer):
        with self.lock:
            self.tracked.discard(closer)

    def _close_all_tracked(self):
        with self.lock:
            closers = list(self.tracked)
            self.tracked.clear()
        for closer in closers:
            try:
                closer.close()
            except:
                pass

    def _ws_fail_record(self, dc_key):
        try:
            count = int(self.fail_count.get(dc_key, 0) or 0) + 1
            self.fail_count[dc_key] = count
            backoff = float(TGWS_WS_FAIL_COOLDOWN_SEC) * (2 ** min(max(count - 1, 0), 4))
            self.fail_until[dc_key] = time.time() + min(backoff, float(TGWS_WS_FAIL_COOLDOWN_MAX_SEC))
        except:
            self.fail_until[dc_key] = time.time() + float(TGWS_WS_FAIL_COOLDOWN_SEC)

    def _ws_fail_clear(self, dc_key):
        try:
            self.fail_until.pop(dc_key, None)
            self.fail_count.pop(dc_key, None)
        except:
            pass

    def _ws_is_blacklisted(self, dc_key):
        try:
            until = float(self.ws_blacklist_until.get(dc_key, 0.0) or 0.0)
            if until and until > time.time():
                return True
            self.ws_blacklist_until.pop(dc_key, None)
            self.ws_blacklist.discard(dc_key)
        except:
            pass
        return False

    def _ws_blacklist_add(self, dc_key):
        try:
            self.ws_blacklist.add(dc_key)
            self.ws_blacklist_until[dc_key] = time.time() + float(TGWS_WS_BLACKLIST_TTL_SEC)
        except:
            pass

    def _parse_config(self, config_json):
        cfg = {
            "port": int(TGWS_LOCAL_PORT),
            "dc_ip": dict(TGWS_DEFAULT_DC_IP),
            "pool_size": int(TGWS_WS_POOL_SIZE),
            "cfproxy": bool(TGWS_CFPROXY_ENABLED),
            "cfproxy_priority": bool(TGWS_CFPROXY_PRIORITY),
            "cfproxy_domains": list(TGWS_CFPROXY_DEFAULT_DOMAINS),
            "cfproxy_worker_domain": str(TGWS_CFPROXY_WORKER_DOMAIN or ""),
        }
        raw = str(config_json or "").strip()
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                if parsed.get("port"):
                    cfg["port"] = int(parsed.get("port") or TGWS_LOCAL_PORT)
                if "pool_size" in parsed:
                    try:
                        cfg["pool_size"] = max(0, int(parsed.get("pool_size") or 0))
                    except:
                        pass
                if "cfproxy" in parsed:
                    cfg["cfproxy"] = bool(parsed.get("cfproxy"))
                if "cfproxy_priority" in parsed:
                    cfg["cfproxy_priority"] = bool(parsed.get("cfproxy_priority"))
                if "cfproxy_worker_domain" in parsed:
                    cfg["cfproxy_worker_domain"] = str(parsed.get("cfproxy_worker_domain") or "")
                cf_domains = parsed.get("cfproxy_domains")
                if isinstance(cf_domains, list):
                    clean = _tgws_normalize_domain_pool(cf_domains)
                    if len(clean) >= int(TGWS_CFPROXY_MIN_VALID_DOMAINS):
                        cfg["cfproxy_domains"] = clean
                dc_ip = parsed.get("dc_ip")
                if isinstance(dc_ip, dict):
                    cfg["dc_ip"] = _tgws_normalize_dc_ip_map(dc_ip, with_defaults=True)
        if cfg["port"] <= 0 or cfg["port"] > 65535:
            cfg["port"] = int(TGWS_LOCAL_PORT)
        return cfg

    def start(self, config_json):
        if not self.is_available():
            return "Java crypto недоступно"
        try:
            cfg = self._parse_config(config_json)
            self.stop()
            listener = self._open_listener(int(cfg["port"]))
            self.listener = listener
            self.port = int(cfg["port"])
            self.dc_ip = _tgws_normalize_dc_ip_map(cfg.get("dc_ip") or {}, with_defaults=False)
            self.pool_size = max(0, int(cfg.get("pool_size", TGWS_WS_POOL_SIZE) or 0))
            self.cfproxy_enabled = bool(cfg.get("cfproxy", TGWS_CFPROXY_ENABLED))
            self.cfproxy_priority = bool(cfg.get("cfproxy_priority", TGWS_CFPROXY_PRIORITY))
            cf_domains = _tgws_normalize_domain_pool(cfg.get("cfproxy_domains") or TGWS_CFPROXY_DEFAULT_DOMAINS)
            if len(cf_domains) < int(TGWS_CFPROXY_MIN_VALID_DOMAINS):
                cf_domains = list(TGWS_CFPROXY_DEFAULT_DOMAINS)
            self.cfproxy_domains = list(cf_domains)
            self.cfproxy_worker_domain = str(cfg.get("cfproxy_worker_domain", "") or "")
            self._reset_cf_domain_pref()
            self.ws_pool.reset()
            self.ws_pool.size = int(self.pool_size)
            self.ws_blacklist.clear()
            self.ws_blacklist_until.clear()
            self.fail_until.clear()
            self.fail_count.clear()
            self.ip_fail_until.clear()
            self.ws_domain_pref.clear()
            self.cf_429_until.clear()
            self.stop_event.clear()
            self.listener_generation += 1
            listener_generation = int(self.listener_generation)
            self.cfproxy_refresh_stop = threading.Event()
            self.listener_thread = threading.Thread(target=self._accept_loop, args=(listener_generation,), daemon=True)
            self.listener_thread.start()
            self.ws_pool.warmup(self.dc_ip)
            refresh_stop = self.cfproxy_refresh_stop
            self.cfproxy_refresh_thread = threading.Thread(target=self._cfproxy_refresh_loop, args=(refresh_stop,), daemon=True)
            self.cfproxy_refresh_thread.start()
            return ""
        except Exception as exc:
            try:
                if self.listener is not None:
                    self.listener.close()
            except:
                pass
            self.listener = None
            return str(exc)

    def stop(self):
        self.listener_generation += 1
        self.stop_event.set()
        try:
            self.cfproxy_refresh_stop.set()
        except:
            pass
        try:
            if self.listener is not None:
                self.listener.close()
        except:
            pass
        self.listener = None
        try:
            self.ws_pool.reset()
        except:
            pass
        try:
            self.cf_429_until.clear()
        except:
            pass
        self._close_all_tracked()
        thread = self.listener_thread
        self.listener_thread = None
        if thread is not None and thread.is_alive():
            try:
                thread.join(1.5)
            except:
                pass
        refresh = self.cfproxy_refresh_thread
        self.cfproxy_refresh_thread = None
        if refresh is not None and refresh.is_alive():
            try:
                refresh.join(1.0)
            except:
                pass

    def _open_listener(self, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            _tgws_set_socket_options(listener)
            listener.bind((VLESS_LOCAL_HOST, int(port)))
            listener.listen(32)
            listener.settimeout(1.0)
            return listener
        except:
            try:
                listener.close()
            except:
                pass
            raise

    def _restart_listener(self, generation):
        old_listener = self.listener
        self.listener = None
        try:
            if old_listener is not None:
                old_listener.close()
        except:
            pass
        if self.stop_event.wait(float(TGWS_LISTENER_RESTART_DELAY_SEC)):
            return False
        if int(generation) != int(self.listener_generation):
            return False
        try:
            listener = self._open_listener(self.port)
        except:
            return False
        if self.stop_event.is_set() or int(generation) != int(self.listener_generation):
            try:
                listener.close()
            except:
                pass
            return False
        self.listener = listener
        return True

    def _accept_loop(self, generation):
        while not self.stop_event.is_set() and int(generation) == int(self.listener_generation):
            listener = self.listener
            if listener is None:
                self._restart_listener(generation)
                continue
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except:
                if self.stop_event.is_set() or int(generation) != int(self.listener_generation):
                    break
                self._restart_listener(generation)
                continue
            try:
                _tgws_set_socket_options(conn)
            except:
                pass
            self._track(conn)
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _close_write(self, conn):
        try:
            conn.shutdown(socket.SHUT_WR)
        except:
            pass

    def _bridge_tcp(self, left, right, streams=None):
        done = threading.Event()
        clt_dec = clt_enc = tg_enc = tg_dec = None
        if streams:
            try:
                clt_dec, clt_enc, tg_enc, tg_dec = streams
            except:
                clt_dec = clt_enc = tg_enc = tg_dec = None
        for conn in (left, right):
            try:
                conn.settimeout(None)
            except:
                pass

        def _forward(src, dst, transform=None):
            try:
                while not done.is_set():
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    if transform is not None:
                        chunk = transform(chunk)
                    dst.sendall(chunk)
            except:
                pass
            done.set()
            self._close_write(dst)

        up = (lambda chunk: tg_enc.xor(clt_dec.xor(chunk))) if clt_dec is not None and tg_enc is not None else None
        down = (lambda chunk: clt_enc.xor(tg_dec.xor(chunk))) if clt_enc is not None and tg_dec is not None else None
        t1 = threading.Thread(target=_forward, args=(left, right, up), daemon=True)
        t2 = threading.Thread(target=_forward, args=(right, left, down), daemon=True)
        t1.start()
        t2.start()
        while not done.is_set() and (t1.is_alive() or t2.is_alive()):
            time.sleep(0.1)
        done.set()
        for item in (left, right):
            try:
                item.close()
            except:
                pass
            self._untrack(item)

    def _bridge_ws_split(self, client, ws, splitter, streams=None):
        done = threading.Event()
        downstream_seen = threading.Event()
        clt_dec = clt_enc = tg_enc = tg_dec = None
        if streams:
            try:
                clt_dec, clt_enc, tg_enc, tg_dec = streams
            except:
                clt_dec = clt_enc = tg_enc = tg_dec = None
        try:
            client.settimeout(None)
        except:
            pass

        def _client_to_ws():
            try:
                while not done.is_set():
                    chunk = client.recv(65536)
                    if not chunk:
                        if splitter is not None:
                            try:
                                for tail in splitter.flush():
                                    ws.send(tail)
                            except:
                                pass
                        break
                    if clt_dec is not None and tg_enc is not None:
                        chunk = tg_enc.xor(clt_dec.xor(chunk))
                    if splitter is not None:
                        parts = splitter.split(chunk)
                        if not parts:
                            continue
                        if len(parts) > 1:
                            try:
                                ws.send_batch(parts)
                            except Exception:
                                for payload in parts:
                                    ws.send(payload)
                        else:
                            ws.send(parts[0])
                    else:
                        ws.send(chunk)
            except:
                pass
            done.set()

        def _ws_to_client():
            try:
                while not done.is_set():
                    payload = ws.recv()
                    if payload is None:
                        break
                    downstream_seen.set()
                    if tg_dec is not None and clt_enc is not None:
                        payload = clt_enc.xor(tg_dec.xor(payload))
                    client.sendall(payload)
            except:
                pass
            done.set()

        t1 = threading.Thread(target=_client_to_ws, daemon=True)
        t2 = threading.Thread(target=_ws_to_client, daemon=True)
        t1.start()
        t2.start()
        while not done.is_set() and (t1.is_alive() or t2.is_alive()):
            time.sleep(0.1)
        done.set()
        try:
            ws.close()
        except:
            pass
        self._untrack(ws)
        try:
            client.close()
        except:
            pass
        self._untrack(client)
        return downstream_seen.is_set()

    def _direct_passthrough(self, client, dst, port):
        remote = socket.create_connection((str(dst), int(port)), 10.0)
        _tgws_set_socket_options(remote)
        try:
            client.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
            remote.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
        except:
            pass
        self._track(remote)
        client.sendall(_tgws_socks_reply(0x00))
        self._bridge_tcp(client, remote)

    def _tcp_fallback(self, client, dst, port, init_packet, streams=None):
        remote = socket.create_connection((str(dst), int(port)), 10.0)
        _tgws_set_socket_options(remote)
        try:
            client.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
            remote.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
        except:
            pass
        self._track(remote)
        if init_packet:
            remote.sendall(bytes(init_packet))
        self._bridge_tcp(client, remote, streams=streams)

    def _cfproxy_worker_fallback(self, client, dc, is_media, init_packet, proto_int, streams=None):
        worker_domain = str(self.cfproxy_worker_domain or "").strip()
        if not worker_domain:
            return False
        try:
            fallback_dst = str(TGWS_DIRECT_FALLBACK_IP.get(str(int(dc))) or "").strip()
        except:
            fallback_dst = ""
        if not fallback_dst:
            return False
        try:
            query = urllib.parse.urlencode({
                "dst": fallback_dst,
                "dc": str(int(dc)),
                "media": "1" if bool(is_media) else "0",
            })
        except:
            return False
        path = "/apiws?" + query
        ws = None
        try:
            ws = _TgWsRawWebSocket.connect(worker_domain, worker_domain, timeout=TGWS_CFPROXY_CONNECT_TIMEOUT_SEC, path=path)
            self._track(ws)
            ws.send(init_packet)
            self._bridge_ws_split(client, ws, None, streams=streams)
            return True
        except:
            try:
                if ws is not None:
                    ws.close()
            except:
                pass
            return False

    def _cfproxy_fallback(self, client, dc, is_media, init_packet, proto_int, streams=None):
        domains = list(self.cfproxy_domains or [])
        try:
            preferred = str(self.cf_domain_pref.get(int(dc)) or "").strip()
        except:
            preferred = ""
        if preferred:
            rest = [domain for domain in domains if domain != preferred]
            try:
                random.shuffle(rest)
            except:
                pass
            domains = [preferred] + rest
        else:
            try:
                random.shuffle(domains)
            except:
                pass
        for base_domain in domains:
            base = str(base_domain or "").strip()
            if not base:
                continue
            try:
                if float(self.cf_429_until.get(base, 0.0) or 0.0) > time.time():
                    continue
            except:
                pass
            domain = "kws%s.%s" % (int(dc), base)
            ws = None
            try:
                ws = _TgWsRawWebSocket.connect(domain, domain, timeout=TGWS_CFPROXY_CONNECT_TIMEOUT_SEC)
                try:
                    self.cf_429_until.pop(base, None)
                except:
                    pass
                self.cf_domain_pref[int(dc)] = base
                self._track(ws)
                ws.send(init_packet)
                splitter = None
                try:
                    splitter = _TgWsMsgSplitter(init_packet, proto_int)
                except:
                    splitter = None
                healthy = self._bridge_ws_split(client, ws, splitter, streams=streams)
                if not healthy:
                    self.cf_domain_pref.pop(int(dc), None)
                return True
            except Exception as exc:
                try:
                    if int(getattr(exc, "status_code", 0) or 0) == 429:
                        self.cf_429_until[base] = time.time() + float(TGWS_CFPROXY_429_COOLDOWN_SEC)
                except:
                    pass
                try:
                    if ws is not None:
                        ws.close()
                except:
                    pass
                continue
        return False

    def _fallback(self, client, dst, port, init_packet, dc=None, is_media=False, proto_int=None, allow_cf=True, streams=None):
        methods = ["tcp"]
        if bool(allow_cf) and bool(self.cfproxy_enabled) and dc is not None:
            methods.insert(0 if bool(self.cfproxy_priority) else 1, "cf")
        if dc is not None and str(self.cfproxy_worker_domain or "").strip():
            methods.insert(0, "cf_worker")
        for method in methods:
            try:
                if method == "cf_worker":
                    if self._cfproxy_worker_fallback(client, int(dc), bool(is_media), init_packet, proto_int, streams=streams):
                        return True
                elif method == "cf":
                    if self._cfproxy_fallback(client, int(dc), bool(is_media), init_packet, proto_int, streams=streams):
                        return True
                else:
                    fallback_dst = str(dst or "")
                    try:
                        if dc is not None:
                            fallback_dst = str(TGWS_DIRECT_FALLBACK_IP.get(str(int(dc))) or fallback_dst)
                    except:
                        pass
                    self._tcp_fallback(client, fallback_dst, port, init_packet, streams=streams)
                    return True
            except:
                continue
        return False

    def _connect_ws(self, candidate_ips, domains, dc_key):
        ws_failed_redirect = False
        all_redirects = True
        timed_out = False
        for domain in list(domains or []):
            for candidate_ip in _tgws_unique_values(*list(candidate_ips or [])):
                try:
                    ws = _TgWsRawWebSocket.connect(candidate_ip, domain, timeout=TGWS_WS_CONNECT_TIMEOUT_SEC)
                    self.ws_domain_pref[dc_key] = str(domain)
                    return ws, ws_failed_redirect, False, False
                except Exception as exc:
                    if _tgws_is_timeout_error(exc):
                        timed_out = True
                        all_redirects = False
                        break
                    if _tgws_is_redirect_error(exc):
                        ws_failed_redirect = True
                        continue
                    all_redirects = False
            if timed_out:
                break
        return None, ws_failed_redirect, all_redirects, timed_out

    def _handle_client(self, conn):
        try:
            conn.settimeout(10.0)
            header = _tgws_recv_exact(conn, 2)
            streams = None
            if header[0] == 0x05:
                _tgws_recv_exact(conn, header[1])
                conn.sendall(b"\x05\x00")
                req = _tgws_recv_exact(conn, 4)
                if req[1] != 0x01:
                    conn.sendall(_tgws_socks_reply(0x07))
                    return
                atyp = int(req[3])
                dst, port = _tgws_read_socks_address(conn, atyp)

                dst_ip = str(dst)
                if atyp == 0x03:
                    try:
                        resolved = _tgws_resolve_ipv4(dst)
                        if resolved:
                            dst_ip = resolved
                    except Exception:
                        pass

                if not _tgws_is_telegram_ip(dst_ip):
                    try:
                        self._direct_passthrough(conn, dst, port)
                    except:
                        try:
                            conn.sendall(_tgws_socks_reply(0x05))
                        except:
                            pass
                    return
                conn.sendall(_tgws_socks_reply(0x00))
                conn.settimeout(15.0)
                init_packet = _tgws_recv_exact(conn, 64)
                conn.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
                if _tgws_is_http_transport(init_packet):
                    return
                dc, is_media, proto_int = _tgws_init_info(init_packet)
                dst_entry = _tgws_dc_from_dst_ip(dst_ip)

                if dst_entry is not None:
                    try:
                        dc = int(dst_entry[0])
                        is_media = bool(dst_entry[1])
                        target_ip0 = _tgws_dc_target(self.dc_ip, dc, is_media)
                        if target_ip0:
                            init_packet = _tgws_patch_init_dc(init_packet, -dc if is_media else dc)
                    except Exception:
                        pass

                if dc is None:
                    try:
                        if _tgws_is_telegram_ip(dst_ip) and ":" in str(dst_ip):
                            default_dc = _tgws_default_dc(self.dc_ip)
                            if default_dc is not None:
                                dc = int(default_dc)
                                is_media = False
                    except Exception:
                        pass
            else:
                init_in = bytes(header) + _tgws_recv_exact(conn, 62)
                conn.settimeout(TGWS_BRIDGE_IDLE_TIMEOUT_SEC)
                if _tgws_is_http_transport(init_in):
                    return
                session = _tgws_raw_proxy_session(init_in)
                if not session:
                    return
                dc, is_media, proto_int, init_packet, streams = session
                port = 443
                dst = str(TGWS_DIRECT_FALLBACK_IP.get(str(int(dc))) or "")
                dst_ip = str(_tgws_dc_target(self.dc_ip, dc, is_media) or dst)

            if dc is None:
                self._fallback(conn, dst, port, init_packet, None, False, proto_int, streams=streams)
                return
            target_ip = _tgws_dc_target(self.dc_ip, dc, is_media)
            dc_key = (int(dc), bool(is_media))
            priority_cf_tried = False
            if bool(self.cfproxy_enabled) and bool(self.cfproxy_priority):
                priority_cf_tried = True
                if self._cfproxy_fallback(conn, dc, is_media, init_packet, proto_int, streams=streams):
                    return
            if not target_ip:
                self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                return
            try:
                if self._ws_is_blacklisted(dc_key):
                    self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                    return
            except Exception:
                pass
            now = time.monotonic()
            ip_blocked = now < float(self.ip_fail_until.get(target_ip, 0.0) or 0.0)
            any_cf_fallback = bool(self.cfproxy_enabled) or bool(str(self.cfproxy_worker_domain or "").strip())
            fail_until = float(self.fail_until.get(dc_key, 0.0) or 0.0)
            if fail_until > time.time():
                self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                return
            ws = None
            ws_failed_redirect = False
            all_redirects = True
            domains = _tgws_ws_domains(dc, is_media)
            try:
                preferred = str(self.ws_domain_pref.get(dc_key) or "").strip()
            except Exception:
                preferred = ""
            if preferred:
                domains = [preferred] + [domain for domain in domains if domain != preferred]

            try:
                # A timed-out target may still have a warm WS connection.  Use
                # that connection before falling back; this is especially
                # important after the device resumes from sleep.
                ws = self.ws_pool.get(
                    dc, is_media, target_ip, domains,
                    allow_refill=not ip_blocked,
                )
                if ws is not None:
                    all_redirects = False
            except:
                ws = None

            if ip_blocked and any_cf_fallback and ws is None:
                self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                return

            if ws is None:
                ws, ws_failed_redirect, all_redirects, ws_timed_out = self._connect_ws((target_ip, dst_ip), domains, dc_key)
            else:
                ws_timed_out = False
            if ws is None:
                if ws_timed_out:
                    self.ip_fail_until[target_ip] = time.monotonic() + float(TGWS_IP_FAIL_COOLDOWN_SEC)
                try:
                    if ws_failed_redirect and all_redirects:
                        self._ws_blacklist_add(dc_key)
                except Exception:
                    pass
                self._ws_fail_record(dc_key)
                self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                return
            self._ws_fail_clear(dc_key)
            self.ip_fail_until.pop(target_ip, None)
            self.ws_pool.report_success((int(dc), bool(is_media), str(target_ip)))
            self._track(ws)
            try:
                ws.send(init_packet)
            except:
                try:
                    ws.close()
                except:
                    pass
                self._untrack(ws)
                ws, _, _, ws_timed_out = self._connect_ws((target_ip, dst_ip), domains, dc_key)
                if ws is None:
                    if ws_timed_out:
                        self.ip_fail_until[target_ip] = time.monotonic() + float(TGWS_IP_FAIL_COOLDOWN_SEC)
                    self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                    return
                self.ip_fail_until.pop(target_ip, None)
                self.ws_pool.report_success((int(dc), bool(is_media), str(target_ip)))
                self._track(ws)
                try:
                    ws.send(init_packet)
                except:
                    try:
                        ws.close()
                    except:
                        pass
                    self._untrack(ws)
                    self._fallback(conn, dst, port, init_packet, dc, is_media, proto_int, allow_cf=not priority_cf_tried, streams=streams)
                    return
            splitter = None
            try:
                splitter = _TgWsMsgSplitter(init_packet, proto_int)
            except Exception:
                splitter = None
            healthy = self._bridge_ws_split(conn, ws, splitter, streams=streams)
            if not healthy:
                self._ws_fail_record(dc_key)
                self.ws_domain_pref.pop(dc_key, None)
            return
        except:
            pass
        finally:
            try:
                conn.close()
            except:
                pass
            self._untrack(conn)

__all__ = [name for name in globals() if not name.startswith("__")]

