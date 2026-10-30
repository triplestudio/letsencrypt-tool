"""判断 DNS 记录是否已在「权威域名服务器」上生效。

为什么不只查公共 DNS：
8.8.8.8 / 223.5.5.5 这类递归解析器有缓存，可能返回旧值或旧的不存在结果。
CA 的校验器同样会缓存负结果，所以真正决定成败的是权威服务器上写没写进去。
这里先查域名的 NS，再逐台直接向权威服务器问 TXT，不经过任何缓存。
"""

from __future__ import annotations

import random
import socket
import struct
import time

from . import DnsError

TYPE = {"A": 1, "NS": 2, "CNAME": 5, "TXT": 16}
PUBLIC_RESOLVERS = ["223.5.5.5", "119.29.29.29", "180.76.76.76"]


# --------------------------------------------------------------------------- #
# 报文构造与解析
# --------------------------------------------------------------------------- #

def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if len(raw) > 63:
            raise DnsError("域名标签过长：%s" % label)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _build_query(name: str, qtype: str, tid: int) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", TYPE[qtype], 1)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end = offset
    jumped = False
    hops = 0
    while True:
        if offset >= len(data):
            raise ValueError("报文截断")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 20:
                raise ValueError("压缩指针成环")
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def _parse_message(data: bytes) -> dict:
    if len(data) < 12:
        raise ValueError("报文过短")
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4

    answers: list[dict] = []
    authorities: list[str] = []
    for index in range(ancount + nscount + arcount):
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        section = "answer" if index < ancount else "authority"

        if rtype == TYPE["TXT"] and section == "answer":
            parts, pos = [], 0
            while pos < len(rdata):
                size = rdata[pos]
                pos += 1
                parts.append(rdata[pos:pos + size].decode("utf-8", "replace"))
                pos += size
            answers.append({"name": name, "type": "TXT", "value": "".join(parts), "ttl": ttl})
        elif rtype == TYPE["CNAME"] and section == "answer":
            target, _ = _read_name(data, offset - rdlength)
            answers.append({"name": name, "type": "CNAME", "value": target, "ttl": ttl})
        elif rtype == TYPE["NS"]:
            target, _ = _read_name(data, offset - rdlength)
            if section == "answer":
                answers.append({"name": name, "type": "NS", "value": target, "ttl": ttl})
            else:
                authorities.append(target)

    return {
        "id": tid,
        "truncated": bool(flags & 0x0200),
        "rcode": flags & 0x000F,
        "answers": answers,
        "authority_ns": authorities,
    }


def _udp_query(name: str, qtype: str, server: str, timeout: float) -> dict:
    tid = random.randint(0, 0xFFFF)
    packet = _build_query(name, qtype, tid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return _parse_message(data)


def _tcp_query(name: str, qtype: str, server: str, timeout: float) -> dict:
    tid = random.randint(0, 0xFFFF)
    packet = _build_query(name, qtype, tid)
    with socket.create_connection((server, 53), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        head = sock.recv(2)
        if len(head) < 2:
            raise ValueError("TCP 响应不完整")
        size = struct.unpack("!H", head)[0]
        chunks, got = [], 0
        while got < size:
            chunk = sock.recv(size - got)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
    return _parse_message(b"".join(chunks))


def query(name: str, qtype: str, server: str, timeout: float = 4.0) -> dict:
    """向指定服务器查询，UDP 被截断时自动改走 TCP。"""
    try:
        result = _udp_query(name, qtype, server, timeout)
    except (socket.timeout, TimeoutError):
        raise DnsError(f"查询 {server} 超时", "Timeout")
    except OSError as exc:
        raise DnsError(f"无法连接 {server}: {exc}", "Network")
    if result.get("truncated"):
        result = _tcp_query(name, qtype, server, timeout)
    return result


# --------------------------------------------------------------------------- #
# 业务封装
# --------------------------------------------------------------------------- #

def resolve_ns(zone: str, timeout: float = 4.0) -> list[str]:
    """取域名的权威 NS 列表；查不到返回空列表。"""
    for server in PUBLIC_RESOLVERS:
        try:
            result = query(zone, "NS", server, timeout)
        except DnsError:
            continue
        names = [a["value"] for a in result["answers"] if a["type"] == "NS"]
        names += result.get("authority_ns") or []
        if names:
            return sorted({n.rstrip(".").lower() for n in names})
    return []


def zone_of(name: str, timeout: float = 4.0) -> tuple[str, list[str]]:
    """从记录名逐级向上找托管该域的 zone。"""
    labels = name.rstrip(".").split(".")
    for index in range(0, len(labels) - 1):
        candidate = ".".join(labels[index:])
        servers = resolve_ns(candidate, timeout)
        if servers:
            return candidate, servers
    return "", []


def authoritative_txt(name: str, timeout: float = 4.0,
                      max_cname_hops: int = 3) -> dict:
    """直接向权威服务器查 TXT。

    返回 {'values': [...], 'servers': [{'ns','ip','values','error'}]}。
    """
    name = name.rstrip(".").lower()
    zone, nameservers = zone_of(name, timeout)
    if not nameservers:
        raise DnsError(
            f"无法获取 {name} 的权威服务器地址", "NoNS",
            "本机 DNS 可能不可用；可稍后重试或在其他网络环境验证",
        )

    servers: list[dict] = []
    values: list[str] = []
    target = name
    for _hop in range(max_cname_hops + 1):
        answered = False
        for ns in nameservers:
            try:
                ips = [info[4][0] for info in socket.getaddrinfo(ns, 53, proto=socket.IPPROTO_UDP)]
            except Exception as exc:
                servers.append({"ns": ns, "ip": "", "values": [], "error": str(exc)})
                continue
            ip = ips[0]
            try:
                result = query(target, "TXT", ip, timeout)
            except DnsError as exc:
                servers.append({"ns": ns, "ip": ip, "values": [], "error": exc.message})
                continue
            answered = True
            got = [a["value"] for a in result["answers"] if a["type"] == "TXT"]
            cnames = [a["value"] for a in result["answers"] if a["type"] == "CNAME"]
            servers.append({"ns": ns, "ip": ip, "values": got, "error": ""})
            for value in got:
                if value not in values:
                    values.append(value)
            if not got and cnames:
                target = cnames[0].rstrip(".").lower()
        if answered or target == name:
            break

    return {"name": name, "zone": zone, "target": target, "values": values, "servers": servers}


def wait_for_txt(name: str, value, timeout: float = 180.0, interval: float = 5.0,
                 log=None) -> tuple[bool, dict]:
    """轮询直到权威服务器返回期望值，或超时。

    value 可以是单个字符串，也可以是列表——通配符与裸域同时申请时，同名记录上
    会有两条不同的值，必须都出现才放行。
    """
    deadline = time.time() + timeout
    last: dict = {"values": [], "servers": []}
    wanted = [value.strip()] if isinstance(value, str) else [v.strip() for v in value]
    while True:
        try:
            last = authoritative_txt(name)
        except DnsError as exc:
            if log:
                log(f"查询权威服务器失败：{exc.readable()}", "warn")
            last = {"values": [], "servers": [], "error": exc.message}
        else:
            hit = [v for v in wanted if v in last["values"]]
            if len(hit) == len(wanted):
                answered = [s for s in last["servers"] if s["values"] or not s["error"]]
                if log:
                    log(
                        "权威服务器已返回该记录：%s（%d 台应答）"
                        % (name, len(answered)),
                        "info",
                    )
                return True, last
            if log:
                detail = []
                for s in last["servers"]:
                    if s["error"]:
                        detail.append(f"{s['ns']} 不可达")
                    else:
                        detail.append(f"{s['ns']} 返回 {len(s['values'])} 条")
                if len(wanted) > 1:
                    detail.append(f"已看到 {len(hit)}/{len(wanted)} 条期望值")
                log(f"{name} 尚未生效（{'；'.join(detail) or '无应答'}），继续等待", "info")
        if time.time() > deadline:
            return False, last
        time.sleep(interval)
