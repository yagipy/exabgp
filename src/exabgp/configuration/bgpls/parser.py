"""configuration/bgpls/parser.py

Created by Hiroyuki Yagihashi on 2026-06-07.
Copyright (c) 2026 Hiroyuki Yagihashi. All rights reserved.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from exabgp.protocol.ip import IP, IPv6
from exabgp.bgp.message.update.nlri.bgpls.nlri import PROTO_CODES

if TYPE_CHECKING:
    from exabgp.configuration.core.parser import Tokeniser

_ASN_MAX: int = 4294967295
_BGPLS_ID_MAX: int = 4294967295
_IDENTIFIER_MAX: int = 18446744073709551615
_MT_ID_MAX: int = 4095  # 12-bit per RFC 7752 §3.2.1.5


def _require(raw: str | None, field: str) -> str:
    if not raw:
        raise ValueError('%s: missing value' % field)
    return raw


def protocol_id(tokeniser: Tokeniser) -> int:
    value = int(_require(tokeniser(), 'protocol-id'))
    if value not in PROTO_CODES:
        raise ValueError('protocol-id %d is not valid; must be one of %s' % (value, sorted(PROTO_CODES)))
    return value


def identifier(tokeniser: Tokeniser) -> int:
    value = int(_require(tokeniser(), 'identifier'))
    if not (0 <= value <= _IDENTIFIER_MAX):
        raise ValueError('identifier %d out of range [0, %d]' % (value, _IDENTIFIER_MAX))
    return value


def local_node_descriptor(tokeniser: Tokeniser) -> tuple[int, int, IP]:
    value = _require(tokeniser(), 'local-node-descriptor')
    if value != '(':
        raise ValueError('local-node-descriptor: expected ( but got %s' % value)
    asn = int(_require(tokeniser(), 'local-node-descriptor asn'))
    if not (0 <= asn <= _ASN_MAX):
        raise ValueError('local-node-descriptor: asn %d out of range [0, %d]' % (asn, _ASN_MAX))
    bgpls_id = int(_require(tokeniser(), 'local-node-descriptor bgp-ls-id'))
    if not (0 <= bgpls_id <= _BGPLS_ID_MAX):
        raise ValueError('local-node-descriptor: bgp-ls-id %d out of range [0, %d]' % (bgpls_id, _BGPLS_ID_MAX))
    try:
        router_id = IP.from_string(_require(tokeniser(), 'local-node-descriptor router-id'))
    except (ValueError, OSError) as exc:
        raise ValueError('local-node-descriptor: invalid router-id: %s' % exc) from exc
    end = _require(tokeniser(), 'local-node-descriptor closing )')
    if end != ')':
        raise ValueError('local-node-descriptor: expected ) but got %s' % end)
    return asn, bgpls_id, router_id


def _parse_ipv6_sid(raw: str) -> IPv6:
    try:
        ip = IP.from_string(raw)
    except (ValueError, OSError) as exc:
        raise ValueError('srv6-sid-information: invalid address %r: %s' % (raw, exc)) from exc
    if not isinstance(ip, IPv6):
        raise ValueError('srv6-sid-information: %r is not an IPv6 address; SRv6 SIDs must be IPv6' % raw)
    return ip


def _validated_mt_id(raw: str) -> int:
    try:
        mt_id = int(raw)
    except ValueError as exc:
        raise ValueError('multi-topology-id: expected integer, got %r' % raw) from exc
    if not (0 <= mt_id <= _MT_ID_MAX):
        raise ValueError('multi-topology-id %d out of range [0, %d]' % (mt_id, _MT_ID_MAX))
    return mt_id


def srv6_sid_information(tokeniser: Tokeniser) -> list[IPv6]:
    sids: list[IPv6] = []
    value = _require(tokeniser(), 'srv6-sid-information')
    if value == '[':
        while True:
            value = _require(tokeniser(), 'srv6-sid-information list item or ]')
            if value == ']':
                break
            sids.append(_parse_ipv6_sid(value))
    else:
        sids.append(_parse_ipv6_sid(value))
    return sids


def multi_topology_id(tokeniser: Tokeniser) -> list[int]:
    ids: list[int] = []
    value = _require(tokeniser(), 'multi-topology-id')
    if value == '[':
        while True:
            value = _require(tokeniser(), 'multi-topology-id list item or ]')
            if value == ']':
                break
            ids.append(_validated_mt_id(value))
    else:
        ids.append(_validated_mt_id(value))
    return ids
