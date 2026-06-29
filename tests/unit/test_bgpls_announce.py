#!/usr/bin/env python3
# encoding: utf-8

"""Tests for BGP-LS SRv6 SID announcement (RFC 9514)

Tests:
- configuration/bgpls/parser.py  — tokeniser parsing functions
- configuration/announce/bgpls.py — wire format building and Route creation
"""

import pytest
from struct import unpack

from exabgp.protocol.family import AFI, SAFI
from exabgp.protocol.ip import IP, IPv6

from exabgp.bgp.message.update.nlri.bgpls.srv6sid import SRv6SID
from exabgp.bgp.message.update.nlri.bgpls.settings import SRv6SIDSettings  # noqa: F401
from exabgp.bgp.message.update.nlri.bgpls.tlvs.node import NODE_DESC_TLV_IGP_ROUTER

from exabgp.configuration.announce import ParseAnnounce
from exabgp.configuration.announce.bgpls import AnnounceBGPLS  # noqa: F401
from exabgp.configuration.announce.route_builder import _build_route  # noqa: F401
from exabgp.configuration.bgpls.parser import (
    identifier,
    local_node_descriptor,
    multi_topology_id,
    protocol_id,
    srv6_sid_information,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeTokeniser:
    """Minimal tokeniser stub for configuration parser testing."""

    def __init__(self, tokens: list[str]) -> None:
        self._tokens = iter(tokens)
        self.announce = True
        self.afi = AFI.bgpls

    def __call__(self) -> str:
        try:
            return next(self._tokens)
        except StopIteration:
            return ''  # matches real Tokeniser._get() behaviour on EOF


def _build_bgpls(tokeniser):
    return _build_route(tokeniser, AnnounceBGPLS.schema, AFI.bgpls, SAFI.bgp_ls)


# ---------------------------------------------------------------------------
# configuration/bgpls/parser.py
# ---------------------------------------------------------------------------


class TestProtocolId:
    def test_parses_valid_static(self) -> None:
        t = FakeTokeniser(['5'])
        assert protocol_id(t) == 5  # static

    def test_parses_valid_ospf(self) -> None:
        t = FakeTokeniser(['3'])
        assert protocol_id(t) == 3  # ospf_v2

    def test_parses_valid_freertr(self) -> None:
        t = FakeTokeniser(['227'])
        assert protocol_id(t) == 227

    def test_zero_raises(self) -> None:
        t = FakeTokeniser(['0'])
        with pytest.raises(ValueError, match='not valid'):
            protocol_id(t)

    def test_invalid_value_raises(self) -> None:
        t = FakeTokeniser(['255'])
        with pytest.raises(ValueError, match='not valid'):
            protocol_id(t)

    def test_out_of_proto_codes_raises(self) -> None:
        t = FakeTokeniser(['10'])
        with pytest.raises(ValueError, match='not valid'):
            protocol_id(t)

    def test_eof_raises_value_error(self) -> None:
        """Missing value should raise ValueError, not TypeError."""
        t = FakeTokeniser([])
        with pytest.raises(ValueError):
            protocol_id(t)


class TestIdentifier:
    def test_parses_integer(self) -> None:
        t = FakeTokeniser(['1'])
        assert identifier(t) == 1

    def test_parses_zero(self) -> None:
        t = FakeTokeniser(['0'])
        assert identifier(t) == 0

    def test_parses_max_value(self) -> None:
        val = 2**64 - 1
        t = FakeTokeniser([str(val)])
        assert identifier(t) == val

    def test_overflow_raises(self) -> None:
        val = 2**64
        t = FakeTokeniser([str(val)])
        with pytest.raises(ValueError, match='out of range'):
            identifier(t)


class TestLocalNodeDescriptor:
    def test_parses_tuple(self) -> None:
        t = FakeTokeniser(['(', '65000', '1', '10.0.0.1', ')'])
        asn, bgpls_id, router_id = local_node_descriptor(t)
        assert asn == 65000
        assert bgpls_id == 1
        assert str(router_id) == '10.0.0.1'

    def test_parses_ipv6_router_id(self) -> None:
        t = FakeTokeniser(['(', '65001', '100', '2001:db8::1', ')'])
        asn, bgpls_id, router_id = local_node_descriptor(t)
        assert asn == 65001
        assert bgpls_id == 100
        assert str(router_id) == '2001:db8::1'

    def test_asn_overflow_raises(self) -> None:
        t = FakeTokeniser(['(', str(2**32), '1', '10.0.0.1', ')'])
        with pytest.raises(ValueError, match='asn.*out of range'):
            local_node_descriptor(t)

    def test_bgpls_id_overflow_raises(self) -> None:
        t = FakeTokeniser(['(', '65000', str(2**32), '10.0.0.1', ')'])
        with pytest.raises(ValueError, match='bgp-ls-id.*out of range'):
            local_node_descriptor(t)

    def test_missing_open_paren_raises(self) -> None:
        t = FakeTokeniser(['65000', '1', '10.0.0.1', ')'])
        with pytest.raises(ValueError, match='expected \\('):
            local_node_descriptor(t)

    def test_missing_close_paren_raises(self) -> None:
        t = FakeTokeniser(['(', '65000', '1', '10.0.0.1', 'extra'])
        with pytest.raises(ValueError, match='expected \\)'):
            local_node_descriptor(t)


class TestSrv6SidInformation:
    def test_parses_single_sid(self) -> None:
        t = FakeTokeniser(['2001:db8::1'])
        sids = srv6_sid_information(t)
        assert len(sids) == 1
        assert str(sids[0]) == '2001:db8::1'

    def test_parses_multiple_sids(self) -> None:
        t = FakeTokeniser(['[', '2001:db8::1', 'fc00::1', ']'])
        sids = srv6_sid_information(t)
        assert len(sids) == 2
        assert str(sids[0]) == '2001:db8::1'
        assert str(sids[1]) == 'fc00::1'

    def test_parses_empty_list(self) -> None:
        t = FakeTokeniser(['[', ']'])
        sids = srv6_sid_information(t)
        assert sids == []

    def test_ipv4_raises(self) -> None:
        t = FakeTokeniser(['192.0.2.1'])
        with pytest.raises(ValueError, match='not an IPv6 address'):
            srv6_sid_information(t)

    def test_ipv4_in_list_raises(self) -> None:
        t = FakeTokeniser(['[', '2001:db8::1', '10.0.0.1', ']'])
        with pytest.raises(ValueError, match='not an IPv6 address'):
            srv6_sid_information(t)

    def test_eof_in_list_raises_value_error(self) -> None:
        """Unterminated list should raise ValueError, not TypeError."""
        t = FakeTokeniser(['[', '2001:db8::1'])  # missing ]
        with pytest.raises(ValueError):
            srv6_sid_information(t)

    def test_invalid_ip_raises_value_error(self) -> None:
        """OSError from inet_pton on out-of-range IP must be wrapped as ValueError."""
        t = FakeTokeniser(['999.0.0.1'])
        with pytest.raises(ValueError):
            srv6_sid_information(t)


class TestMultiTopologyId:
    def test_parses_single_id(self) -> None:
        t = FakeTokeniser(['0'])
        ids = multi_topology_id(t)
        assert ids == [0]

    def test_parses_max_id(self) -> None:
        t = FakeTokeniser(['4095'])
        ids = multi_topology_id(t)
        assert ids == [4095]

    def test_parses_list(self) -> None:
        t = FakeTokeniser(['[', '0', '1', '2', ']'])
        ids = multi_topology_id(t)
        assert ids == [0, 1, 2]

    def test_parses_empty_list(self) -> None:
        t = FakeTokeniser(['[', ']'])
        ids = multi_topology_id(t)
        assert ids == []

    def test_out_of_range_raises(self) -> None:
        t = FakeTokeniser(['4096'])
        with pytest.raises(ValueError, match='out of range'):
            multi_topology_id(t)

    def test_out_of_range_in_list_raises(self) -> None:
        t = FakeTokeniser(['[', '0', '70000', ']'])
        with pytest.raises(ValueError, match='out of range'):
            multi_topology_id(t)

    def test_eof_in_list_raises_value_error(self) -> None:
        """Unterminated list should raise ValueError, not TypeError."""
        t = FakeTokeniser(['[', '0'])  # missing ]
        with pytest.raises(ValueError):
            multi_topology_id(t)

    def test_non_integer_raises(self) -> None:
        """Non-numeric token should raise with a descriptive message."""
        t = FakeTokeniser(['abc'])
        with pytest.raises(ValueError, match='expected integer'):
            multi_topology_id(t)


# ---------------------------------------------------------------------------
# _bgpls_srv6sid end-to-end
# ---------------------------------------------------------------------------


class TestBgplsSrv6Sid:
    def _make_tokeniser(self, extra: list[str] | None = None) -> FakeTokeniser:
        tokens = [
            'protocol-id',
            '5',
            'identifier',
            '1',
            'origin',
            'igp',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'srv6-sid-information',
            '[',
            '2001:db8::1',
            ']',
            'multi-topology-id',
            '[',
            '0',
            ']',
            'next-hop',
            '10.0.0.2',
        ]
        return FakeTokeniser(tokens + (extra or []))

    def test_returns_one_route(self) -> None:
        routes = _build_bgpls(self._make_tokeniser())
        assert len(routes) == 1

    def test_nexthop(self) -> None:
        routes = _build_bgpls(self._make_tokeniser())
        assert str(routes[0].nexthop) == '10.0.0.2'

    def test_nlri_type(self) -> None:
        routes = _build_bgpls(self._make_tokeniser())
        assert isinstance(routes[0].nlri, SRv6SID)

    def test_nlri_protocol_id(self) -> None:
        routes = _build_bgpls(self._make_tokeniser())
        assert routes[0].nlri.proto_id == 5

    def test_nlri_domain(self) -> None:
        routes = _build_bgpls(self._make_tokeniser())
        assert routes[0].nlri.domain == 1

    def test_nlri_json_contains_node_descriptors(self) -> None:
        routes = _build_bgpls(self._make_tokeniser())
        j = routes[0].nlri.json()
        assert '"autonomous-system": 65000' in j
        assert '"bgp-ls-identifier"' in j
        assert '"router-id": "10.0.0.1"' in j

    def test_nlri_json_contains_srv6_sid(self) -> None:
        routes = _build_bgpls(self._make_tokeniser())
        j = routes[0].nlri.json()
        assert '2001:db8::1' in j
        assert 'srv6-sids' in j

    def test_nlri_json_contains_mtid(self) -> None:
        routes = _build_bgpls(self._make_tokeniser())
        j = routes[0].nlri.json()
        assert 'multi-topology-ids' in j

    def test_without_optional_fields(self) -> None:
        tokens = [
            'protocol-id',
            '5',
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'next-hop',
            '10.0.0.2',
        ]
        routes = _build_bgpls(FakeTokeniser(tokens))
        assert len(routes) == 1
        assert routes[0].nlri.proto_id == 5
        j = routes[0].nlri.json()
        # Empty lists must still be present in the JSON output
        assert '"srv6-sids": []' in j
        assert '"multi-topology-ids": []' in j

    def test_ospfv2_ipv4_router_id_round_trip(self) -> None:
        """OSPFv2 (protocol-id 3) with IPv4 router-id should pack and round-trip."""
        tokens = [
            'protocol-id',
            '3',  # OSPFv2
            'identifier',
            '42',
            'local-node-descriptor',
            '(',
            '65001',
            '2',
            '192.168.0.1',
            ')',
            'srv6-sid-information',
            '[',
            'fc00::1',
            ']',
            'next-hop',
            '10.0.0.1',
        ]
        routes = _build_bgpls(FakeTokeniser(tokens))
        assert len(routes) == 1
        nlri = routes[0].nlri
        assert isinstance(nlri, SRv6SID)
        assert nlri.proto_id == 3
        assert nlri.domain == 42
        reparsed = SRv6SID.unpack_bgpls_nlri(nlri._packed, None)
        assert reparsed._packed == nlri._packed
        # Verify the decoded router-id is preserved
        router_ids = [
            str(nd.node_id[0]) for nd in reparsed.local_node_descriptors if nd.node_type == NODE_DESC_TLV_IGP_ROUTER
        ]
        assert '192.168.0.1' in router_ids

    def test_unknown_command_raises(self) -> None:
        tokens = [
            'protocol-id',
            '5',
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'next-hop',
            '10.0.0.2',
            'unknown-field',
            'value',
        ]
        with pytest.raises(ValueError, match='[Uu]nknown command'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_missing_protocol_id_raises(self) -> None:
        tokens = [
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'next-hop',
            '10.0.0.2',
        ]
        with pytest.raises(ValueError, match='protocol-id'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_missing_identifier_raises(self) -> None:
        tokens = [
            'protocol-id',
            '5',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'next-hop',
            '10.0.0.2',
        ]
        with pytest.raises(ValueError, match='identifier'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_missing_local_node_descriptor_raises(self) -> None:
        tokens = [
            'protocol-id',
            '5',
            'identifier',
            '1',
            'next-hop',
            '10.0.0.2',
        ]
        with pytest.raises(ValueError, match='local-node-descriptor'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_missing_next_hop_raises(self) -> None:
        tokens = [
            'protocol-id',
            '5',
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
        ]
        with pytest.raises(ValueError, match='next-hop'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_isis_l1_raises(self) -> None:
        """IS-IS system-ids cannot be expressed as IP addresses."""
        tokens = [
            'protocol-id',
            '1',  # IS-IS Level 1
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'next-hop',
            '10.0.0.2',
        ]
        with pytest.raises(ValueError, match='IS-IS'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_isis_l2_raises(self) -> None:
        """IS-IS Level 2 also unsupported — same limitation."""
        tokens = [
            'protocol-id',
            '2',  # IS-IS Level 2
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '2001:db8::1',
            ')',
            'next-hop',
            '10.0.0.2',
        ]
        with pytest.raises(ValueError, match='IS-IS'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_direct_proto_id_raises(self) -> None:
        """Protocol-id 4 (direct) has no NodeDescriptor decoder handler."""
        tokens = [
            'protocol-id',
            '4',
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'next-hop',
            '10.0.0.2',
        ]
        with pytest.raises(ValueError, match='protocol-id 4'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_direct_proto_id_ipv6_router_id_raises(self) -> None:
        """Protocol-id 4 with IPv6 router-id also raises (hits the direct guard first)."""
        tokens = [
            'protocol-id',
            '4',
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '2001:db8::1',
            ')',
            'next-hop',
            '10.0.0.2',
        ]
        with pytest.raises(ValueError, match='protocol-id 4'):
            _build_bgpls(FakeTokeniser(tokens))

    def test_ospf_ipv6_router_id_raises(self) -> None:
        """OSPF protocol-ids reject IPv6 router-ids (only 4/8-byte supported)."""
        for pid in ('3', '5', '6', '227'):
            tokens = [
                'protocol-id',
                pid,
                'identifier',
                '1',
                'local-node-descriptor',
                '(',
                '65000',
                '1',
                '2001:db8::1',
                ')',
                'next-hop',
                '10.0.0.2',
            ]
            with pytest.raises(ValueError, match='IPv4 router-id'):
                _build_bgpls(FakeTokeniser(tokens))

    def test_wire_format_round_trip(self) -> None:
        """Pack → SRv6SID → unpack_bgpls_nlri → compare bytes and decoded SID."""
        routes = _build_bgpls(self._make_tokeniser())
        nlri = routes[0].nlri
        assert isinstance(nlri, SRv6SID)

        reparsed = SRv6SID.unpack_bgpls_nlri(nlri._packed, None)
        assert reparsed.proto_id == nlri.proto_id
        assert reparsed.domain == nlri.domain
        assert reparsed._packed == nlri._packed
        # Verify the decoded SID value is preserved through the round-trip
        assert reparsed.srv6_sid_descriptors['srv6-sids'] == ['2001:db8::1']

    def test_mtid_single_tlv_format(self) -> None:
        """Multiple MT-IDs produce a single TLV per RFC 7752 §3.2.1.5."""
        tokens = [
            'protocol-id',
            '5',
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'multi-topology-id',
            '[',
            '0',
            '1',
            '2',
            ']',
            'next-hop',
            '10.0.0.2',
        ]
        routes = _build_bgpls(FakeTokeniser(tokens))
        nlri = routes[0].nlri
        j = nlri.json()
        assert 'multi-topology-ids' in j
        # Verify round-trip with the RFC-correct single-TLV encoding
        reparsed = SRv6SID.unpack_bgpls_nlri(nlri._packed, None)
        assert reparsed._packed == nlri._packed


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestBgplsRegistration:
    def test_family_registered(self) -> None:
        """bgpls_bgp_ls is registered for AFI.bgpls / SAFI.bgp_ls."""
        key = (AFI.bgpls.name(), SAFI.bgp_ls.name())
        assert key in ParseAnnounce.known, f'bgp-ls/bgp-ls family not registered in ParseAnnounce.known (key={key!r})'

    def test_registered_handler_returns_routes(self) -> None:
        tokens = [
            'protocol-id',
            '5',
            'identifier',
            '1',
            'local-node-descriptor',
            '(',
            '65000',
            '1',
            '10.0.0.1',
            ')',
            'next-hop',
            '10.0.0.2',
        ]
        handler = ParseAnnounce.known[(AFI.bgpls.name(), SAFI.bgp_ls.name())]
        routes = handler(FakeTokeniser(tokens))
        assert len(routes) == 1
        assert isinstance(routes[0].nlri, SRv6SID)
