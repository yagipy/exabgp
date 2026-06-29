"""announce/bgpls.py

Created by Hiroyuki Yagihashi on 2026-06-07.
Copyright (c) 2026 Hiroyuki Yagihashi. All rights reserved.
"""

from __future__ import annotations

from exabgp.rib.route import Route

from exabgp.protocol.family import AFI
from exabgp.protocol.family import SAFI

from exabgp.bgp.message.update.nlri.bgpls.srv6sid import SRv6SID
from exabgp.bgp.message.update.nlri.bgpls.settings import SRv6SIDSettings

from exabgp.configuration.announce import ParseAnnounce
from exabgp.configuration.announce.route_builder import _build_route
from exabgp.configuration.core import Parser
from exabgp.configuration.core import Tokeniser
from exabgp.configuration.core import Scope
from exabgp.configuration.core import Error
from exabgp.configuration.schema import ActionKey
from exabgp.configuration.schema import ActionOperation
from exabgp.configuration.schema import ActionTarget
from exabgp.configuration.schema import Leaf
from exabgp.configuration.schema import RouteBuilder
from exabgp.configuration.schema import ValueType
from exabgp.configuration.validator import LegacyParserValidator
from exabgp.configuration.static.parser import next_hop as static_next_hop
from exabgp.configuration.static.parser import origin as static_origin

from exabgp.configuration.bgpls.parser import identifier as parse_identifier
from exabgp.configuration.bgpls.parser import local_node_descriptor as parse_local_node_descriptor
from exabgp.configuration.bgpls.parser import multi_topology_id as parse_multi_topology_id
from exabgp.configuration.bgpls.parser import protocol_id as parse_protocol_id
from exabgp.configuration.bgpls.parser import srv6_sid_information as parse_srv6_sid_information


class AnnounceBGPLS(ParseAnnounce):
    schema = RouteBuilder(
        description='BGP-LS SRv6 SID announcement',
        nlri_class=SRv6SID,
        settings_class=SRv6SIDSettings,
        prefix_parser=None,
        assign={
            'protocol-id': 'protocol_id',
            'identifier': 'identifier',
            'local-node-descriptor': 'local_node_descriptor',
            'srv6-sid-information': 'srv6_sid_information',
            'multi-topology-id': 'multi_topology_id',
        },
        children={
            'protocol-id': Leaf(
                type=ValueType.INTEGER,
                description='BGP-LS protocol identifier (3=OSPFv2, 5=Static, 6=OSPFv3, 227=freertr)',
                target=ActionTarget.NLRI,
                operation=ActionOperation.SET,
                key=ActionKey.FIELD,
                validator=LegacyParserValidator(parser_func=parse_protocol_id, name='protocol-id'),
            ),
            'identifier': Leaf(
                type=ValueType.INTEGER,
                description='64-bit BGP-LS domain identifier',
                target=ActionTarget.NLRI,
                operation=ActionOperation.SET,
                key=ActionKey.FIELD,
                validator=LegacyParserValidator(parser_func=parse_identifier, name='identifier'),
            ),
            'local-node-descriptor': Leaf(
                type=ValueType.STRING,
                description='Local node descriptor: ( asn bgp-ls-id router-id )',
                target=ActionTarget.NLRI,
                operation=ActionOperation.SET,
                key=ActionKey.FIELD,
                validator=LegacyParserValidator(parser_func=parse_local_node_descriptor, name='local-node-descriptor'),
            ),
            'srv6-sid-information': Leaf(
                type=ValueType.STRING,
                description='SRv6 SID IPv6 address(es): <ipv6> | [ <ipv6> ... ]',
                target=ActionTarget.NLRI,
                operation=ActionOperation.SET,
                key=ActionKey.FIELD,
                validator=LegacyParserValidator(parser_func=parse_srv6_sid_information, name='srv6-sid-information'),
            ),
            'multi-topology-id': Leaf(
                type=ValueType.INTEGER,
                description='Multi-topology identifier(s) 0-4095: <int> | [ <int> ... ]',
                target=ActionTarget.NLRI,
                operation=ActionOperation.SET,
                key=ActionKey.FIELD,
                validator=LegacyParserValidator(parser_func=parse_multi_topology_id, name='multi-topology-id'),
            ),
            'next-hop': Leaf(
                type=ValueType.NEXT_HOP,
                description='Next-hop IP address',
                target=ActionTarget.NEXTHOP_ATTRIBUTE,
                operation=ActionOperation.SET,
                key=ActionKey.COMMAND,
                validator=LegacyParserValidator(parser_func=static_next_hop, name='next-hop', accepts_afi=True),
            ),
            'origin': Leaf(
                type=ValueType.ORIGIN,
                description='BGP origin attribute (IGP|EGP|INCOMPLETE)',
                target=ActionTarget.ATTRIBUTE,
                operation=ActionOperation.ADD,
                key=ActionKey.NAME,
                validator=LegacyParserValidator(parser_func=static_origin, name='origin'),
            ),
        },
    )

    name = 'bgp-ls'
    afi: AFI = AFI.bgpls

    @property
    def syntax(self) -> str:
        defn = ' ;\n   '.join(self.schema.definition)
        return f'bgp-ls {{\n   bgp-ls {defn}\n}}'

    def __init__(self, parser: Parser, scope: Scope, error: Error) -> None:
        ParseAnnounce.__init__(self, parser, scope, error)

    def clear(self) -> None:
        pass

    def pre(self) -> bool:
        self.scope.to_context(self.name)
        return True

    def post(self) -> bool:
        return ParseAnnounce.post(self) and self._check()

    @staticmethod
    def check(route: Route, afi: AFI | None) -> bool:
        return True


@ParseAnnounce.register_family(AFI.bgpls, SAFI.bgp_ls, ActionTarget.SCOPE, ActionOperation.EXTEND, ActionKey.NAME)
def bgpls_bgp_ls(tokeniser: Tokeniser) -> list[Route]:
    return _build_route(tokeniser, AnnounceBGPLS.schema, AFI.bgpls, SAFI.bgp_ls)
