"""
announce/bgpls.py

Created by Hiroyuki Yagihashi on 2025-03-15.
Copyright (c) 2025 Hiroyuki Yagihashi. All rights reserved.
License: 3-clause BSD. (See the COPYRIGHT file)
"""
from exabgp.bgp.message import Action
from exabgp.configuration.static.parser import origin
from exabgp.rib.change import Change

from exabgp.protocol.family import AFI
from exabgp.protocol.family import SAFI

from exabgp.bgp.message.update.attribute import Attributes

from exabgp.configuration.announce import ParseAnnounce

from exabgp.configuration.bgpls.parser import protocol_id
from exabgp.configuration.bgpls.parser import identifier
from exabgp.configuration.bgpls.parser import local_node_descriptor
from exabgp.configuration.bgpls.parser import srv6_sid_information
from exabgp.configuration.bgpls.parser import multi_topology_id
from exabgp.configuration.bgpls.parser import next_hop
from exabgp.bgp.message.update.nlri.bgpls.srv6sid import SRv6SID


class AnnounceBGPLSSAFI(ParseAnnounce):
    definition = [
        'protocol-id <protocol id; 8 bits number>',
        'identifier <identifier; 64 bits number>',
        'origin IGP|EGP|INCOMPLETE',
        'local-node-descriptor ( <asn> <bgp ls identifier; 32 bits number> <ip> <confederation member; 32 bits number> )',
        'srv6-sid-information [ <ipv6>.. ]',
        'multi-topology-id [ <mt id; 16 bits number>.. ]',
        'next-hop <ip>',
    ]

    syntax = 'bgp-ls %s\n' % '  '.join(definition)

    known = {
        'protocol-id': protocol_id,
        'identifier': identifier,
        'origin': origin,
        'local-node-descriptor': local_node_descriptor,
        'srv6-sid-information': srv6_sid_information,
        'multi-topology-id': multi_topology_id,
        'next-hop': next_hop,
    }

    action = {
        'protocol-id': 'nlri-set',
        'identifier': 'nlri-set',
        'origin': 'attribute-add',
        'local-node-descriptor': 'nlri-set',
        'srv6-sid-information': 'nlri-set',
        'multi-topology-id': 'nlri-set',
        'next-hop': 'nexthop-and-attribute',
    }

    assign = {
        'protocol-id': 'proto_id',
        'identifier': 'identifier',
        'local-node-descriptor': 'local_node_descriptor',
        'srv6-sid-information': 'srv6_sid_information',
        'multi-topology-id': 'multi_topology_id',
    }

    name = 'bgp-ls'
    afi = None

    def __init__(self, tokeniser, scope, error):
        ParseAnnounce.__init__(self, tokeniser, scope, error)

    def clear(self):
        return True

    def post(self):
        return self._check()

    @staticmethod
    def check(change, afi):
        return True


def bgpls(tokeniser, afi, safi):
    change = Change(SRv6SID(None, None, None, action=Action.ANNOUNCE), Attributes())

    while True:
        command = tokeniser()
        if not command:
            break

        action = AnnounceBGPLSSAFI.action[command]
        if 'nlri-set' in action:
            change.nlri.assign(AnnounceBGPLSSAFI.assign[command], AnnounceBGPLSSAFI.known[command](tokeniser))
        elif 'attribute-add' in action:
            change.attributes.add(AnnounceBGPLSSAFI.known[command](tokeniser))
        elif action == 'nexthop-and-attribute':
            nexthop, attribute = AnnounceBGPLSSAFI.known[command](tokeniser)
            change.nlri.nexthop = nexthop
            change.attributes.add(attribute)
        else:
            raise ValueError('bgp-ls: unknown command "%s"' % command)

    change.nlri._pack() # TODO: 削除、proto_idやidentifierがNoneのままだとpackできない
    return [
        change,
    ]


@ParseAnnounce.register('bgp-ls', 'extend-name', 'bgp-ls')
def bgpls_bgpls(tokeniser):
    return bgpls(tokeniser, AFI.bgpls, SAFI.bgp_ls)
