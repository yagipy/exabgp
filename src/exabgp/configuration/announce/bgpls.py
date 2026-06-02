"""
announce/bgpls.py

Created by Hiroyuki Yagihashi on 2025-03-15.
Copyright (c) 2025 Hiroyuki Yagihashi. All rights reserved.
License: 3-clause BSD. (See the COPYRIGHT file)
"""
from exabgp.bgp.message import Action
from exabgp.configuration.static.parser import origin
from exabgp.rib.change import Change

from exabgp.bgp.message.update.attribute import Attributes

from exabgp.configuration.announce import ParseAnnounce

from exabgp.configuration.bgpls.parser import srv6_sid
from exabgp.configuration.bgpls.parser import srv6_sid_information
from exabgp.configuration.bgpls.parser import multi_topology_id
from exabgp.configuration.bgpls.parser import next_hop


class AnnounceBGPLSSAFI(ParseAnnounce):
    definition = [
        'srv6-sid <protocol id; 8 bits number> <identifier; 64 bits number> ( <asn> <bgp ls identifier; 32 bits number> <ip> <confederation member; 32 bits number> )',
        'origin IGP|EGP|INCOMPLETE',
        'srv6-sid-information [ <ipv6>.. ]',
        'multi-topology-id [ <mt id; 16 bits number>.. ]',
        'next-hop <ip>',
    ]

    syntax = 'bgp-ls %s\n' % '  '.join(definition)

    known = {
        'origin': origin,
        'srv6-sid-information': srv6_sid_information,
        'multi-topology-id': multi_topology_id,
        'next-hop': next_hop,
    }

    action = {
        'origin': 'attribute-add',
        'srv6-sid-information': 'nlri-set',
        'multi-topology-id': 'nlri-set',
        'next-hop': 'nexthop-and-attribute',
    }

    assign = {
        'srv6-sid-information': 'srv6_sid_information',
        'multi-topology-id': 'multi_topology_id',
    }

    def __init__(self, tokeniser, scope, error):
        ParseAnnounce.__init__(self, tokeniser, scope, error)

    def clear(self):
        return True

    def post(self):
        return self._check()

    @staticmethod
    def check(change, afi):
        return True


def bgpls(tokeniser):
    bgpls_type = tokeniser()
    if 'srv6-sid' == bgpls_type:
        bgpls_nlri = srv6_sid(tokeniser, Action.ANNOUNCE)
    else:
        raise ValueError('bgp-ls: unknown bgp-ls type: %s' % bgpls_type)

    change = Change(bgpls_nlri, Attributes())

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

    # TODO: 削除
    if bgpls_type == 'srv6-sid':
        change.nlri.pack_srv6_sid()
    return [change]


@ParseAnnounce.register('bgp-ls', 'extend-name', 'bgp-ls')
def bgpls_bgpls(tokeniser):
    return bgpls(tokeniser)
