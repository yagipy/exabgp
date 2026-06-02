"""
bgpls/parser.py

Created by Hiroyuki Yagihashi on 2025-03-15.
Copyright (c) 2025 Hiroyuki Yagihashi. All rights reserved.
License: 3-clause BSD. (See the COPYRIGHT file)
"""
from exabgp.bgp.message.update.nlri.bgpls.srv6sid import SRv6SID
from exabgp.bgp.message.update.nlri.bgpls.tlvs.multitopology import MTID
from exabgp.bgp.message.update.nlri.bgpls.tlvs.node import NodeDescriptorSub, NodeDescriptor
from exabgp.bgp.message.update.nlri.bgpls.tlvs.srv6sidinformation import SRv6SIDInformation
from exabgp.protocol.family import AFI

from exabgp.protocol.ip import IP, IPSelf
from exabgp.bgp.message.update.attribute import NextHopSelf, NextHop


def srv6_sid(tokeniser, action):
    proto_id = int(tokeniser())
    identifier = int(tokeniser())
    value = tokeniser()
    if value == '(':
        as_number = int(tokeniser())
        bgp_ls_identifier = int(tokeniser())
        router_id = IP.create(tokeniser())
        confederation_member = int(tokeniser())
        tokeniser()
        node_descriptor = NodeDescriptor([
            NodeDescriptorSub(as_number, 512),
            NodeDescriptorSub(bgp_ls_identifier, 513),
            NodeDescriptorSub(router_id, 516),
            NodeDescriptorSub(confederation_member, 517),
        ])
    else:
        raise ValueError('invalid local node descriptor')

    return SRv6SID(
        proto_id,
        identifier,
        node_descriptor,
        action=action,
    )

def srv6_sid_information(tokeniser):
    sids = []

    value = tokeniser()
    if value == '[':
        while True:
            value = tokeniser()
            if value == ']':
                break
            sids.append(IP.create(value))
    else:
        sids.append(IP.create(value))

    return SRv6SIDInformation(sids)

def multi_topology_id(tokeniser):
    ids = []

    value = tokeniser()
    if value == '[':
        while True:
            value = tokeniser()
            if value == ']':
                break
            ids.append(int(value))
    else:
        ids.append(int(value))
    return MTID(ids)

def next_hop(tokeniser, afi=None):
    value = tokeniser()
    if value.lower() == 'self':
        return IPSelf(tokeniser.afi), NextHopSelf(tokeniser.afi)
    else:
        ip = IP.create(value)
        if ip.afi == AFI.ipv4 and afi == AFI.ipv6:
            ip = IP.create('::ffff:%s' % ip)
        return ip, NextHop(ip.top())
