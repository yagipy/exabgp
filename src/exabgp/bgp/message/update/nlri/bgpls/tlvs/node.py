# encoding: utf-8
"""
node.py

Created by Evelio Vila on 2016-11-26. eveliovila@gmail.com
Copyright (c) 2009-2017 Exa Networks. All rights reserved.
License: 3-clause BSD. (See the COPYRIGHT file)
"""

from struct import unpack, pack

from exabgp.protocol.ip import IP
from exabgp.protocol.iso import ISO

#           +--------------------+--------------------------+----------+
#           | Sub-TLV Code Point | Description              |   Length |
#           +--------------------+--------------------------+----------+
#           |        512         | Autonomous System        |        4 |
#           |        513         | BGP-LS Identifier        |        4 |
#           |        514         | OSPF Area-ID             |        4 |
#           |        515         | IGP Router-ID            | Variable |
#           |        516         | BGP Router-ID            |        4 |
#           |        517         | BGP Confederation Member |        4 |
#           +--------------------+--------------------------+----------+
#            https://tools.ietf.org/html/rfc7752#section-3.2.1.4
#            https://tools.ietf.org/html/rfc9086#section-6.2
# ================================================================== NODE-DESC-SUB-TLVs


class NodeDescriptorSub(object):
    _known_tlvs = {
        512: 'autonomous-system',
        513: 'bgp-ls-identifier',
        514: 'ospf-area-id',
        515: 'igp-router-id',
        516: 'bgp-router-id',
        517: 'bgp-confederation-member',
    }

    _error_tlvs = {
        512: 'Invalid autonomous-system sub-tlv',
        513: 'Invalid bgp-ls-identifier sub-tlv',
        514: 'Invalid ospf-area-id sub-tlv',
        515: 'Invalid igp-router-id sub-tlv',
        516: 'Invalid bgp-router-id sub-tlv',
        517: 'Invalid bgp-confederation-member sub-tlv',
    }

    def __init__(self, node_id, node_type, igp=None, psn=None, dr_id=None, packed=None):
        self.node_id = node_id
        self.node_type = node_type
        self.igp = igp
        self.psn = psn
        self.dr_id = dr_id
        self.packed_value = self.pack_value()
        self.value_length = len(self.packed_value)
        self._packed = packed
        self.pack()

    @classmethod
    def unpack(cls, data, igp):
        node_type, length = unpack('!HH', data[0:4])
        packed = data[: 4 + length]
        payload = packed[4:]
        remaining = data[4 + length :]

        node_id = None
        dr_id = None
        psn = None

        # autonomous-system
        if node_type == 512:
            if length != 4:
                raise Exception(cls._error_tlvs[node_type])
            node_id = unpack('!L', payload)[0]
            return cls(node_id, node_type, igp, psn, dr_id, packed), remaining

        # bgp-ls-id
        if node_type == 513:
            if length != 4:
                raise Exception(cls._error_tlvs[node_type])
            node_id = unpack('!L', payload)[0]
            return cls(node_id, node_type, igp, psn, dr_id, packed), remaining

        # ospf-area-id
        if node_type == 514:
            if length not in (4, 16):  # FIXME: it may only need to be 4
                raise Exception(cls._error_tlvs[node_type])
            node_id = IP.unpack(payload)
            return cls(node_id, node_type, igp, psn, dr_id, packed), remaining

        # IGP Router-ID: The TLV size in combination with the protocol
        # identifier enables the decoder to determine the node_typee
        # of the node: sec 3.2.1.4.
        if node_type == 515:
            # IS-IS non-pseudonode
            if igp in (1, 2):
                if length not in (6, 7):
                    raise Exception(cls._error_tlvs[node_type])
                node_id = (ISO.unpack_sysid(payload),)
                if length == 7:
                    psn = unpack('!B', payload[6:7])[0]
                return cls(node_id, node_type, igp, psn, dr_id, packed), remaining

            # OSPFv{2,3} non-pseudonode
            if igp in (3, 5, 6, 227):
                if length not in (4, 8):
                    raise Exception(cls._error_tlvs[node_type])
                node_id = (IP.unpack(payload[:4]),)
                if length == 8:
                    dr_id = IP.unpack(payload[4:8])
                return cls(node_id, node_type, igp, psn, dr_id, packed), remaining

        # BGP Router-ID
        if node_type == 516:
            if length != 4:
                raise Exception(cls._error_tlvs[node_type])
            node_id = IP.unpack(payload)
            return cls(node_id, node_type, igp, psn, dr_id, packed), remaining

        # BGP Confederation Member
        if node_type == 517:
            if length != 4:
                raise Exception(cls._error_tlvs[node_type])
            node_id = unpack('!I', payload)[0]
            return cls(node_id, node_type, igp, psn, dr_id, packed), remaining

        raise Exception(
            'unknown node descriptor sub-tlv ({}, {})'.format(
                f'node-type: {node_type}',
                f'igp: {igp}',
            )
        )

    def json(self, compact=None):
        node = None
        if self.node_type == 512:
            node = '"autonomous-system": %d' % self.node_id
        if self.node_type == 513:
            node = '"bgp-ls-identifier": "%d"' % self.node_id
        if self.node_type == 514:
            node = '"ospf-area-id": "%s"' % self.node_id
        if self.node_type == 515:
            node = '"igp-router-id": "%s"' % self.node_id
        if self.node_type == 516:
            node = '"bgp-router-id": "%s"' % self.node_id
        if self.node_type == 517:
            node = '"bgp-confederation-member": "%s"' % self.node_id
        designated = None
        if self.dr_id:
            designated = '"designated-router-id": "%s"' % self.dr_id
        psn = None
        if self.psn:
            psn = '"psn": "%s"' % self.psn
        content = ', '.join(_ for _ in [node, designated, psn] if _)
        return '{ %s }' % content

    def __eq__(self, other):
        return isinstance(other, NodeDescriptorSub) and self.node_id == other.node_id

    def __neq__(self, other):
        return self.node_id != other.node_id

    def __lt__(self, other):
        raise RuntimeError('Not implemented')

    def __le__(self, other):
        raise RuntimeError('Not implemented')

    def __gt__(self, other):
        raise RuntimeError('Not implemented')

    def __ge__(self, other):
        raise RuntimeError('Not implemented')

    def __str__(self):
        return self.json()

    def __repr__(self):
        return self.__str__()

    def __len__(self):
        return len(self._packed)

    def __hash__(self):
        return hash(str(self))

    def pack(self):
        if self._packed:
            return self._packed
        return pack('!HH', self.node_type, self.value_length) + self.packed_value

    def pack_value(self):
        if self.node_type == 512:
            return pack('!I', int(self.node_id))

        if self.node_type == 513:
            return pack('!I', int(self.node_id))

        if self.node_type == 514:
            return IP.pack(self.node_id)

        if self.node_type == 515:
            # IS-IS non-pseudonode
            if self.igp in (1, 2):
                if not (isinstance(self.node_id, tuple) and len(self.node_id) == 1):
                    raise Exception(self._error_tlvs[self.node_type])

                sysid = self.node_id[0]
                if self.psn is not None:
                    return sysid + pack('!B', self.psn)
                return sysid

            # OSPFv{2,3} non-pseudonode
            if self.igp in (3, 5, 6, 227):
                if not (isinstance(self.node_id, tuple) and len(self.node_id) == 1):
                    raise Exception(self._error_tlvs[self.node_type])

                rid = IP.pack(self.node_id[0])
                if self.dr_id is not None:
                    return rid + IP.pack(self.dr_id)
                return rid

        if self.node_type == 516:
            return IP.pack(self.node_id)

        if self.node_type == 517:
            return pack('!I', int(self.node_id))

        raise Exception(
            'unknown node descriptor sub-tlv ({}, {})'.format(
                f'node-type: {self.node_type}',
                f'igp: {self.igp}',
            )
        )


class NodeDescriptor(object):
    TYPE = 256
    def __init__(self, nodes):
        self.nodes = nodes
        self.length = sum(4 + node.value_length for node in self.nodes)

    def pack(self):
        return pack('!HH', self.TYPE, self.length) + b''.join(node.pack() for node in self.nodes)

    @classmethod
    def unpack(cls, data, igp):
        nodes = []
        while data:
            node, left = NodeDescriptorSub.unpack(data, igp)
            nodes.append(node)
            if data == left:
                raise RuntimeError('sub-calls should consume data')
            data = left
        return cls(nodes)

    def json(self):
        return ', '.join(node.json() for node in self.nodes)
