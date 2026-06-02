"""
srv6sid.py

Created by Hiroyuki Yagihashi on 2025-03-15.
Copyright (c) 2025 Hiroyuki Yagihashi. All rights reserved.
License: 3-clause BSD. (See the COPYRIGHT file)
"""
from struct import pack, unpack

from exabgp.bgp.message.update.nlri import BGPLS
from exabgp.bgp.message.update.nlri.bgpls.tlvs.multitopology import MTID
from exabgp.bgp.message.update.nlri.bgpls.tlvs.node import NodeDescriptor
from exabgp.bgp.message.update.nlri.bgpls.tlvs.srv6sidinformation import SRv6SIDInformation

# SRv6 SID NLRI
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+
# |  Protocol-ID  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Identifier                             |
# |                        (8 octets)                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |               Local Node Descriptors (variable)              //
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |               SRv6 SID Descriptors (variable)                //
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


@BGPLS.register
class SRv6SID(BGPLS):
    CODE = 6
    NAME = 'bgpls-srv6-sid'
    SHORT_NAME = 'SRV6_SID'

    def __init__(
        self,
        proto_id,
        identifier,
        local_node_descriptor,
        srv6_sid_information=None,
        multi_topology_id=None,
        nexthop=None,
        action=None,
        addpath=None,
        packed=None
    ):
        BGPLS.__init__(self, action, addpath)
        self.proto_id = proto_id
        self.identifier = identifier
        self.local_node_descriptor = local_node_descriptor
        self.srv6_sid_information = srv6_sid_information
        self.multi_topology_id = multi_topology_id
        self.nexthop = nexthop
        self._packed = packed
        # TODO: 削除
        self.pack_srv6_sid(packed)

    # TODO: pack_nlriを実装
    # def pack_nlri(self, negotiated=None):
    #     return pack('!HH', self.CODE, len(self._packed)) + self._packed
    def pack_srv6_sid(self, packed=None):
        # if self._packed: # TODO: パース後にchange.nlri.pack_srv6_sid()してもこの実装があると更新されない
        #     return self._packed

        if packed:
            self._packed = packed
            return packed

        packed_srv6_sid_information = b''
        packed_multi_topology_id = b''

        if self.srv6_sid_information:
            packed_srv6_sid_information = self.srv6_sid_information.pack()

        if self.multi_topology_id:
            packed_multi_topology_id = self.multi_topology_id.pack()

        print("✅ SRv6SID pack_srv6_sid srv6_sid_information: ", self.srv6_sid_information)
        print("✅ SRv6SID pack_srv6_sid multi_topology_id: ", self.multi_topology_id)
        print("✅ SRv6SID pack_srv6_sid packed_srv6_sid_information: ", packed_srv6_sid_information.hex())
        print("✅ SRv6SID pack_srv6_sid packed_multi_topology_id: ", packed_multi_topology_id.hex())

        self._packed = (
            pack('!B', self.proto_id) +
            pack('!Q', self.identifier) +
            self.local_node_descriptor.pack() +
            packed_srv6_sid_information +
            packed_multi_topology_id
        )
        return self._packed

    @classmethod
    def unpack_nlri(cls, data, rd):
        proto_id = unpack('!B', data[:1])[0]
        identifier = unpack('!Q', data[1:9])[0]
        local_node_descriptor = None
        multi_topology_id = None
        srv6_sid_information = None
        tlvs = data[9:]

        while tlvs:
            tlv_type, tlv_length = unpack('!HH', tlvs[:4])
            value = tlvs[4 : 4 + tlv_length]
            tlvs = tlvs[4 + tlv_length :]

            if tlv_type == 256:
                local_node_descriptor = NodeDescriptor.unpack(value, proto_id)
                continue

            if tlv_type == 263:
                multi_topology_id = MTID.unpack(value)
                continue

            if tlv_type == 518:
                srv6_sid_information = SRv6SIDInformation.unpack(value)
                continue

        return cls(
            proto_id=proto_id,
            identifier=identifier,
            local_node_descriptor=local_node_descriptor,
            srv6_sid_information=srv6_sid_information,
            multi_topology_id=multi_topology_id,
        )

    def __eq__(self, other):
        return (
            isinstance(other, SRv6SID)
            and self.CODE == other.CODE
            and self.proto_id == other.proto_id
            and self.identifier == other.identifier
            and self.local_node_descriptor == other.local_node_descriptor
            and self.srv6_sid_information == other.srv6_sid_information
            and self.multi_topology_id == other.multi_topology_id
        )

    def __str__(self):
        return self.json()

    def json(self, compact=None):
        content = ', '.join(
            [
                '"protocol-id": %d' % int(self.proto_id),
                '"identifier": %d' % int(self.identifier),
                '"local-node-descriptor": [ %s ]' % self.local_node_descriptor.json()
            ]
        )
        if self.multi_topology_id:
            content += ', "multi-topology-ids": [ %s ]' % self.multi_topology_id.json()
        if self.srv6_sid_information:
            content += ', "srv6-sid-information": [ %s ]' % self.srv6_sid_information.json()

        return '{ %s }' % content
