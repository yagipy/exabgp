"""srv6sid.py

Created by Quentin De Muynck
Copyright (c) 2025 Exa Networks. All rights reserved.
"""

from __future__ import annotations

import json
from struct import unpack
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    pass

from exabgp.bgp.message.update.nlri.bgpls.nlri import BGPLS, PROTO_CODES
from exabgp.bgp.message.update.nlri.bgpls.tlvs.multitopology import MTID
from exabgp.bgp.message.update.nlri.bgpls.tlvs.node import NodeDescriptor
from exabgp.bgp.message.update.nlri.bgpls.tlvs.srv6sidinformation import Srv6SIDInformation
from exabgp.bgp.message.update.nlri.qualifier.path import PathInfo
from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher
from exabgp.util import hexstring
from exabgp.util.types import Buffer

# BGP-LS SRv6 SID TLV type codes (RFC 9514)
TLV_LOCAL_NODE_DESC: int = 256  # Local Node Descriptors TLV
TLV_MULTI_TOPO_ID: int = 263  # Multi-Topology Identifier TLV
TLV_SRV6_SID_INFO: int = 518  # SRv6 SID Information TLV

# Minimum TLV header size for validation
MIN_TLV_HEADER_SIZE: int = 2  # Type (2 bytes) + Length (2 bytes) = 4 bytes, checking for at least 2

#     RFC 9514: 6.  SRv6 SID NLRI
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+
#    |  Protocol-ID  |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                        Identifier                             |
#    |                        (8 octets)                             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |               Local Node Descriptors (variable)              //
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |               SRv6 SID Descriptors (variable)                //
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#                        Figure 5: SRv6 SID NLRI Format


@BGPLS.register_bgpls
class SRv6SID(BGPLS):
    CODE: ClassVar[int] = 6
    NAME: ClassVar[str] = 'bgpls-srv6sid'
    SHORT_NAME: ClassVar[str] = 'SRv6_SID'

    # Wire format offsets (after 4-byte header: type(2) + length(2))
    HEADER_SIZE: ClassVar[int] = 4
    PROTO_ID_OFFSET: ClassVar[int] = 4  # Byte 4: Protocol ID
    DOMAIN_OFFSET: ClassVar[int] = 5  # Bytes 5-12: Domain (8 bytes)
    TLV_OFFSET: ClassVar[int] = 13  # Bytes 13+: TLVs

    def __init__(
        self,
        packed: Buffer,
        addpath: PathInfo | None = None,
    ) -> None:
        """Create SRv6SID with complete wire format.

        Args:
            packed: Complete wire format including 4-byte header [type(2)][length(2)][payload]
            addpath: AddPath path identifier
        """
        BGPLS.__init__(self, addpath)
        self._packed = packed

    @property
    def proto_id(self) -> int:
        # Offset by 4-byte header: proto_id at byte 4
        value: int = unpack('!B', self._packed[4:5])[0]
        return value

    @property
    def domain(self) -> int:
        # Offset by 4-byte header: domain at bytes 5-12
        value: int = unpack('!Q', self._packed[5:13])[0]
        return value

    def _parse_tlvs(self) -> tuple[list[NodeDescriptor], dict[str, Any]]:
        """Parse TLVs from packed data."""
        proto_id = self.proto_id
        # Offset by 4-byte header: TLVs start at byte 13 (4 + 1 + 8)
        tlvs = self._packed[13:]

        node_type, node_length = unpack('!HH', tlvs[0:4])
        if node_type != TLV_LOCAL_NODE_DESC:
            return [], {}

        tlvs = tlvs[4:]
        local_node_data = tlvs[:node_length]
        node_ids: list[NodeDescriptor] = []
        while local_node_data:
            node_id, left = NodeDescriptor.unpack_node(local_node_data, proto_id)
            node_ids.append(node_id)
            if left == local_node_data:
                break
            local_node_data = left

        tlvs = tlvs[node_length:]
        srv6_sid_descriptors: dict[str, Any] = {}
        srv6_sid_descriptors['multi-topology-ids'] = []
        srv6_sid_descriptors['srv6-sids'] = []

        while tlvs:
            if len(tlvs) < MIN_TLV_HEADER_SIZE:
                break
            sid_type, sid_length = unpack('!HH', tlvs[:4])
            if sid_type == TLV_MULTI_TOPO_ID:
                srv6_sid_descriptors['multi-topology-ids'].append(MTID.unpack_mtid(tlvs[4 : sid_length + 4]).json())
            elif sid_type == TLV_SRV6_SID_INFO:
                srv6_sid_descriptors['srv6-sids'].append(
                    str(Srv6SIDInformation.unpack_srv6sid(tlvs[4 : sid_length + 4]))
                )
            else:
                if f'generic-tlv-{sid_type}' not in srv6_sid_descriptors:
                    srv6_sid_descriptors[f'generic-tlv-{sid_type}'] = []
                srv6_sid_descriptors[f'generic-tlv-{sid_type}'].append(hexstring(tlvs[4 : sid_length + 4]))

            tlvs = tlvs[sid_length + 4 :]

        return node_ids, srv6_sid_descriptors

    @property
    def local_node_descriptors(self) -> list[NodeDescriptor]:
        return self._parse_tlvs()[0]

    @property
    def srv6_sid_descriptors(self) -> dict[str, Any]:
        return self._parse_tlvs()[1]

    @classmethod
    def unpack_bgpls_nlri(cls, data: Buffer, rd: RouteDistinguisher | None) -> SRv6SID:
        """Unpack SRv6SID from complete wire format.

        Args:
            data: Complete wire format including 4-byte header [type(2)][length(2)][payload]
            rd: Route Distinguisher (ignored for SRv6SID - not supported)
        """
        # Data includes 4-byte header, payload starts at offset 4
        proto_id = unpack('!B', data[4:5])[0]
        if proto_id not in PROTO_CODES.keys():
            raise Exception(f'Protocol-ID {proto_id} is not valid')

        # Validate node descriptor TLV type
        # Offset by 4-byte header: TLVs start at byte 13 (4 + 1 + 8)
        tlvs = data[13:]
        node_type, node_length = unpack('!HH', tlvs[0:4])
        if node_type != TLV_LOCAL_NODE_DESC:
            raise Exception(
                f'Unknown type: {node_type}. Only Local Node descriptors are allowed inNode type msg',
            )

        # Validate node descriptors can be parsed
        tlvs = tlvs[4:]
        local_node_data = tlvs[:node_length]
        while local_node_data:
            _node_id, left = NodeDescriptor.unpack_node(local_node_data, proto_id)
            if left == local_node_data:
                raise RuntimeError('sub-calls should consume data')
            local_node_data = left

        # Validate SRv6 SID descriptors
        tlvs = tlvs[node_length:]
        while tlvs:
            if len(tlvs) < MIN_TLV_HEADER_SIZE:
                raise RuntimeError('SRv6 SID Descriptors are too short')
            _sid_type, sid_length = unpack('!HH', tlvs[:4])
            tlvs = tlvs[sid_length + 4 :]

        # Store complete wire format including header
        return cls(data)

    # pack_nlri inherited from BGPLS base class - returns self._packed directly

    def __len__(self) -> int:
        # _packed includes 4-byte header
        return len(self._packed)

    def __repr__(self) -> str:
        return f'{self.NAME}(protocol_id={self.proto_id}, domain={self.domain})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SRv6SID):
            return False
        # Direct _packed comparison - CODE, proto_id, domain, TLVs all encoded in wire format
        return self._packed == other._packed

    def __hash__(self) -> int:
        # Direct _packed hash - all wire fields encoded in bytes
        return hash(self._packed)

    @classmethod
    def from_settings(cls, settings: 'SRv6SIDSettings') -> 'SRv6SID':
        from struct import pack as struct_pack

        from exabgp.bgp.message.update.nlri.bgpls.tlvs.node import (
            IGP_ISIS_L1,
            IGP_ISIS_L2,
            IGP_OSPFV2,
            IGP_DIRECT,
            IGP_OSPFV3,
            IGP_STATIC,
            NODE_DESC_TLV_AS,
            NODE_DESC_TLV_BGPLS_ID,
            NODE_DESC_TLV_IGP_ROUTER,
        )
        from exabgp.protocol.ip import IPv6

        error = settings.validate()
        if error:
            raise ValueError(error)

        assert settings.protocol_id is not None
        assert settings.identifier is not None
        assert settings.local_node_descriptor is not None

        proto_id = settings.protocol_id
        ident = settings.identifier
        asn, bgpls_id, router_id = settings.local_node_descriptor

        _NON_ISIS_PROTO_IDS = (IGP_OSPFV2, IGP_DIRECT, IGP_OSPFV3, IGP_STATIC)
        if proto_id in (IGP_ISIS_L1, IGP_ISIS_L2):
            raise ValueError(
                'local-node-descriptor: IS-IS (protocol-id %d) requires a 6- or 7-byte '
                'ISO system-id which cannot be expressed as an IP address; '
                'IS-IS SRv6 SID announcement is not currently supported' % proto_id
            )
        if proto_id == 4:
            raise ValueError(
                'protocol-id 4 (direct) is not supported for SRv6 SID announcement: '
                'the NodeDescriptor decoder has no router-id handler for this protocol'
            )
        if proto_id in _NON_ISIS_PROTO_IDS and isinstance(router_id, IPv6):
            raise ValueError(
                'local-node-descriptor: protocol-id %d requires an IPv4 router-id '
                '(NodeDescriptor.unpack_node accepts only 4/8-byte Router-IDs for this protocol); '
                'got IPv6 address %s' % (proto_id, router_id)
            )

        sub = struct_pack('!HHL', NODE_DESC_TLV_AS, 4, asn) + struct_pack('!HHL', NODE_DESC_TLV_BGPLS_ID, 4, bgpls_id)
        rid_bytes = router_id.pack_ip()
        sub += struct_pack('!HH', NODE_DESC_TLV_IGP_ROUTER, len(rid_bytes)) + rid_bytes
        local_node_tlv = struct_pack('!HH', TLV_LOCAL_NODE_DESC, len(sub)) + sub

        mt_ids = settings.multi_topology_id
        if mt_ids:
            body = b''.join(struct_pack('!H', mt_id) for mt_id in mt_ids)
            mtid_tlv = struct_pack('!HH', TLV_MULTI_TOPO_ID, len(body)) + body
        else:
            mtid_tlv = b''

        sid_tlvs = b''.join(
            struct_pack('!HH', TLV_SRV6_SID_INFO, len(sid.pack_ip())) + sid.pack_ip()
            for sid in settings.srv6_sid_information
        )

        payload = struct_pack('!BQ', proto_id, ident) + local_node_tlv + mtid_tlv + sid_tlvs
        packed = struct_pack('!HH', cls.CODE, len(payload)) + payload
        return cls(packed)

    def json(self, announced: bool = True, compact: bool = False) -> str:
        nodes = ', '.join(d.json() for d in self.local_node_descriptors)
        content = ', '.join(
            [
                f'"ls-nlri-type": "{self.NAME}"',
                f'"l3-routing-topology": {int(self.domain)}',
                f'"protocol-id": {int(self.proto_id)}',
                f'"node-descriptors": [ {nodes} ]',
                f'"srv6-sid-descriptors": {json.dumps(self.srv6_sid_descriptors)}',
            ],
        )

        return f'{{ {content} }}'
