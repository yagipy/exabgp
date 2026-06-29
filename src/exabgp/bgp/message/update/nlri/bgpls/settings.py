"""bgpls/settings.py

Created by Hiroyuki Yagihashi on 2026-06-07.
Copyright (c) 2026 Hiroyuki Yagihashi. All rights reserved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from exabgp.bgp.message.action import Action
from exabgp.protocol.family import AFI, SAFI
from exabgp.protocol.ip import IP

if TYPE_CHECKING:
    from exabgp.protocol.ip import IPv6


@dataclass
class SRv6SIDSettings:
    """Settings for SRv6 SID NLRI (RFC 9514) construction.

    Collects all fields needed to build a BGP-LS SRv6 SID NLRI,
    with final validation performed in SRv6SID.from_settings().

    Attributes:
        action: Route action (ANNOUNCE or WITHDRAW)
        afi: Address Family Identifier (injected by validator)
        safi: Subsequent Address Family Identifier (injected by validator)
        nexthop: Next-hop IP address
        protocol_id: BGP-LS protocol identifier (required)
        identifier: 64-bit BGP-LS domain identifier (required)
        local_node_descriptor: (asn, bgp-ls-id, router-id) tuple (required)
        srv6_sid_information: List of SRv6 SID IPv6 addresses (optional)
        multi_topology_id: List of multi-topology IDs 0-4095 (optional)
    """

    action: Action = field(default=Action.UNSET)
    afi: AFI | None = None
    safi: SAFI | None = None
    nexthop: IP = field(default_factory=lambda: IP.NoNextHop)
    protocol_id: int | None = None
    identifier: int | None = None
    local_node_descriptor: tuple[int, int, IP] | None = None
    srv6_sid_information: list[IPv6] = field(default_factory=list)
    multi_topology_id: list[int] = field(default_factory=list)

    def set(self, name: str, value: Any) -> None:
        setattr(self, name, value)

    def validate(self) -> str:
        if self.protocol_id is None:
            return 'bgp-ls nlri protocol-id missing'
        if self.identifier is None:
            return 'bgp-ls nlri identifier missing'
        if self.local_node_descriptor is None:
            return 'bgp-ls nlri local-node-descriptor missing'
        if self.nexthop is IP.NoNextHop:
            return 'bgp-ls nlri next-hop missing'
        return ''
