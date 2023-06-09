from tree.protocol_globals import MSG_FORMAT
from utils import TYPE_CHECKING

from .Packet import Packet
from .PacketIGMPHeader import PacketIGMPHeader
from .PacketIpHeader import PacketIpHeader

if TYPE_CHECKING:
    from Interface import Interface

if MSG_FORMAT == "BINARY":
    from .PacketProtocolHeader import PacketNewProtocolHeader as PacketProtocolHeader
else:
    from .PacketProtocolHeader import PacketProtocolHeader


class ReceivedPacket(Packet):
    # choose payload protocol class based on ip protocol number
    payload_protocol = {2: PacketIGMPHeader, 103: PacketProtocolHeader}

    def __init__(self, raw_packet: bytes, interface: 'Interface'):
        self.interface = interface
        # Parse ao packet e preencher objeto Packet

        packet_ip_hdr = raw_packet[:PacketIpHeader.IP_HDR_LEN]
        ip_header = PacketIpHeader.parse_bytes(packet_ip_hdr)
        protocol_number = ip_header.proto

        packet_without_ip_hdr = raw_packet[ip_header.hdr_length:]
        payload = ReceivedPacket.payload_protocol[protocol_number].parse_bytes(packet_without_ip_hdr)

        super().__init__(ip_header=ip_header, payload=payload)