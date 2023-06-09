import struct
from abc import ABCMeta, abstractmethod


###################################################################################
# JSON FORMAT
###################################################################################
class PacketProtocolHelloOptions(metaclass=ABCMeta):
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              Type             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self, hello_type: str):
        self.type = hello_type

    @abstractmethod
    def bytes(self) -> bytes:
        """
        Obtain Protocol Hello Option in a format to be transmitted (JSON)
        This method will return the Hello Option in JSON format
        """
        pass

    def __len__(self):
        # not used
        return 0

    @staticmethod
    def parse_bytes(data: tuple, hello_type: int = None):
        """
        Parse received Hello Option from JSON and convert it into Hello object
        """
        hello_type = data[0]
        data = data[1]
        return JSON_MSG_TYPES.get(hello_type, PacketProtocolHelloUnknown).parse_bytes(data, hello_type)


class PacketProtocolHelloHoldtime(PacketProtocolHelloOptions):
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Hold Time          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    def __init__(self, holdtime: int or float):
        super().__init__(hello_type="HOLDTIME")
        self.holdtime = int(holdtime)

    def bytes(self) -> dict:
        """
        Obtain Protocol Hello HoldTime Option in a format to be transmitted (JSON)
        This method will return the Hello Option in JSON format
        """
        return {"HOLDTIME": self.holdtime}

    @staticmethod
    def parse_bytes(data, hello_type: int = None):
        """
        Parse received Hello Option HoldTime from JSON and convert it into Hello object
        """
        if hello_type is None:
            raise Exception
        holdtime = data
        return PacketProtocolHelloHoldtime(holdtime=holdtime)



class PacketProtocolHelloCheckpointSN(PacketProtocolHelloOptions):
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Checkpoint SN                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self, checkpoint_sn: int):
        super().__init__(hello_type="CHECKPOINT_SN")
        self.checkpoint_sn = checkpoint_sn

    def bytes(self) -> dict:
        """
        Obtain Protocol Hello Option CheckpointSN in a format to be transmitted (JSON)
        This method will return the Hello Option in JSON format
        """
        return {"CHECKPOINT_SN": self.checkpoint_sn}

    @staticmethod
    def parse_bytes(data, hello_type: int = None):
        """
        Parse received Hello Option CheckpointSN from JSON and convert it into Hello object
        """
        if hello_type is None:
            raise Exception
        checkpoint_sn = data
        return PacketProtocolHelloCheckpointSN(checkpoint_sn=checkpoint_sn)


class PacketProtocolHelloUnknown(PacketProtocolHelloOptions):
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Unknown                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self, hello_type):
        super().__init__(hello_type=hello_type)

    def bytes(self) -> bytes:
        """
        Unknown options are not transmitted... Throw exception
        """
        raise Exception

    @staticmethod
    def parse_bytes(data, hello_type: int = None):
        """
        In case the received Hello Option is unknown parse its content (get to know the length of this option
        in order to parse following options)
        """
        if hello_type is None:
            raise Exception
        return PacketProtocolHelloUnknown(hello_type)


JSON_MSG_TYPES = {"HOLDTIME": PacketProtocolHelloHoldtime,
                  "CHECKPOINT_SN": PacketProtocolHelloCheckpointSN,
                 }



class PacketNewProtocolHelloOptions(metaclass=ABCMeta):
    TYPE = "UNKNOWN"
    PIM_HDR_OPTS = "! HH"
    PIM_HDR_OPTS_LEN = struct.calcsize(PIM_HDR_OPTS)
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              Type             |             Length            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self, hello_type: int, length: int):
        self.type = hello_type
        self.length = length

    def bytes(self) -> bytes:
        """
        Obtain Protocol Hello Option in a format to be transmitted (binary)
        This method will return the Hello Option in binary format
        """
        return struct.pack(PacketNewProtocolHelloOptions.PIM_HDR_OPTS, self.type, self.length)

    def __len__(self):
        return self.PIM_HDR_OPTS_LEN + self.length

    @staticmethod
    def parse_bytes(data: bytes, hello_type: int = None, length: int = None):
        """
        Parse received Hello Option from binary and convert it into Hello object
        """
        (hello_type, length) = struct.unpack(PacketNewProtocolHelloOptions.PIM_HDR_OPTS,
                                        data[:PacketNewProtocolHelloOptions.PIM_HDR_OPTS_LEN])
        #print("hello_type:", type)
        #print("LENGTH:", length)
        data = data[PacketNewProtocolHelloOptions.PIM_HDR_OPTS_LEN:]
        #return PIM_MSG_TYPES[type](data)
        return NEW_PROTOCOL_MSG_TYPES.get(hello_type, PacketNewProtocolHelloUnknown).parse_bytes(data, hello_type, length)


class PacketNewProtocolHelloHoldtime(PacketNewProtocolHelloOptions):
    TYPE = "HOLDTIME"
    PIM_HDR_OPT = "! H"
    PIM_HDR_OPT_LEN = struct.calcsize(PIM_HDR_OPT)
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Hold Time          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self, holdtime: int or float):
        super().__init__(hello_type=1, length=2)
        self.holdtime = int(holdtime)

    def bytes(self) -> bytes:
        """
        Obtain Protocol Hello HoldTime Option in a format to be transmitted (binary)
        This method will return the Hello Option in binary format
        """
        return super().bytes() + struct.pack(self.PIM_HDR_OPT, self.holdtime)

    @staticmethod
    def parse_bytes(data: bytes, hello_type: int = None, length: int = None):
        """
        Parse received Hello Option HoldTime from binary and convert it into Hello object
        """
        if hello_type is None or length is None:
            raise Exception
        (holdtime, ) = struct.unpack(PacketNewProtocolHelloHoldtime.PIM_HDR_OPT, data[:length])
        #print("HOLDTIME:", holdtime)
        return PacketNewProtocolHelloHoldtime(holdtime=holdtime)


class PacketNewProtocolHelloCheckpointSN(PacketNewProtocolHelloOptions):
    TYPE = "CHECKPOINT_SN"
    PIM_HDR_OPT = "! L"
    PIM_HDR_OPT_LEN = struct.calcsize(PIM_HDR_OPT)
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Checkpoint SN                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self, checkpoint_sn: int):
        super().__init__(hello_type=2, length=4)
        self.checkpoint_sn = checkpoint_sn

    def bytes(self) -> bytes:
        """
        Obtain Protocol Hello CheckpointSN Option in a format to be transmitted (binary)
        This method will return the Hello Option in binary format
        """
        return super().bytes() + struct.pack(self.PIM_HDR_OPT, self.checkpoint_sn)

    @staticmethod
    def parse_bytes(data: bytes, hello_type: int = None, length: int = None):
        """
        Parse received Hello Option ChekpointSN from binary and convert it into Hello object
        """
        if hello_type is None or length is None:
            raise Exception
        (checkpoint_sn, ) = struct.unpack(PacketNewProtocolHelloCheckpointSN.PIM_HDR_OPT, data[:length])
        #print("CheckpointSN:", checkpoint_sn)
        return PacketNewProtocolHelloCheckpointSN(checkpoint_sn=checkpoint_sn)


class PacketNewProtocolHelloUnknown(PacketNewProtocolHelloOptions):
    TYPE = "UNKNOWN"
    PIM_HDR_OPT = "! L"
    PIM_HDR_OPT_LEN = struct.calcsize(PIM_HDR_OPT)
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Unknown                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    def __init__(self, hello_type, length):
        super().__init__(hello_type=hello_type, length=length)
        #print("PIM Hello Option Unknown... TYPE=", type, "LENGTH=", length)

    def bytes(self) -> bytes:
        """
        Unknown options are not transmitted... Throw exception
        """
        raise Exception

    @staticmethod
    def parse_bytes(data: bytes, hello_type: int = None, length: int = None):
        """
        In case the received Hello Option is unknown parse its content (get to know the length of this option
        in order to parse following options)
        """
        if hello_type is None or length is None:
            raise Exception
        return PacketNewProtocolHelloUnknown(hello_type, length)


NEW_PROTOCOL_MSG_TYPES = {1: PacketNewProtocolHelloHoldtime,
                          2: PacketNewProtocolHelloCheckpointSN,
                         }