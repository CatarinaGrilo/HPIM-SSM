import struct
import socket

from .PacketProtocolHelloOptions import PacketNewProtocolHelloOptions, PacketProtocolHelloOptions
###########################################################################################################
# JSON FORMAT
###########################################################################################################
class PacketProtocolHelloSyncMetric():
    def __init__(self, metric_preference, metric):
        self.metric = metric
        self.metric_preference = metric_preference

    def bytes(self):
        """
        Obtain metric of Protocol Sync in a format to be transmitted (JSON)
        """
        msg = {"METRIC": self.metric,
               "METRIC_PREFERENCE": self.metric_preference,
              }

        return msg

    @staticmethod
    def parse_bytes(data: bytes):
        """
        Parse received metric of Protocol Sync Packet from JSON format
        and convert it into ProtocolSyncMetric object and PacketProtocolSyncMetric
        """
        metric = data["METRIC"]
        metric_preference = data["METRIC_PREFERENCE"]
        return PacketProtocolHelloSyncEntry(metric_preference, metric)


class PacketProtocolHelloSyncEntry():
    def __init__(self, metric_flag,source, group, assert_metric = []):
        self.metric_flag = metric_flag
        self.source = source
        self.group = group
        self.assert_metric = assert_metric

    def bytes(self):
        """
        Obtain entry of Protocol Sync in a format to be transmitted (JSON)
        """
        metric = []
        for m in self.assert_metric:
            metric.append(m.bytes())

        msg = {"METRIC_FLAG": self.metric_flag,
               "SOURCE": self.source,
               "GROUP": self.group,
               "ASSERT_METRIC": metric
              }

        return msg

    @staticmethod
    def parse_bytes(data: bytes):
        """
        Parse received entry of Protocol Sync Packet from JSON format
        and convert it into ProtocolSyncEntry object and PacketProtocolSyncEntries
        """
        metric = []
        for m in data["ASSERT_METRIC"]:
            metric.append(PacketProtocolHelloSyncMetric.parse_bytes(m))

        metric_flag = data["METRIC_FLAG"]
        source = data["SOURCE"]
        group = data["GROUP"]
        return PacketProtocolHelloSyncEntry(metric_flag, source, group, metric)


class PacketProtocolHelloSync():
    PIM_TYPE = "SYNC"

    def __init__(self, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, upstream_trees=[],
                 master_flag=False, more_flag=False, neighbor_boot_time=0):
        self.sync_sequence_number = sync_sn
        self.my_snapshot_sn = my_snapshot_sn
        self.neighbor_snapshot_sn = neighbor_snapshot_sn
        self.neighbor_boot_time = neighbor_boot_time
        self.upstream_trees = upstream_trees
        self.master_flag = master_flag
        self.more_flag = more_flag
        self.options = {}

    def add_hello_option(self, option: 'PacketNewProtocolHelloOptions'):
        self.options[option.type] = option

    def get_hello_options(self):
        return self.options

    def bytes(self) -> bytes:
        """
        Obtain Protocol Sync Packet in a format to be transmitted (JSON)
        """
        trees = []
        for entry in self.upstream_trees:
            trees.append(entry.bytes())

        msg = {"SYNC_SN": self.sync_sequence_number,
               "MY_SNAPSHOT_SN": self.my_snapshot_sn,
               "NEIGHBOR_SNAPSHOT_SN": self.neighbor_snapshot_sn,
               "NEIGHBOR_BOOT_TIME": self.neighbor_boot_time,
               "TREES": trees,
               "MASTER_FLAG": self.master_flag,
               "MORE_FLAG": self.more_flag,
               "HELLO_OPTIONS": {}
              }
        for hello_option in self.options.values():
            msg["HELLO_OPTIONS"].update(hello_option.bytes())

        return msg

    def parse_bytes(data: bytes):
        """
        Parse received Protocol Sync Packet and all its entries from JSON format
        and convert it into ProtocolSync object and PacketProtocolSyncEntries
        """
        trees = []
        for entry in data["TREES"]:
            trees.append(PacketProtocolHelloSyncEntry.parse_bytes(entry))

        sync_sn = data["SYNC_SN"]
        my_snapshot_sn = data["MY_SNAPSHOT_SN"]
        neighbor_snapshot_sn = data["NEIGHBOR_SNAPSHOT_SN"]
        neighbor_boot_time = data["NEIGHBOR_BOOT_TIME"]
        master_flag = data["MASTER_FLAG"]
        more_flag = data["MORE_FLAG"]
        hello_options = data["HELLO_OPTIONS"]
        sync_msg = PacketProtocolHelloSync(my_snapshot_sn, neighbor_snapshot_sn, sync_sn, trees, master_flag,
                                           more_flag, neighbor_boot_time)
        for (key, value) in hello_options.items():
            option = PacketProtocolHelloOptions.parse_bytes((key, value))
            sync_msg.add_hello_option(option)

        return sync_msg


###########################################################################################################
# BINARY FORMAT
###########################################################################################################
'''
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Metric Preference                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Metric                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''
class PacketNewProtocolSyncMetric():
    PIM_HDR_SYNC_METRIC = "! L L"
    PIM_HDR_SYNC_METRIC_LEN = struct.calcsize(PIM_HDR_SYNC_METRIC)


    def __init__(self, metric_preference, metric):
        self.metric = metric
        self.metric_preference = metric_preference

    def __len__(self):
        return PacketNewProtocolSyncMetric.PIM_HDR_SYNC_METRIC_LEN

    def bytes(self):
        """
        Obtain entry of Protocol Sync in a format to be transmitted (binary)
        """
        msg = struct.pack(PacketNewProtocolSyncMetric.PIM_HDR_SYNC_METRIC, self.metric_preference, self.metric)
        return msg

    @staticmethod
    def parse_bytes(data: bytes):
        """
        Parse received entry of Protocol Sync Packet from binary format
        and convert it into ProtocolSyncEntry object and PacketProtocolSyncEntries
        """
        (metric_preference, metric) = struct.unpack(
            PacketNewProtocolSyncMetric.PIM_HDR_SYNC_METRIC,
            data[:PacketNewProtocolSyncMetric.PIM_HDR_SYNC_METRIC_LEN])
        return PacketNewProtocolSyncMetric(metric_preference, metric)


'''
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           metric_flag                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Tree Source IP                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Tree Group IP                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Assert Metric                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''
class PacketNewProtocolSyncEntry():
    PIM_HDR_SYNC_ENTRY = "! h 4s 4s"
    PIM_HDR_SYNC_ENTRY_LEN = struct.calcsize(PIM_HDR_SYNC_ENTRY)


    def __init__(self, metric_flag, source, group, assert_metric):
        if type(source) not in (str, bytes) or type(group) not in (str, bytes):
            raise Exception
        if type(source) is bytes:
            source = socket.inet_ntoa(source)
        if type(group) is bytes:
            group = socket.inet_ntoa(group)

        self.metric_flag = metric_flag
        self.source = source
        self.group = group
        self.assert_metric = assert_metric

    def add_metric(self, m):
        self.assert_metric.append(m)

    def bytes(self) -> bytes:
        """
        Obtain entry of Protocol Sync in a format to be transmitted (binary)
        """
        msg = struct.pack(PacketNewProtocolSyncEntry.PIM_HDR_SYNC_ENTRY, self.metric_flag, socket.inet_aton(self.source),
                          socket.inet_aton(self.group))
        if self.metric_flag:
            msg += self.assert_metric[0].bytes()
        return msg

    def __len__(self):
        return len(self.bytes())
    
    @staticmethod
    def parse_bytes(data: bytes):
        """
        Parse received entry of Protocol Sync Packet from binary format
        and convert it into ProtocolSyncEntry object and PacketProtocolSyncEntries
        """
        (metric_flag, source, group) = struct.unpack(
            PacketNewProtocolSyncEntry.PIM_HDR_SYNC_ENTRY,
            data[:PacketNewProtocolSyncEntry.PIM_HDR_SYNC_ENTRY_LEN])
        
        data = data[PacketNewProtocolSyncEntry.PIM_HDR_SYNC_ENTRY_LEN:]
        entry_msg = PacketNewProtocolSyncEntry(metric_flag, source, group, [])

        if metric_flag:
            metric_msg = PacketNewProtocolSyncMetric.parse_bytes(data)
            entry_msg.add_metric(metric_msg)
        return entry_msg


'''
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         MySnapshotSN                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      NeighborSnapshotSN                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       NeighborBootTime                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|M|m|                        Sync SN                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Trees (equivalent to multiple IamUpstream messages)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''
class PacketNewProtocolSync:
    PIM_TYPE = 1

    PIM_HDR_INSTALL_WITHOUT_TREES = "! L L L L"
    PIM_HDR_INSTALL_WITHOUT_TREES_LEN = struct.calcsize(PIM_HDR_INSTALL_WITHOUT_TREES)

    def __init__(self, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, upstream_trees,
                 master_flag=False, more_flag=False, neighbor_boot_time=0):
        self.my_snapshot_sn = my_snapshot_sn
        self.neighbor_snapshot_sn = neighbor_snapshot_sn
        self.neighbor_boot_time = neighbor_boot_time
        self.sync_sequence_number = sync_sn
        self.master_flag = master_flag
        self.more_flag = more_flag
        self.upstream_trees = upstream_trees
        self.options = {}

    def add_tree(self, t):
        self.upstream_trees.append(t)

    def add_hello_option(self, option: 'PacketNewProtocolHelloOptions'):
        self.options[option.TYPE] = option

    def get_hello_options(self):
        return self.options

    def bytes(self) -> bytes:
        """
        Obtain entry of Protocol Sync in a format to be transmitted (binary)
        """
        flags_and_sync_sn = (self.master_flag << 31) | (self.more_flag << 30) | self.sync_sequence_number

        msg = struct.pack(PacketNewProtocolSync.PIM_HDR_INSTALL_WITHOUT_TREES, self.my_snapshot_sn,
                          self.neighbor_snapshot_sn, self.neighbor_boot_time, flags_and_sync_sn)
        if self.more_flag:
            for t in self.upstream_trees:
                msg += t.bytes()
        else:
            for option in self.options.values():
                msg += option.bytes()
        return msg

    def __len__(self):
        return len(self.bytes())

    @staticmethod
    def parse_bytes(data: bytes):
        """
        Parse received Protocol Sync Packet and all its entries from binary format
        and convert it into ProtocolSync object and PacketProtocolSyncEntries
        """
        (my_snapshot_sn, neighbor_snapshot_sn, neighbor_boot_time, flags_and_sync_sn) = \
            struct.unpack(PacketNewProtocolSync.PIM_HDR_INSTALL_WITHOUT_TREES,
                          data[:PacketNewProtocolSync.PIM_HDR_INSTALL_WITHOUT_TREES_LEN])

        sync_sn = flags_and_sync_sn & 0x3FFFFFFF
        master_flag = flags_and_sync_sn >> 31
        more_flag = (flags_and_sync_sn & 0x4FFFFFFF) >> 30
        data = data[PacketNewProtocolSync.PIM_HDR_INSTALL_WITHOUT_TREES_LEN:]
        sync_msg = PacketNewProtocolSync(my_snapshot_sn, neighbor_snapshot_sn, sync_sn, [], master_flag=master_flag,
                                         more_flag=more_flag, neighbor_boot_time=neighbor_boot_time)
        if more_flag:
            while data != b'':
                tree_msg = PacketNewProtocolSyncEntry.parse_bytes(data)

                sync_msg.add_tree(tree_msg)
                data = data[len(tree_msg):]
        else:
            while data != b'':
                option = PacketNewProtocolHelloOptions.parse_bytes(data)
                option_length = len(option)
                data = data[option_length:]
                sync_msg.add_hello_option(option)
        return sync_msg