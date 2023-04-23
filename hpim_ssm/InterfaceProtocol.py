import hashlib
import hmac
import logging
import random
import socket
import time
import traceback
from threading import Timer, RLock


import netifaces
import Main
from Interface import Interface
from Neighbor import Neighbor
from Packet.Packet import Packet
from Packet.ReceivedPacket import ReceivedPacket
from ReliableMsgTransmission import ReliableMessageTransmission
from tree.protocol_globals import MSG_FORMAT, HELLO_HOLD_TIME_TIMEOUT

from Neighbor import Synced

if MSG_FORMAT == "BINARY":
    from Packet.PacketProtocolHelloOptions import PacketNewProtocolHelloHoldtime as PacketProtocolHelloHoldtime, \
        PacketNewProtocolHelloCheckpointSN as PacketProtocolHelloCheckpointSN
    from Packet.PacketProtocolHello import PacketNewProtocolHello as PacketProtocolHello
    from Packet.PacketProtocolHeader import PacketNewProtocolHeader as PacketProtocolHeader
    from Packet.PacketProtocolSync import PacketNewProtocolSyncEntry as PacketProtocolHelloSyncEntry, \
        PacketNewProtocolSync as PacketProtocolHelloSync
    from Packet.PacketProtocolInterest import PacketNewProtocolPrune as PacketProtocolPrune, \
        PacketNewProtocolJoin as PacketProtocolJoin
    from Packet.PacketProtocolAssert import PacketNewProtocolAssert as PacketProtocolAssert
    from Packet.PacketProtocolAck import PacketNewProtocolAck as PacketProtocolAck
else:
    from Packet.PacketProtocolHelloOptions import PacketProtocolHelloHoldtime, PacketProtocolHelloCheckpointSN
    from Packet.PacketProtocolHello import PacketProtocolHello
    from Packet.PacketProtocolHeader import PacketProtocolHeader
    from Packet.PacketProtocolSync import PacketProtocolHelloSync
    from Packet.PacketProtocolAssert import PacketProtocolAssert
    from Packet.PacketProtocolInterest import PacketProtocolPrune, PacketProtocolJoin
    from Packet.PacketProtocolSync import PacketProtocolHelloSyncEntry
    from Packet.PacketProtocolAck import PacketProtocolAck



class InterfaceProtocol(Interface):
    MCAST_GRP = '224.0.0.13'

    MAX_SEQUENCE_NUMBER = (2 ** 32 - 1)  # 45 <- test with lower MAXIMUM_SEQUENCE_NUMBER

    HELLO_PERIOD = 30
    TRIGGERED_HELLO_PERIOD = 5

    LOGGER = logging.getLogger('protocol.Interface')

    def __init__(self, interface_name: str, vif_index: int):
        self.interface_logger = logging.LoggerAdapter(InterfaceProtocol.LOGGER, {'vif': vif_index,
                                                                                 'interfacename': interface_name})

        # Generate BootTime
        self.time_of_boot = int(time.time())

        # Regulate transmission of Hello messages
        self.hello_timer = None

        # protocol neighbors
        self._had_neighbors = False
        self.neighbors = {}
        self.neighbors_lock = RLock()

        # reliable transmission buffer
        self.reliable_transmission_buffer = {}  # Key: ID da msg ; value: ReliableMsgTransmission
        self.reliable_transmission_lock = RLock()

        # sequencer for msg reliability
        self.sequencer = 0
        self.sequencer_lock = RLock()

        # security
        self.security_id = 0
        self.security_len = 0
        self.hash_function = None
        self.security_key = b''

        #igmp
        self.igmp_interest = {}

        # SOCKET
        ip_interface = netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['addr']
        self.ip_interface = ip_interface

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_PIM)

        # allow other sockets to bind this port too
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # explicitly join the multicast group on the interface specified
        # s.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(Interface.MCAST_GRP) + socket.inet_aton(ip_interface))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     socket.inet_aton(Interface.MCAST_GRP) + socket.inet_aton(ip_interface))
        s.setsockopt(socket.SOL_SOCKET, 25, str(interface_name + '\0').encode('utf-8'))

        # set socket output interface
        s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip_interface))

        # set socket TTL to 1
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)

        # don't receive outgoing packets
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

        super().__init__(interface_name, s, s, vif_index)
        super().enable()

        # hardcoded todo: delete when igmpv3 implemented!!!

        self.force_send_hello()
    
    @staticmethod
    def _get_address_family():
        return socket.AF_INET
    
    def get_ip(self):
        """
        Get IP of this interface
        """
        return self.ip_interface

    def _receive(self, raw_bytes):
        """
        Interface received a new control packet
        """
        if raw_bytes:
            packet = ReceivedPacket(raw_bytes, self)
            if self.is_security_enabled():
                received_security_id = packet.payload.security_id
                if received_security_id != self.security_id:
                    return

                received_security_len = packet.payload.security_length
                if received_security_len != self.security_len:
                    return

                received_security_value = packet.payload.security_value
                received_ip_header = packet.ip_header

                packet.payload.security_value = b''
                calculated_security_value = hmac.new(self.get_security_key(),
                                                     socket.inet_aton(received_ip_header.ip_src) +
                                                     socket.inet_aton(received_ip_header.ip_dst) +
                                                     packet.bytes(), digestmod=self.hash_function).digest()
                if received_security_value != calculated_security_value:
                    return

            #self.interface_logger.debug('receive packet : ' + str(packet.payload.get_pim_type()))
            self.PKT_FUNCTIONS[packet.payload.get_pim_type()](self, packet)

    def send(self, data: Packet, group_ip: str = MCAST_GRP):
        """
        Send a new packet destined to group_ip IP
        """
        if self.is_security_enabled():
            key = self.get_security_key()
            data.payload.security_id = self.security_id
            data.payload.security_length = self.security_len
            security_value = hmac.new(key, socket.inet_aton(self.get_ip()) + socket.inet_aton(group_ip) +
                                      data.bytes(), digestmod=self.hash_function).digest()
            data.payload.security_value = security_value
        super().send(data=data.bytes(), group_ip=group_ip)

    def is_security_enabled(self):
        return self.get_security_key() != b''

    def get_security_key(self):
        return self.security_key

    def add_security_key(self, security_identifier, security_function, security_key):
        """
        Set Security information for the HMAC of control messages. Set the Security Identifier used to identify
         the Hash algorithm of received control messages, the corresponding hash algorithm and the SecurityKey used to
          calculate the HMAC
        """
        self.security_id = security_identifier
        self.security_len = len(hashlib.new(security_function).digest())
        self.hash_function = getattr(hashlib, security_function)
        self.security_key = str.encode(security_key)

    def remove_security_key(self, security_identifer):
        """
        Disable a given <SecurityIdentifier; HashAlgorithm; SecurityKey> of HMAC control messages.
        """
        if security_identifer != self.security_id:
            return
        self.security_key = b''
        self.security_id = 0
        self.security_len = 0
        self.hash_function = None

    def get_sequence_number(self):
        """
        Get the new sequence number SN to be transmitted in a new control message
        This method will increment the last used sequence number and return it
        It also returns the current BootTime
        """
        with self.sequencer_lock:
            self.sequencer += 1

            if self.sequencer == InterfaceProtocol.MAX_SEQUENCE_NUMBER:
                self.time_of_boot = int(time.time())
                self.sequencer = 1
                self.clear_reliable_transmission()
                self.force_send_hello()

            return (self.time_of_boot, self.sequencer)

    def get_checkpoint_sn(self):
        """
        Get the CheckpointSN to be transmitted in a new Hello message
        """
        #print("A ENTRAR CHECK_SN")
        with self.neighbors_lock:
            with self.sequencer_lock:
                with self.reliable_transmission_lock:
                    time_of_boot = self.time_of_boot
                    checkpoint_sn = self.sequencer

                    for rt in self.reliable_transmission_buffer.values():
                        (msg_boot_time, msg_checkpoint_sn) = rt.get_sequence_number()
                        if msg_boot_time == time_of_boot and checkpoint_sn > msg_checkpoint_sn:
                            checkpoint_sn = msg_checkpoint_sn

                    #print("A SAIR CHECK_SN")
                    return (time_of_boot, checkpoint_sn)

    # Random interval for initial Hello message on bootup or triggered Hello message to a rebooting neighbor
    def force_send_hello(self):
        """
        Force the transmission of a new Hello message
        """
        if self.hello_timer is not None:
            self.hello_timer.cancel()

        hello_timer_time = random.uniform(0, self.TRIGGERED_HELLO_PERIOD)
        self.hello_timer = Timer(hello_timer_time, self.send_hello)
        self.hello_timer.start()

    # For tests purposes
    # def force_send_join(self):
    #     """
    #     Force the transmission of a new Join message
    #     Only applicable for R6 and R7
    #     """

    #     if self.get_ip() == '10.4.4.4' or self.get_ip() == '10.4.4.3':
    #         source = "10.1.1.100"
    #         group = "224.12.12.12"
    #         print("\n\n-----Sending JOIN-------\n\n")
    #         self.send_join(source, group)
    #     else:
    #         print("\n\n-----NOT Sending JOIN-------\n\n")

    # # For tests purposes
    # def force_send_prune(self):
    #     """
    #     Force the transmission of a new Prune message
    #     Only applicable for R6 and R7
    #     """

    #     print("send prune")

    #     if self.get_ip() == '10.4.4.4' or self.get_ip() == '10.4.4.3':
    #         source = "10.1.1.100"
    #         group = "224.12.12.12"
    #         self.send_prune(source, group)

    def send_hello(self):
        """
        Send a new Hello message
        Include in it the HelloHoldTime and CheckpointSN
        """
        self.hello_timer.cancel()

        pim_payload = PacketProtocolHello()
        pim_payload.add_option(PacketProtocolHelloHoldtime(holdtime=4 * self.HELLO_PERIOD))

        with self.neighbors_lock:
            with self.sequencer_lock:
                with self.reliable_transmission_lock:
                    (bt, checkpoint_sn) = self.get_checkpoint_sn()
                    if bt == self.time_of_boot:
                        pim_payload.add_option(PacketProtocolHelloCheckpointSN(checkpoint_sn))

                ph = PacketProtocolHeader(pim_payload, boot_time=self.time_of_boot)
        packet = Packet(payload=ph)
        self.send(packet)

        # reschedule hello_timer
        self.hello_timer = Timer(self.HELLO_PERIOD, self.send_hello)
        self.hello_timer.start()

    def remove(self):
        """
        Remove this interface
        Clear all state
        """
        self.interface_logger.debug("Removing interface")

        self.hello_timer.cancel()
        self.hello_timer = None

        # send pim_hello timeout message
        pim_payload = PacketProtocolHello()
        pim_payload.add_option(PacketProtocolHelloHoldtime(holdtime=HELLO_HOLD_TIME_TIMEOUT))
        ph = PacketProtocolHeader(pim_payload, boot_time=self.time_of_boot)
        packet = Packet(payload=ph)
        self.send(packet)

        super().remove()
        for n in self.neighbors.values():
            n.remove_neighbor_state()
        self.neighbors.clear()
        self.clear_reliable_transmission()

    def snapshot_multicast_routing_table(self, neighbor_ip):
        """
        Create a new snapshot
        This method will return the current BootTime, SnapshotSN and all trees to be included in Sync messages
        """
        with Main.kernel.rwlock.genWlock():
            with self.sequencer_lock:
                (snapshot_bt, snapshot_sn) = self.get_sequence_number()

                trees_to_sync = Main.kernel.snapshot_multicast_routing_table(self.vif_index, neighbor_ip)  # type: dict
                tree_to_sync_in_msg_format = {}

                for (source_group, state) in trees_to_sync.items():
                    self.interface_logger.debug('added tree in sync message: router is interested!')
                    #print("NA SNAPSHOT NA INTERFACEPROTOCOL")
                    #print("O STATE E")
                    #print(str(state))

                    tree_to_sync_in_msg_format[source_group] = PacketProtocolHelloSyncEntry(source_group[0],
                                                                source_group[1], state.metric_preference, state.route_metric)


                return (snapshot_bt, snapshot_sn, tree_to_sync_in_msg_format)

    ##############################################
    # Check neighbor status
    ##############################################
    def get_tree_state(self, source_group):
        """
        Get Interest state regarding a given tree...
        Regarding Interest this method will return "Interested/True" if at least one neighbor is interested
            or "NotInterested" if all neighbors are not interested in traffic regarding (source_group) tree
        Regarding the assert this method returns the neighbor that offers the best RPC metric
        """

        #print("IN InterfaceProtocol GET_TREE_STATE")

        interest_state = False
        assert_state = None

        for n in list(self.neighbors.values()):
            neighbor_interest_state, neighbor_assert_state = n.get_tree_state(tree=source_group)

            if not interest_state and neighbor_interest_state:
                interest_state = neighbor_interest_state

            if neighbor_assert_state is not None:
                if assert_state is None:
                    assert_state = neighbor_assert_state
                elif neighbor_assert_state.is_better_than(assert_state):
                    assert_state = neighbor_assert_state

        print("igmp_interest in interface " + str(self.ip_interface) + ": " + str(self.igmp_interest.get((source_group[0], source_group[1]))))         
        if not interest_state and self.igmp_interest.get((source_group[0], source_group[1]), False):
            interest_state = True

        print("In get tree state interface " +str(self.ip_interface) + ": ", interest_state)
        #self.interface_logger.debug('get tree state: metric state: ' + str(assert_state))
        return interest_state, assert_state

    def remove_tree_state(self, source_ip, group_ip):
        """
        Remove tree state regarding a given (Source_IP, Group_IP) tree
        """
        for n in list(self.neighbors.values()):
            n.remove_tree_state(source_ip, group_ip)

    # Used to show list of neighbors in CLI interfaces
    def get_neighbors(self):
        """
        Get all neighbors
        """
        with self.neighbors_lock:
            return self.neighbors.values()

    def get_neighbors_ip(self):
        """
        Get IP of all neighbors
        """
        return set(self.neighbors.keys())

    def get_neighbor(self, ip):
        with self.neighbors_lock:
            return self.neighbors.get(ip)

    def force_neighbor_failure(self, neighbor_ip):
        """
        Force an adjacent neighbor to be declared as failed.
        This is used to break an adjacency if a neighbor fails to ack successive control messages
        """
        with self.neighbors_lock:
            neighbor = self.neighbors.get(neighbor_ip, None)
            if neighbor is not None:
                neighbor.remove()

    def did_all_neighbors_acked(self, neighbors_that_acked: set):
        """
        Verify if all neighbor have acknowledged a given message
        Compare if all neighbors that are being monitored are present in neighbors_that_acked set
        """
        return neighbors_that_acked >= self.neighbors.keys()

    def is_neighbor(self, neighbor_ip):
        """
        Verify if neighbor_ip is considered a neighbor
        """
        return neighbor_ip in self.neighbors

    def remove_neighbor(self, ip):
        """
        Remove known neighbor
        """
       
        with self.neighbors_lock:
            if ip not in self.neighbors:
                return
            self.neighbors.pop(ip)

            Main.kernel.recheck_all_trees(self.vif_index)

    ###########################################
    # Recv packets
    ###########################################
    def new_neighbor(self, neighbor_ip, boot_time, detected_via_non_sync_msg=True):
        """
        New neighbor detected... start monitoring it and start synchronization
        """
        with self.neighbors_lock:
            self.neighbors[neighbor_ip] = Neighbor(self, neighbor_ip, 120, boot_time, self.time_of_boot)

            if detected_via_non_sync_msg:
                self.neighbors[neighbor_ip].start_sync_process()

    def receive_hello(self, packet):
        """
        Received an Hello packet
        """
        ip = packet.ip_header.ip_src
        boot_time = packet.payload.boot_time
        #print("ip = ", ip)
        options = packet.payload.payload.get_options()
        hello_hold_time = options["HOLDTIME"].holdtime
        checkpoint_sn = 0
        if "CHECKPOINT_SN" in options:
            checkpoint_sn = options["CHECKPOINT_SN"].checkpoint_sn
        #self.interface_logger.debug('Received Hello message with HelloHoldTime: ' + str(hello_hold_time) +
        #                            '; CheckpointSN: ' + str(checkpoint_sn) + ' from neighbor ' + ip)

        with self.neighbors_lock:
            if ip in self.neighbors:
                self.neighbors[ip].recv_hello(boot_time, hello_hold_time, checkpoint_sn)
            else:
                self.new_neighbor(ip, boot_time, True)

    def receive_sync(self, packet):
        """
        Received an Sync packet
        """
        ip = packet.ip_header.ip_src
        boot_time = packet.payload.boot_time

        pkt_hs = packet.payload.payload  # type: PacketProtocolHelloSync

        # Process Sync msg
        my_boot_time = pkt_hs.neighbor_boot_time
        if my_boot_time != self.time_of_boot:
            return

        # All information in Sync msg
        sync_sn = pkt_hs.sync_sequence_number
        upstream_trees = pkt_hs.upstream_trees
        hello_options = pkt_hs.get_hello_options()
        neighbor_sn = pkt_hs.my_snapshot_sn
        my_sn = pkt_hs.neighbor_snapshot_sn
        master_flag = pkt_hs.master_flag
        more_flag = pkt_hs.more_flag

        self.interface_logger.debug('Received Sync message with BootTime: ' + str(boot_time) +
                                    '; NeighborBootTime: ' + str(my_boot_time) +
                                    '; MySnapshotSN: ' + str(neighbor_sn) +
                                    '; NeighborSnapshotSN: ' + str(my_sn) +
                                    '; SyncSN: ' + str(sync_sn) +
                                    '; Master flag: ' + str(master_flag) +
                                    '; More flag: ' + str(more_flag) +
                                    ' from neighbor ' + ip + "\n")
        self.interface_logger.debug(upstream_trees)

        with self.neighbors_lock:
            if ip not in self.neighbors:
                self.new_neighbor(ip, boot_time, detected_via_non_sync_msg=False)

            self.neighbors[ip].recv_sync(upstream_trees, my_sn, neighbor_sn, boot_time, sync_sn, master_flag, more_flag,
                                         my_boot_time, hello_options)

    def receive_join(self, packet):
        """
        Received a Join packet
        """
        #print("\n\n-----Received JOIN-------\n\n")
        neighbor_source_ip = packet.ip_header.ip_src
        boot_time = packet.payload.boot_time

        pkt_jt = packet.payload.payload  # type: PacketProtocolJoin

        # Process Interest msg
        source_group = (pkt_jt.source, pkt_jt.group)
        sequence_number = pkt_jt.sequence_number

        self.interface_logger.debug('Received Join message with BootTime: ' + str(boot_time) +
                                    '; Tree: ' + str(source_group) +
                                    '; SN: ' + str(sequence_number) +
                                    ' from neighbor ' + neighbor_source_ip + "\n")

        # check neighbor existence
        with self.neighbors_lock:
            neighbor = self.neighbors.get(neighbor_source_ip, None)
            if neighbor is None:
                # self.interface_logger.debug("Received Join: New neighbor")
                self.new_neighbor(neighbor_source_ip, boot_time)
                return

            try:
                if neighbor.recv_reliable_packet(sequence_number, source_group, boot_time):
                    neighbor.tree_interest_state[source_group] = True
                    print("NEIGHBOUR " + str(neighbor.ip) + " INTEREST: " + str(neighbor.tree_interest_state[source_group])+"\n")
                    # self.neighbors_lock.release()
                    Main.kernel.recv_interest_msg(source_group, self)

            except:
                print(traceback.format_exc())
        

    def receive_prune(self, packet):
        """
        Received a Prune packet
        """
        #print("\n\n-----Received Prune-------\n\n")
        neighbor_source_ip = packet.ip_header.ip_src
        boot_time = packet.payload.boot_time

        pkt_jt = packet.payload.payload  # type: PacketProtocolPrune

        # Process NoInterest msg
        source_group = (pkt_jt.source, pkt_jt.group)
        sequence_number = pkt_jt.sequence_number

        self.interface_logger.debug('Received Prune message with BootTime: ' + str(boot_time) +
                                    '; Tree: ' + str(source_group) +
                                    '; SN: ' + str(sequence_number) +
                                    ' from neighbor ' + neighbor_source_ip + "\n")

        # check neighbor existence
        with self.neighbors_lock:
            neighbor = self.neighbors.get(neighbor_source_ip, None)
            if neighbor is None:
                # self.interface_logger.debug("Received Prune: New neighbor")
                self.new_neighbor(neighbor_source_ip, boot_time)
                return

            try:
                if neighbor.recv_reliable_packet(sequence_number, source_group, boot_time):
                    # self.interface_logger.debug('Received Prune: trying')
                    neighbor.tree_interest_state[source_group] = False
                    print("NEIGHBOUR " + str(neighbor.ip) + " INTEREST: " + str(neighbor.tree_interest_state[source_group])+"\n")
                    neighbor.tree_interest_state.pop(source_group)
                    # self.neighbors_lock.release()
                    Main.kernel.recv_interest_msg(source_group, self)

            except:
                    print(traceback.format_exc())

    def receive_ack(self, packet):
        """
        Received an Ack packet
        """
        neighbor_source_ip = packet.ip_header.ip_src
        neighbor_boot_time = packet.payload.boot_time
        pkt_ack = packet.payload.payload  # type: PacketProtocolAck

        # Process Ack msg
        source_group = (pkt_ack.source, pkt_ack.group)
        my_boot_time = pkt_ack.neighbor_boot_time
        my_snapshot_sn = pkt_ack.neighbor_snapshot_sn
        neighbor_snapshot_sn = pkt_ack.my_snapshot_sn
        sequence_number = pkt_ack.sequence_number

        self.interface_logger.debug('Received Ack message with BootTime: ' + str(neighbor_boot_time) +
                                    '; NeighborBootTime: ' + str(my_boot_time) +
                                    '; MySnapshotSN: ' + str(neighbor_snapshot_sn) +
                                    '; NeighborSnapshotSN: ' + str(my_snapshot_sn) +
                                    '; Tree: ' + str(source_group) +
                                    '; SN: ' + str(sequence_number) +
                                    ' from neighbor ' + neighbor_source_ip + "\n")


        # check neighbor existence
        with self.neighbors_lock:
            neighbor = self.neighbors.get(neighbor_source_ip, None)  # type: Neighbor
            if neighbor is None:
                self.new_neighbor(neighbor_source_ip, neighbor_boot_time)
                return

            with self.sequencer_lock:
                with self.reliable_transmission_lock:
                    if not neighbor.recv_ack(my_boot_time, neighbor_boot_time, my_snapshot_sn, neighbor_snapshot_sn):
                        return

                    # if my_boot_time != self.time_of_boot:
                    #    return

                    reliable_transmission = self.reliable_transmission_buffer.get(source_group, None)
                    if reliable_transmission is not None:
                        reliable_transmission.receive_ack(neighbor_source_ip, my_boot_time, sequence_number)

    def receive_assert(self, packet):
        """
        Received an Assert packet
        """
        from tree.metric import AssertMetric
        neighbor_source_ip = packet.ip_header.ip_src
        boot_time = packet.payload.boot_time
        pkt_jt = packet.payload.payload  # type: PacketProtocolAssert

        # Process Assert msg
        source_group = (pkt_jt.source, pkt_jt.group)
        sequence_number = pkt_jt.sequence_number

        metric_preference = pkt_jt.metric_preference
        metric = pkt_jt.metric
        received_metric = AssertMetric(metric_preference=metric_preference, route_metric=metric,
                                       ip_address=neighbor_source_ip)

        self.interface_logger.debug('Received Assert message with BootTime: ' + str(boot_time) +
                                    '; Tree: ' + str(source_group) +
                                    '; SN: ' + str(sequence_number) +
                                    '; MetricPreference: ' + str(metric_preference) +
                                    '; Metric: ' + str(metric) +
                                    ' from neighbor ' + neighbor_source_ip + "\n")

        # check neighbor existence
        with self.neighbors_lock:
            neighbor = self.neighbors.get(neighbor_source_ip, None)
            if neighbor is None:
                self.new_neighbor(neighbor_source_ip, boot_time)
                return

            try:
                if neighbor.recv_reliable_packet(sequence_number, source_group, boot_time):
                    #neighbor.tree_interest_state.pop(source_group, None)
                    neighbor.tree_metric_state[source_group] = received_metric
                    if received_metric.metric_preference == 2147483647 and received_metric.route_metric == 4294967295:
                        neighbor.tree_metric_state.pop(source_group)
                    #self.neighbors_lock.release()
                    Main.kernel.recv_assert_msg(source_group, self)


            except:
                print(traceback.format_exc())

    PKT_FUNCTIONS = {
        PacketProtocolHello.PIM_TYPE: receive_hello,
        PacketProtocolHelloSync.PIM_TYPE: receive_sync,
        PacketProtocolAssert.PIM_TYPE: receive_assert,
        PacketProtocolJoin.PIM_TYPE: receive_join,
        PacketProtocolPrune.PIM_TYPE: receive_prune,
        PacketProtocolAck.PIM_TYPE: receive_ack,
    }

    def receive_igmp(self, source_group, interest):
        """
        Received a Join packet
        """
        #print("\n\n-----Received JOIN-------\n\n")

        self.interface_logger.debug('Received IGMP report for Tree: ' + str(source_group) +
                                    '; Interest: ' + str(interest) + "\n")
        
        self.igmp_interest[(source_group[0], source_group[1])] = interest

        #print("dic igmp interest " + str(self.igmp_interest))

        # check neighbor existence
        with self.neighbors_lock:
            Main.kernel.recv_interest_msg(source_group, self)

    ########################################################################
    # Message Transmission
    ########################################################################
    def get_reliable_message_transmission(self, tree):
        """
        Get object used to monitor the reliable transmission of messages regarding a given tree
        """
        with self.reliable_transmission_lock:
            reliable_msg_transmission = self.reliable_transmission_buffer.get(tree, None)

            if reliable_msg_transmission is None:
                reliable_msg_transmission = ReliableMessageTransmission(self)
                self.reliable_transmission_buffer[tree] = reliable_msg_transmission

            return reliable_msg_transmission

    def send_assert(self, source, group, rpc):
        """
        Send a new Assert message
        """
        tree = (source, group)
        with self.sequencer_lock:
            with self.reliable_transmission_lock:
                self.get_reliable_message_transmission(tree).send_assert(source, group, rpc)

    def send_join(self, source, group, dst):
        """
        Send a new Join message
        """
        tree = (source, group)
        with self.sequencer_lock:
            with self.reliable_transmission_lock:
                self.get_reliable_message_transmission(tree).send_join(source, group, dst)

    def send_prune(self, source, group,dst):
        """
        Send a new Prune message
        """

        tree = (source, group)
        with self.sequencer_lock:
            with self.reliable_transmission_lock:
                self.get_reliable_message_transmission(tree).send_prune(source, group, dst)

    def neighbor_start_synchronization(self, neighbor_ip, my_snapshot_bt, my_snapshot_sn):
        """
        Neighbor started a new synchronization... consider all trees included in the snapshot to be Acknowledged
        (all packets transmitted with a lower BootTime or lower SN compared to SnapshotSN will be considered to have been
        acknowledged by it)
        """
        with self.reliable_transmission_lock:
            for rmt in self.reliable_transmission_buffer.values():
                rmt.receive_ack(neighbor_ip, my_snapshot_bt, my_snapshot_sn)

    def cancel_all_messages(self, tree):
        """
        Cancel the reliable monitoring of all messages regarding a given tree
        """
        with self.reliable_transmission_lock:
            if tree in self.reliable_transmission_buffer:
                self.reliable_transmission_buffer[tree].cancel_all_messages()

    def cancel_join_message(self, tree):
        """
        Cancel the reliable monitoring of all interest messages regarding a given tree
        """
        with self.reliable_transmission_lock:
            if tree in self.reliable_transmission_buffer:
                self.reliable_transmission_buffer[tree].cancel_message_multicast()

    def cancel_assert_message(self, tree):
        """
        Cancel the reliable monitoring of all upstream messages regarding a given tree
        """
        with self.reliable_transmission_lock:
            if tree in self.reliable_transmission_buffer:
                self.reliable_transmission_buffer[tree].cancel_message_multicast()

    def clear_reliable_transmission(self):
        """
        Cancel the reliable monitoring of all messages regarding all trees
        """
        with self.reliable_transmission_lock:
            for rmt in self.reliable_transmission_buffer.values():
                rmt.cancel_all_messages()