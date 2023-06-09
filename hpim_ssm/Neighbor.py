import ipaddress
import logging
import time
from threading import Timer

import Main
from Packet.Packet import Packet
from tree import protocol_globals
from tree.metric import AssertMetric
from utils import TYPE_CHECKING
from threading import RLock

if protocol_globals.MSG_FORMAT == "BINARY":
    from Packet.PacketProtocolAck import PacketNewProtocolAck as PacketProtocolAck
    from Packet.PacketProtocolSync import PacketNewProtocolSync as PacketProtocolHelloSync
    from Packet.PacketProtocolHelloOptions import PacketNewProtocolHelloHoldtime as PacketProtocolHelloHoldtime
    from Packet.PacketProtocolHeader import PacketNewProtocolHeader as PacketProtocolHeader
else:
    from Packet.PacketProtocolAck import PacketProtocolAck
    from Packet.PacketProtocolSync import PacketProtocolHelloSync
    from Packet.PacketProtocolHelloOptions import PacketProtocolHelloHoldtime
    from Packet.PacketProtocolHeader import PacketProtocolHeader

if TYPE_CHECKING:
    from InterfaceProtocol import InterfaceProtocol

DEFAULT_HELLO_HOLD_TIME_DURING_SYNC = 4 * protocol_globals.SYNC_RETRANSMISSION_TIME
DEFAULT_HELLO_HOLD_TIME_AFTER_SYNC = 120

class NeighborState():
    @staticmethod
    def new_neighbor_or_adjacency_reset(neighbor):
        neighbor.set_sync_state(Slave)

        neighbor.start_snapshot()

        # Remove all info from neighbor (if already knew it)
        neighbor.tree_interest_state.clear()
        neighbor.tree_metric_state.clear()
        neighbor.last_sequence_number.clear()
        neighbor.current_sync_sn = 0
        neighbor.neighbor_snapshot_sn = 0
        neighbor.checkpoint_sn = 0
        #

        my_snapshot_mrt = neighbor.my_snapshot_multicast_routing_table[0:neighbor.sync_fragmentation]
        my_more_bit = len(neighbor.my_snapshot_multicast_routing_table) > 0
        my_snapshot_sn = neighbor.my_snapshot_sequencer

        pkt_s = PacketProtocolHelloSync(my_snapshot_sn, 0,
                                        sync_sn=neighbor.current_sync_sn,
                                        upstream_trees=my_snapshot_mrt, master_flag=True,
                                        more_flag=my_more_bit,
                                        neighbor_boot_time=neighbor.time_of_boot)
        pkt = Packet(payload=PacketProtocolHeader(pkt_s, neighbor.my_snapshot_boot_time))
        neighbor.contact_interface.send(pkt, neighbor.ip)
        neighbor.set_sync_timer()
        neighbor.set_hello_hold_time(DEFAULT_HELLO_HOLD_TIME_DURING_SYNC)

    @staticmethod
    def recv_sync(neighbor, tree_state, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, master_bit, more_bit, hello_options):
        return

    @staticmethod
    def sync_timer_expires(neighbor):
        return


class Synced(NeighborState):
    @staticmethod
    def recv_sync(neighbor, tree_state, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, master_bit, more_bit, hello_options):
        if neighbor.neighbor_snapshot_sn > neighbor_snapshot_sn:
            return
        elif neighbor.neighbor_snapshot_sn < neighbor_snapshot_sn:
            Synced.new_neighbor_or_adjacency_reset(neighbor)
            return

        if sync_sn != neighbor.current_sync_sn:
            return

        if master_bit and neighbor.my_snapshot_sequencer == my_snapshot_sn:
            pkt_s = PacketProtocolHelloSync(my_snapshot_sn, neighbor_snapshot_sn, sync_sn=sync_sn,
                                            master_flag=False, more_flag=False,
                                            neighbor_boot_time=neighbor.time_of_boot)
            pkt_s.add_hello_option(PacketProtocolHelloHoldtime(holdtime=4 * neighbor.contact_interface.HELLO_PERIOD))
            pkt = Packet(payload=PacketProtocolHeader(pkt_s, neighbor.my_snapshot_boot_time))
            neighbor.send(pkt)


class Master(NeighborState):
    @staticmethod
    def recv_sync(neighbor, tree_state, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, master_bit, more_bit, hello_options):
        if neighbor.current_sync_sn == 0 and neighbor.neighbor_snapshot_sn == 0:
            neighbor.neighbor_snapshot_sn = neighbor_snapshot_sn

        if neighbor.neighbor_snapshot_sn > neighbor_snapshot_sn:
            return
        elif neighbor.neighbor_snapshot_sn < neighbor_snapshot_sn:
            Master.new_neighbor_or_adjacency_reset(neighbor)
            return

        if sync_sn != neighbor.current_sync_sn:
            return

        if master_bit and (sync_sn > 0 and neighbor.my_snapshot_sequencer == my_snapshot_sn or sync_sn == 0):
            neighbor.install_tree_state(tree_state)

            my_snapshot_mrt = neighbor.my_snapshot_multicast_routing_table[neighbor.current_sync_sn*neighbor.sync_fragmentation:
                                                                           (neighbor.current_sync_sn+1)*neighbor.sync_fragmentation]
            my_more_bit = len(neighbor.my_snapshot_multicast_routing_table) > neighbor.current_sync_sn*neighbor.sync_fragmentation
            my_snapshot_sn = neighbor.my_snapshot_sequencer
            neighbor_sn = neighbor.neighbor_snapshot_sn

            pkt_s = PacketProtocolHelloSync(my_snapshot_sn, neighbor_sn,
                                            sync_sn=neighbor.current_sync_sn,
                                            upstream_trees=my_snapshot_mrt, master_flag=False,
                                            more_flag=my_more_bit, neighbor_boot_time=neighbor.time_of_boot)
            if not my_more_bit:
                pkt_s.add_hello_option(PacketProtocolHelloHoldtime(holdtime=4 * neighbor.contact_interface.HELLO_PERIOD))
            pkt = Packet(payload=PacketProtocolHeader(pkt_s, neighbor.my_snapshot_boot_time))
            neighbor.send(pkt)

            if sync_sn > 0 and not more_bit and not my_more_bit:
                if "HOLDTIME" in hello_options:
                    neighbor.set_hello_hold_time(hello_options["HOLDTIME"].holdtime)
                else:
                    neighbor.set_hello_hold_time(DEFAULT_HELLO_HOLD_TIME_AFTER_SYNC)
                neighbor.set_sync_state(Synced)
                neighbor.clear_sync_timer()
                del neighbor.my_snapshot_multicast_routing_table[:]
            else:
                neighbor.set_hello_hold_time(DEFAULT_HELLO_HOLD_TIME_DURING_SYNC)
                neighbor.set_sync_timer()
                neighbor.current_sync_sn += 1

    @staticmethod
    def sync_timer_expires(neighbor):
        my_snapshot_mrt = neighbor.my_snapshot_multicast_routing_table[(neighbor.current_sync_sn - 1) * neighbor.sync_fragmentation:
                                                                       neighbor.current_sync_sn * neighbor.sync_fragmentation]
        my_more_bit = len(neighbor.my_snapshot_multicast_routing_table) > (neighbor.current_sync_sn - 1) * neighbor.sync_fragmentation
        my_snapshot_sn = neighbor.my_snapshot_sequencer
        neighbor_sn = neighbor.neighbor_snapshot_sn

        pkt_s = PacketProtocolHelloSync(my_snapshot_sn, neighbor_sn,
                                        sync_sn=neighbor.current_sync_sn - 1,
                                        upstream_trees=my_snapshot_mrt, master_flag=False,
                                        more_flag=my_more_bit, neighbor_boot_time=neighbor.time_of_boot)
        if not my_more_bit:
            pkt_s.add_hello_option(PacketProtocolHelloHoldtime(holdtime=4 * neighbor.contact_interface.HELLO_PERIOD))

        pkt = Packet(payload=PacketProtocolHeader(pkt_s, neighbor.my_snapshot_boot_time))
        neighbor.send(pkt)
        neighbor.set_sync_timer()


class Slave(NeighborState):
    @staticmethod
    def recv_sync(neighbor, tree_state, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, master_bit, more_bit, hello_options):
        if neighbor.current_sync_sn == 0 and neighbor.neighbor_snapshot_sn == 0:
            neighbor.neighbor_snapshot_sn = neighbor_snapshot_sn

        if neighbor.neighbor_snapshot_sn > neighbor_snapshot_sn:
            return
        elif neighbor.neighbor_snapshot_sn < neighbor_snapshot_sn:
            Slave.new_neighbor_or_adjacency_reset(neighbor)
            return

        if sync_sn != neighbor.current_sync_sn:
            return

        if sync_sn == 0 and master_bit:
            my_ip = ipaddress.ip_address(neighbor.contact_interface.get_ip())
            neighbor_ip = ipaddress.ip_address(neighbor.ip)
            if my_ip < neighbor_ip:
                neighbor.set_sync_state(Master)
                neighbor.current_sync_sn = 0
                Master.recv_sync(neighbor, tree_state, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, master_bit,
                                 more_bit, hello_options)
            else:
                Slave.sync_timer_expires(neighbor)
        elif not master_bit and neighbor.my_snapshot_sequencer == my_snapshot_sn:
            my_more_bit = len(neighbor.my_snapshot_multicast_routing_table) > neighbor.current_sync_sn*neighbor.sync_fragmentation

            if sync_sn > 0 and not my_more_bit and not more_bit:
                if "HOLDTIME" in hello_options:
                    neighbor.set_hello_hold_time(hello_options["HOLDTIME"].holdtime)
                else:
                    neighbor.set_hello_hold_time(DEFAULT_HELLO_HOLD_TIME_AFTER_SYNC)
                neighbor.set_sync_state(Synced)
                neighbor.clear_sync_timer()
                del neighbor.my_snapshot_multicast_routing_table[:]
            else:
                neighbor.set_hello_hold_time(DEFAULT_HELLO_HOLD_TIME_DURING_SYNC)
                neighbor.current_sync_sn += 1
                neighbor.install_tree_state(tree_state)

                my_snapshot_mrt = neighbor.my_snapshot_multicast_routing_table[neighbor.current_sync_sn*neighbor.sync_fragmentation:
                                                                               (neighbor.current_sync_sn+1)*neighbor.sync_fragmentation]
                my_more_bit = len(neighbor.my_snapshot_multicast_routing_table) > neighbor.current_sync_sn*neighbor.sync_fragmentation
                my_snapshot_sn = neighbor.my_snapshot_sequencer
                neighbor_sn = neighbor.neighbor_snapshot_sn

                pkt_s = PacketProtocolHelloSync(my_snapshot_sn, neighbor_sn,
                                                sync_sn=neighbor.current_sync_sn,
                                                upstream_trees=my_snapshot_mrt, master_flag=True,
                                                more_flag=my_more_bit, neighbor_boot_time=neighbor.time_of_boot)
                if not my_more_bit:
                    pkt_s.add_hello_option(PacketProtocolHelloHoldtime(holdtime=4 * neighbor.contact_interface.HELLO_PERIOD))
                pkt = Packet(payload=PacketProtocolHeader(pkt_s, neighbor.my_snapshot_boot_time))
                neighbor.send(pkt)
                neighbor.set_sync_timer()

    @staticmethod
    def sync_timer_expires(neighbor):
        my_snapshot_mrt = neighbor.my_snapshot_multicast_routing_table[neighbor.current_sync_sn * neighbor.sync_fragmentation:
                                                                       (neighbor.current_sync_sn + 1) * neighbor.sync_fragmentation]
        my_more_bit = len(neighbor.my_snapshot_multicast_routing_table) > neighbor.current_sync_sn * neighbor.sync_fragmentation
        my_snapshot_sn = neighbor.my_snapshot_sequencer
        neighbor_sn = neighbor.neighbor_snapshot_sn

        pkt_s = PacketProtocolHelloSync(my_snapshot_sn, neighbor_sn,
                                        sync_sn=neighbor.current_sync_sn,
                                        upstream_trees=my_snapshot_mrt, master_flag=True,
                                        more_flag=my_more_bit, neighbor_boot_time=neighbor.time_of_boot)
        if not my_more_bit:
            pkt_s.add_hello_option(PacketProtocolHelloHoldtime(holdtime=4 * neighbor.contact_interface.HELLO_PERIOD))

        pkt = Packet(payload=PacketProtocolHeader(pkt_s, neighbor.my_snapshot_boot_time))
        neighbor.send(pkt)
        neighbor.set_sync_timer()


class Unknown(NeighborState):
    @staticmethod
    def recv_sync(neighbor, tree_state, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, master_bit, more_bit, hello_options):
        if sync_sn == 0 and sync_sn == neighbor.current_sync_sn and master_bit:
            neighbor.set_sync_state(Master)
            neighbor.set_hello_hold_time(DEFAULT_HELLO_HOLD_TIME_DURING_SYNC)

            neighbor.start_snapshot()

            # Remove all info from neighbor (if already knew it)
            neighbor.tree_interest_state.clear()
            neighbor.tree_metric_state.clear()
            neighbor.last_sequence_number.clear()
            neighbor.current_sync_sn = 0
            neighbor.neighbor_snapshot_sn = 0
            neighbor.checkpoint_sn = 0
            #

            Master.recv_sync(neighbor, tree_state, my_snapshot_sn, neighbor_snapshot_sn, sync_sn, master_bit, more_bit, hello_options)
        else:
            Unknown.new_neighbor_or_adjacency_reset(neighbor)


class Neighbor:
    LOGGER = logging.getLogger('hpim.Interface.Neighbor')

    def __init__(self, contact_interface: "InterfaceProtocol", ip, hello_hold_time: int, neighbor_time_of_boot: int,
                 my_interface_boot_time: int):
        if hello_hold_time == protocol_globals.HELLO_HOLD_TIME_TIMEOUT:
            raise Exception
        logger_info = dict(contact_interface.interface_logger.extra)
        logger_info['neighbor_ip'] = ip
        self.neighbor_logger = logging.LoggerAdapter(self.LOGGER, logger_info)

        self.contact_interface = contact_interface
        self.ip = ip
        self.time_of_boot = neighbor_time_of_boot
        self.neighbor_snapshot_sn = 0

        self.neighbor_liveness_timer = None
        self.hello_hold_time = None
        self.set_hello_hold_time(hello_hold_time)
        self.time_of_last_update = time.time()

        self.current_sync_sn = 0
        self.sync_fragmentation = 0

        # Tree Database storage
        self.tree_interest_state = {}
        self.tree_metric_state = {}

        # Control if received control packets should be processed
        # Used to detect msg retransmissions and out of order reception
        self.last_sequence_number = {}

        self.sync_timer = None
        self.neighbor_state = Unknown
        self.neighbor_logger.debug('Neighbor state of ' + self.ip + ' transitions to ' + self.neighbor_state.__name__)

        # checkpoint sn
        self.checkpoint_sn = 0

        # Information of my snapshot
        self.my_snapshot_boot_time = my_interface_boot_time
        self.my_snapshot_sequencer = 0
        self.my_snapshot_multicast_routing_table = []

        self.tree_interface_nlt_subscribers = []
        self.tree_interface_nlt_subscribers_lock = RLock()

    ######################################################################
    # Sync Timer
    ######################################################################
    def set_sync_timer(self):
        """
        Set Sync timer... useful when the Sync process is making progress and a Sync message from the neighbor node must be received
        """
        self.clear_sync_timer()
        self.sync_timer = Timer(protocol_globals.SYNC_RETRANSMISSION_TIME, self.sync_timeout)
        self.sync_timer.start()

    def clear_sync_timer(self):
        """
        Cancel Sync timer... useful when the Sync process finishes
        """
        if self.sync_timer is not None:
            self.sync_timer.cancel()

    ###########################################
    # Sync Timer timeout
    ###########################################
    def sync_timeout(self):
        """
        Expiration of Sync timer (mus cause a retransmission of a Sync message)
        """
        self.neighbor_state.sync_timer_expires(self)

    ######################################################################
    # Neighbor Liveness Timer
    ######################################################################
    def set_hello_hold_time(self, hello_hold_time: int):
        """
        Set Neighbor liveness timer due to progress in Sync process or a received Hello message
        """
        self.hello_hold_time = hello_hold_time
        if self.neighbor_liveness_timer is not None:
            self.neighbor_liveness_timer.cancel()

        if hello_hold_time == protocol_globals.HELLO_HOLD_TIME_TIMEOUT:
            self.remove()
            #pass
        else:
            self.neighbor_liveness_timer = Timer(hello_hold_time, self.remove)
            self.neighbor_liveness_timer.start()

    ###########################################
    # Neighbor Liveness Timer timeout
    ###########################################
    def remove(self):
        """
        Remove neighbor node because neighbor liveness timer expired
        """
        self.neighbor_logger.debug('Neighbor liveness timer expired, the neighbor is: ' + str(self.ip))
        with self.contact_interface.neighbors_lock:
            self.remove_neighbor_state()
            self.contact_interface.remove_neighbor(self.ip)


        '''
        # notify interfaces which have this neighbor as AssertWinner
        with self.tree_interface_nlt_subscribers_lock:
            for tree_if in self.tree_interface_nlt_subscribers:
                tree_if.assert_winner_nlt_expires()
        '''



    ############################################
    # Sync State
    ############################################
    def set_sync_state(self, state):
        """
        Set sync state of this neighbor node (Unknown or Master or Slave or Synced)
        """
        if self.neighbor_state == state:
            return

        self.neighbor_state = state
        self.neighbor_logger.debug('Neighbor state of ' + self.ip + ' transitions to ' + state.__name__ +
                                   ' with MyBootTime=' + str(self.my_snapshot_boot_time) +
                                   '; MySnapshotSN=' + str(self.my_snapshot_sequencer) +
                                   '; NeighborBootTime=' + str(self.time_of_boot) +
                                   '; NeighborSnapshotSN=' + str(self.neighbor_snapshot_sn))
        if state == Synced:
            Main.kernel.recheck_all_trees(self.contact_interface.vif_index)


    def install_tree_state(self, tree_state: list):
        """
        Store Interest state regarding trees that were included in a Sync message... Since we allow installing state from
        Interest/NoInterest messages concurrently to an ongoing synchronization, verify if
        trees included in Sync message have state fresher than the one that is already stored (in a non-Sync message)
        """
        for t in tree_state:
            tree_id = (t.source, t.group)
            metric_flag = t.metric_flag
            assert_metric = t.assert_metric
            if self.last_sequence_number.get(tree_id, 0) > self.neighbor_snapshot_sn:
                continue

            if metric_flag:
                self.tree_metric_state[tree_id[0]] = AssertMetric(metric_preference=assert_metric[0].metric_preference,
                                                               route_metric=assert_metric[0].metric, ip_address=self.ip)
            else:
                self.tree_interest_state[tree_id] = True

    def remove_tree_state(self, source, group):
        """
        Remove all stored state of the neighbor node regarding trees in Unknown state
        """
        self.tree_interest_state.pop((source, group), None)
        self.tree_metric_state.pop((source), None)



    def get_known_trees(self):
        """
        Get all trees that I am storing state regarding this neighbor node
        """
        return set(self.tree_interest_state.keys())
    
    def get_known_sources(self):
        """
        Get all sources' RPCS that I am storing state regarding this neighbor node
        """
        return set(self.tree_metric_state.keys())

    ######################################################################
    # Send Messages
    ######################################################################
    def send(self, packet):
        """
        Send messages destined to this neighbor node... Used in the neighbor state machine implementation
        """
        self.contact_interface.send(packet, self.ip)

    ######################################################################
    # Receive Messages
    ######################################################################
    def recv_hello(self, boot_time, holdtime, checkpoint_sn):
        """
        Process a received Hello message from this neighbor node
        """
        if boot_time < self.time_of_boot:
            return
        elif boot_time > self.time_of_boot:
            self.time_of_boot = boot_time
            self.neighbor_snapshot_sn = 0
            self.neighbor_state.new_neighbor_or_adjacency_reset(self)
            return

        if self.neighbor_state == Synced:
            self.time_of_last_update = time.time()
            self.set_hello_hold_time(holdtime)
            self.set_checkpoint_sn(checkpoint_sn)
        elif holdtime == 0:
            self.set_hello_hold_time(holdtime)

    def recv_sync(self, upstream_trees, my_sn, neighbor_sn, boot_time, sync_sn, master_flag, more_flag, own_interface_boot_time, hello_options):
        """
        Process a received Sync message from this neighbor node
        """
        if boot_time < self.time_of_boot:
            return
        elif boot_time > self.time_of_boot or own_interface_boot_time > self.my_snapshot_boot_time:
            self.time_of_boot = boot_time
            self.neighbor_snapshot_sn = 0
            self.neighbor_state.new_neighbor_or_adjacency_reset(self)
            return

        self.neighbor_state.recv_sync(self, upstream_trees, my_sn, neighbor_sn, sync_sn, master_flag, more_flag, hello_options)

    def recv_reliable_packet(self, sn, tree, boot_time):
        """
        Decide if a packet received from this neighbor should be processed
        """
        #self.neighbor_logger.debug("ENTROU RCV RELIABLE PACKET")
        if boot_time < self.time_of_boot:
            #self.neighbor_logger.debug("SKOL1")
            return False
        elif boot_time > self.time_of_boot:
            self.time_of_boot = boot_time
            self.neighbor_snapshot_sn = 0
            self.start_sync_process()
            #self.neighbor_logger.debug("SKOL2")
            return False

        if self.neighbor_state == Unknown or self.current_sync_sn == 0:
            #do not interpret control message without having the guarantee of
            # correct <NeighborBootTime; NeighborSnapshotSN> pair
            return False

        last_received_sn = self.last_sequence_number.get(tree, 0)

        if sn <= self.neighbor_snapshot_sn or sn <= self.checkpoint_sn:
            # dont deliver to application
            return False
        elif sn >= last_received_sn:
            (source, group) = tree
            ack = PacketProtocolAck(source, group, sn, neighbor_boot_time=boot_time,
                                    neighbor_snapshot_sn=self.neighbor_snapshot_sn,
                                    my_snapshot_sn=self.my_snapshot_sequencer)
            ph = PacketProtocolHeader(ack, boot_time=self.contact_interface.time_of_boot)
            packet = Packet(payload=ph)
            self.contact_interface.send(packet, self.ip)

            if sn > last_received_sn:
                # update most recent sn received from this neighbor
                self.last_sequence_number[tree] = sn

                # deliver to application
                return True
        # dont deliver to application
        return False

    def recv_ack(self, my_boot_time, neighbor_boot_time, my_snapshot_sn, neighbor_snapshot):
        """
        Decide if a received Ack should be processed... this decision is based on the SNs obtained during the Sync
        process with this neighbor
        """
        if neighbor_boot_time < self.time_of_boot:
            return False
        elif neighbor_boot_time > self.time_of_boot:
            self.time_of_boot = neighbor_boot_time
            self.neighbor_snapshot_sn = 0
            self.start_sync_process()
            return False

        return self.neighbor_state != Unknown and self.current_sync_sn > 0 and \
               self.my_snapshot_boot_time == my_boot_time and self.time_of_boot == neighbor_boot_time and\
               self.my_snapshot_sequencer == my_snapshot_sn and self.neighbor_snapshot_sn == neighbor_snapshot

    #####################################################
    # CheckpointSN... Store and clear lower SNs
    #####################################################
    def set_checkpoint_sn(self, checkpoint_sn):
        """
        By receiving an Hello message with a CheckpointSN store it (if greater than the previously stored CheckpointSN)...
        By storing a greater CheckpointSN, clear all SNs that are lower than the stored CheckpointSN
        """
        if checkpoint_sn > self.checkpoint_sn:
            self.checkpoint_sn = checkpoint_sn

            to_remove = {k for k, v in self.last_sequence_number.items() if v <= checkpoint_sn}
            for k in to_remove:
                self.last_sequence_number.pop(k)

    #######################################################
    # Synchronization methods for starting it
    #######################################################
    def start_sync_process(self):
        """
        Trigger synchronization with this neighbor node
        """
        self.neighbor_state.new_neighbor_or_adjacency_reset(self)

    def start_snapshot(self):
        """
        Create my own snapshot and set my SNs (my BootTime and MySnapshotSN)
        """
        (my_snapshot_bt, my_snapshot_sn, my_snapshot_mrt) = self.contact_interface.snapshot_multicast_routing_table(self.ip)
        self.my_snapshot_boot_time = my_snapshot_bt
        self.my_snapshot_sequencer = my_snapshot_sn
        self.my_snapshot_multicast_routing_table = list(my_snapshot_mrt.values())
        self.sync_fragmentation = protocol_globals.SYNC_FRAGMENTATION_MSG
        if self.sync_fragmentation == 0:
            self.sync_fragmentation = (self.contact_interface.get_mtu() - 20 - 8 - 16) // 16
        self.contact_interface.neighbor_start_synchronization(self.ip, my_snapshot_bt, my_snapshot_sn)


    #################################################################
    # Obtain Upstream and Interest information regarding a neighbor
    #################################################################
    def get_tree_state(self, tree):

        """
        Obtain Interest state regarding neighbor node... This information is obtained based on previous
        messages received from this neighbor node that were stored in the neighbor structure
        """
        if self.neighbor_state != Synced:
            # do not interpret stored state if not Synced
            return False, None
        else:
            assert_state = self.tree_metric_state.get(tree[0], None)
            interest_state = self.tree_interest_state.get(tree, False)
            return interest_state, assert_state


    #######################################
    # Remove state regarding neighbor
    #######################################
    def remove_neighbor_state(self):
        """
        Clear all information regarding neighbor node
        """
        self.neighbor_logger.debug('Removing neighbor ' + self.ip)
        if self.neighbor_liveness_timer is not None:
            self.neighbor_liveness_timer.cancel()

        self.clear_sync_timer()

        self.tree_interest_state.clear()
        self.tree_metric_state.clear()
        self.last_sequence_number.clear()
        del self.my_snapshot_multicast_routing_table[:]

    def subscribe_nlt_expiration(self, tree_if):

        with self.tree_interface_nlt_subscribers_lock:
            if tree_if not in self.tree_interface_nlt_subscribers:
                self.tree_interface_nlt_subscribers.append(tree_if)

    def unsubscribe_nlt_expiration(self, tree_if):

        with self.tree_interface_nlt_subscribers_lock:
            if tree_if in self.tree_interface_nlt_subscribers:
                self.tree_interface_nlt_subscribers.remove(tree_if)

    def get_neighbor_state(self):
        return self.neighbor_state