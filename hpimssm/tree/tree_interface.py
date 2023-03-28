import ipaddress
import logging
import traceback
from abc import ABCMeta, abstractmethod
from threading import RLock
import time

import netifaces
from hpimssm import Main

from .assert_state import AssertState, AssertStateABC
from .local_membership import LocalMembership
from .metric import AssertMetric, Metric


class TreeInterface(metaclass=ABCMeta):
    def __init__(self, kernel_entry, interface_id, logger: logging.LoggerAdapter):
        self._kernel_entry = kernel_entry
        self._interface_id = interface_id
        self.logger = logger
        self.assert_logger = logging.LoggerAdapter(logger.logger.getChild('Assert'), logger.extra)


        # Local Membership State
        self._igmp_lock = RLock()
        try:
            interface_name = Main.kernel.vif_index_to_name_dic[interface_id]
            igmp_interface = Main.igmp_interfaces[interface_name]  # type: InterfaceIGMP
            group_state = igmp_interface.interface_state.get_group_state(kernel_entry.group_ip)
            igmp_has_members = group_state.add_multicast_routing_entry(self)
            self._local_membership_state = LocalMembership.Include if igmp_has_members else LocalMembership.NoInfo
        except:
            self._local_membership_state = LocalMembership.NoInfo

        # todo: Assert Winner State
        print("in creating tree interface - assert")
        self._assert_state = AssertState.NoInfo
        self._assert_winner_metric = Metric()
        # self._assert_timer = None
        rpc = self._kernel_entry.get_rpc()
        self._my_assert_rpc = AssertMetric(rpc.metric_preference, rpc.route_metric, self.get_ip())
        self.assert_logger.debug("Created tree interface: assert state is NoInfo")

    ############################################
    # Set ASSERT State
    ############################################
    def set_assert_state(self, new_state: AssertStateABC, creating_interface=False):
        """
        Set Assert state (AssertWinner , AssertLoser or NoInfo)
        """

        with self.get_state_lock():
            if new_state != self._assert_state:
                self._assert_state = new_state
                self.assert_logger.debug('Assert state transitions to ' + str(new_state))

                if not creating_interface:
                    self.change_tree()
                    self.evaluate_in_tree()

    def set_assert_winner_metric(self, new_assert_metric):

        with self.get_state_lock():
            try:
                old_neighbor = self.get_interface().get_neighbor(self._assert_winner_metric.get_ip())
                new_neighbor = self.get_interface().get_neighbor(new_assert_metric.get_ip())

                if old_neighbor is not None:
                    old_neighbor.unsubscribe_nlt_expiration(self)
                if new_neighbor is not None:
                    new_neighbor.subscribe_nlt_expiration(self)
            except:
                print(traceback.format_exc())
            finally:
                self._assert_winner_metric = new_assert_metric

    ###########################################
    # Recv packets
    ###########################################
    def recv_data_msg(self):
        """
        This interface received a data packet
        """
        pass

    def recv_assert_msg(self, received_metric):

        print("in recv_assert_msg function in TreeInterface")

        # Event 1, Event 2
        if self.is_assert_winner():
            # Event 1
            if not received_metric.is_better_than(self.my_assert_metric()):
                self._assert_state.receivedInferiorMetric(self, received_metric)
            # Event 2
            elif received_metric.is_better_than(self.my_assert_metric()):
                self._assert_state.receivedPreferedMetric(self, received_metric)
           
        # Event 3, Event 4, Event 5
        elif self.is_assert_loser():
            if self._assert_winner_metric.ip_address == received_metric.ip_address:
                if received_metric.is_better_than(self.my_assert_metric()):
                    self._assert_state.updateAWinfo(self, received_metric)
                else:
                    self._assert_state.receivedInferiorMetricFromWinner(self, received_metric)
            else:
                if received_metric.is_better_than(self._assert_winner_metric):
                    self._assert_state.updateAWinfo(self, received_metric)


    ######################################
    # Send messages
    ######################################
    def get_sync_state(self):
        """
        Determine if this tree must be included in a new snapshot
        By default not include this tree in snapshot... This behavior is overrode by subclasses (in NonRoot interfaces)
        """
        return None

    def send_join(self):
        """
        Send a Join message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None:
            if not self.is_interface_connected_to_source():
                self.get_interface().send_join(source, group)

    def send_prune(self):
        """
        Send a Prune message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None:
            if not self.is_interface_connected_to_source():
                self.get_interface().send_prune(source, group)

    def send_assert(self):
        print("send assert")
        """
        Send an Assert message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None and self.is_downstream():
            self.get_interface().send_assert(source, group, self._my_assert_rpc)

    def send_assert_cancel(self):
        print("send assert cancel")
        """
        Send an Assert cancel message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None and self.is_downstream():
            self.get_interface().send_assert(source, group, Metric())

    #############################################################
    @abstractmethod
    def is_forwarding(self):
        """
        Determine if this interface must be included in the OIL at the multicast routing table...
        This method must be overrode by subclasses
        """
        pass

    def assert_winner_nlt_expires(self):

        if self.is_assert_loser():
            self._assert_state.winnerLivelinessTimerExpires(self)

    @abstractmethod
    def delete(self):
        """
        Tree interface is being removed... due to change of interface roles or
        due to the removal of the tree by this router
        Clear all state from this interface regarding this tree
        """
        (s, g) = self.get_tree_id()
        # unsubscribe igmp information
        try:
            interface_name = Main.kernel.vif_index_to_name_dic[self._interface_id]
            igmp_interface = Main.igmp_interfaces[interface_name]  # type: InterfaceIGMP
            group_state = igmp_interface.interface_state.get_group_state(g)
            group_state.remove_multicast_routing_entry(self)
        except:
            pass

        # assert state

        if self.is_assert_winner() or self.is_assert_loser():
            self.send_assert_cancel()

        self._assert_state = None
        self._my_assert_rpc = None
        self.set_assert_winner_metric(AssertMetric.infinite_assert_metric())  # unsubscribe from current AssertWinner NeighborLivenessTimer
        self._assert_winner_metric = None

        print('Tree Interface deleted')

    def is_node_in_tree(self):
        """
        Determine if this router is interested in receiving data packets
        """
        
        return self._kernel_entry.is_in_tree()

    def evaluate_in_tree(self):
        """
        Verify if there are changes regarding interest of the router...
        This method is invoked whenever a new interface is included in the OIL or if an interface is removed from it
        """

        self._kernel_entry.evaluate_in_tree_change()

    ###########################################################
    # Interest state
    ###########################################################
    def change_interest_state(self, interest_state):
        """
        A neighbor has changed Interest state due to the reception of any control packet
        (Join or Prune or Sync)
        """
        return

    #############################################################
    # Local Membership (IGMP)
    ############################################################
    def check_igmp_state(self):
        """
        Reverify IGMP state of this group whenever this interface enabled or disabled IGMP
        """
        (_, group_ip) = self.get_tree_id()
        with self._igmp_lock:
            try:
                interface_name = Main.kernel.vif_index_to_name_dic[self._interface_id]
                igmp_interface = Main.igmp_interfaces[interface_name]  # type: InterfaceIGMP
                group_state = igmp_interface.interface_state.get_group_state(group_ip)
                self._igmp_has_members = group_state.add_multicast_routing_entry(self)
                igmp_has_members = group_state.add_multicast_routing_entry(self)
                self._local_membership_state = LocalMembership.Include if igmp_has_members else LocalMembership.NoInfo
            except:
                self._local_membership_state = LocalMembership.NoInfo

            self.change_tree()
            self.evaluate_in_tree()


    def notify_igmp(self, has_members: bool):
        """
        IGMP detected a change of membership regarding the group of this tree
        """
        with self.get_state_lock():
            with self._igmp_lock:
                if has_members != self._local_membership_state.has_members():
                    self._local_membership_state = LocalMembership.Include if has_members else LocalMembership.NoInfo
                    self.change_tree()
                    self.evaluate_in_tree()

    def igmp_has_members(self):
        """
        Determine if there are hosts interested in receiving data packets regarding this tree
        """

        with self._igmp_lock:
            return self._local_membership_state.has_members()

    def get_interface(self):
        """
        Get the InterfaceProtocol object regarding this physical interface
        """
        interface = Main.interfaces.get(self.get_interface_name(), None)
        return interface

    def get_interface_name(self):
        """
        Get interface name of this interface
        """
        kernel = Main.kernel
        return kernel.vif_index_to_name_dic.get(self._interface_id, None)

    def get_ip(self):
        """
        Get IP of this interface
        """
        if_name = self.get_interface_name()
        ip = netifaces.ifaddresses(if_name)[netifaces.AF_INET][0]['addr']
        return ip

    def get_interface_netmask(self):
        """
        Get Netmask of this interface
        """
        if_name = self.get_interface_name()
        return netifaces.ifaddresses(if_name)[netifaces.AF_INET][0]["netmask"]

    def is_interface_connected_to_source(self):
        """
        Determine if this interface is connected to the source of multicast traffic
        """
        source_ip = self.get_tree_id()[0]
        if_address = self.get_ip() + "/" + self.get_interface_netmask()
        return ipaddress.ip_address(source_ip) in ipaddress.ip_interface(if_address).network

    def get_tree_id(self):
        """
        Get tree id, i.e. pair (Source, Group) IPs
        """
        return (self._kernel_entry.source_ip, self._kernel_entry.group_ip)

    def change_tree(self):
        """
        Re-set multicast routing table...
        Invoked whenever there are state transitions
        """
        self._kernel_entry.change()

    def get_state_lock(self):
        """
        Obtain lock used to change state of an interface
        """
        return self._kernel_entry.CHANGE_STATE_LOCK

    @abstractmethod
    def is_downstream(self):
        raise NotImplementedError()

    ###########################################
    # Change to in/out-tree
    ###########################################
    def node_is_out_tree(self):
        return

    def node_is_in_tree(self):
        return

    ###################################################
    # RPC Change
    ###################################################
    def notify_rpc_change(self, new_rpc):
        return

        # obtain ip of RPF'(S)

    def get_neighbor_RPF(self):
        """
        RPF'(S)
        """
        if self.i_am_assert_loser():
            return self._assert_winner_metric.get_ip()
        else:
            return self._kernel_entry.rpf_node

    ###################################################
    # ASSERT
    ###################################################

    def lost_assert(self):
        if not self.is_downstream():
            return False
        else:
            return not self._assert_winner_metric.i_am_assert_winner(self) and \
                   self._assert_winner_metric.is_better_than(AssertMetric.spt_assert_metric(self))

    def could_assert(self):
        return self.is_downstream()

    def my_assert_metric(self):
        """
        The assert metric of this interface for usage in assert state machine
        @rtype: AssertMetric
        """
        if self.could_assert():
            return self._my_assert_rpc
        else:
            return AssertMetric.infinite_assert_metric()

    def i_am_assert_loser(self):
        return self._assert_state == AssertState.Loser

    @abstractmethod
    def verify_assert(self):
        return

    def is_assert_winner(self):
        """
        Determine if this interface is responsible for forwarding multicast data packets
        """
        return self._assert_state is not None and self._assert_state.is_assert_winner()

    def is_assert_loser(self):
        return self._assert_state is not None and self._assert_state.is_assert_loser()

    def is_no_info(self):
        return self._assert_state is not None and self._assert_state.is_no_info()

