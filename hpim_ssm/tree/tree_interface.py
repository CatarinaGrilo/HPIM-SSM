import ipaddress
import logging
import traceback
from abc import ABCMeta, abstractmethod
from threading import RLock
import time

import netifaces
import Main
from .assert_state import AssertState, SFMRAssertABC
from .local_membership import LocalMembership
from .metric import AssertMetric, Metric


class TreeInterface(metaclass=ABCMeta):
    def __init__(self, kernel_entry, interface_id, best_neighbor_metric, logger: logging.LoggerAdapter):
        self._kernel_entry = kernel_entry
        self._interface_id = interface_id
        self.logger = logger
        self.assert_logger = logging.LoggerAdapter(logger.logger.getChild('Assert'), logger.extra)

        self._best_neighbor_metric = best_neighbor_metric  # current Assert Winner

        # Local Membership State
        self._igmp_lock = RLock()
        try:
            interface_name = Main.kernel.vif_index_to_name_dic[interface_id]
            igmp_interface = Main.igmp_interfaces[interface_name]  #InterfaceIGMP
            group_state = igmp_interface.interface_state.get_group_state(kernel_entry.group_ip)
            igmp_has_members = group_state.add_multicast_routing_entry(self)
            self._local_membership_state = LocalMembership.Include if igmp_has_members else LocalMembership.NoInfo
        except:
            self._local_membership_state = LocalMembership.NoInfo




    ###########################################
    # Recv packets
    ###########################################

    def recv_assert_msg(self, metric_state):
        """
        This interface received a data packet
        """
        pass


    ######################################
    # Send messages
    ######################################
    def get_sync_state(self, neighbor_ip):
        """
        Determine if this tree must be included in a new snapshot
        By default not include this tree in snapshot... This behavior is overrode by subclasses (in NonRoot interfaces)
        """
        return None

    def send_join(self, dst):
        """
        Send a Join message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None:
            if not self.is_interface_connected_to_source():
                self.get_interface().send_join(source, group, dst)

    def send_prune(self, dst):
        """
        Send a Prune message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None:
            if not self.is_interface_connected_to_source():
                self.get_interface().send_prune(source, group, dst)


    #############################################################
    @abstractmethod
    def is_forwarding(self):
        """
        Determine if this interface must be included in the OIL at the multicast routing table...
        This method must be overrode by subclasses
        """
        pass

    def assert_winner_nlt_expires(self):
        pass
        #if self.is_assert_loser():
         #   self._assert_state.winnerLivelinessTimerExpires(self)

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
            igmp_interface = Main.igmp_interfaces[interface_name]  # InterfaceIGMP
            group_state = igmp_interface.interface_state.get_group_state(g)
            group_state.remove_multicast_routing_entry(self)
        except:
            pass

        print('Tree (' + str(self._kernel_entry.source_ip) + ', ' + str(self._kernel_entry.group_ip) +') Interface deleted')

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
                igmp_interface = Main.igmp_interfaces[interface_name]  #InterfaceIGMP
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

    @abstractmethod
    def is_upstream(self):
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

    ###################################################
    # ASSERT
    ###################################################

    def verify_assert(self):
        """
        Calculate the router responsible for forwarding data packets to a link...
        This method must be overrode by subclasses
        """
        return

    def change_best_neighbor_metric(self, new_best_neighbor_metric):
        self._best_neighbor_metric = new_best_neighbor_metric

