import logging

import Main

from .downstream_state import SFMRPruneState, SFMRDownstreamStateABC
from .metric import Metric
from .non_root_state_machine import SFMRNonRootState
from .tree_interface import TreeInterface
from .metric import AssertMetric, Metric
from .assert_state import AssertState, SFMRAssertABC


class TreeInterfaceDownstream(TreeInterface):
    LOGGER = logging.getLogger('hpim.KernelEntry.NonRootInterface')

    def __init__(self, kernel_entry, interface_id, rpc: Metric, interest_state, best_neighbor_metric, was_root, was_in_tree):
        extra_dict_logger = kernel_entry.kernel_entry_logger.extra.copy()
        extra_dict_logger['vif'] = interface_id
        extra_dict_logger['interfacename'] = Main.kernel.vif_index_to_name_dic[interface_id]
        logger = logging.LoggerAdapter(TreeInterfaceDownstream.LOGGER, extra_dict_logger)
        TreeInterface.__init__(self, kernel_entry, interface_id, best_neighbor_metric, logger)
        self.assert_logger = logging.LoggerAdapter(logger.logger.getChild('Assert'), logger.extra)
        self.downstream_logger = logging.LoggerAdapter(logger.logger.getChild('Downstream'), logger.extra)


        # Downstream Node Interest State
        if interest_state:
            self._downstream_node_interest_state = SFMRPruneState.DI
        else:
            self._downstream_node_interest_state = SFMRPruneState.NDI

        self.downstream_logger.debug('Downstream interest state transitions to ' + str(self._downstream_node_interest_state))

        # Assert State

        if Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None) is None:
            Main.kernel.assert_state_per_interface[(self._kernel_entry.source_ip, self._interface_id)] = AssertState.NotAvailable
            self.assert_logger.debug('Assert state transitions to ' + 
                                    str(Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None)))
        #self._assert = Main.kernel.assert_state_per_interface[(self._kernel_entry.source_ip, self._interface_id)]
        self._assert=AssertState.NotAvailable

        if Main.kernel.my_rpc.get((self._kernel_entry.source_ip, self._interface_id), None) is None:
            Main.kernel.my_rpc[(self._kernel_entry.source_ip, self._interface_id)] = AssertMetric(rpc.metric_preference, rpc.route_metric, self.get_ip())
        
        self.verify_assert(creating_interface=True)


        # Deal with messages according to tree state and interface role change

        # Event 1
        #if was_root and interest_state:
        if was_root and was_in_tree:
            #self.downstream_logger.debug("event 1")
            SFMRNonRootState.interface_roles_change(self)


        #self.logger.debug('Created NonRootInterface')


    ############################################
    # Set ASSERT State
    ############################################
    def set_assert_state(self, new_state: SFMRAssertABC, creating_interface=False):
        """
        Set Assert state (AssertWinner , AssertLoser, NotAvailable)
        """

        with self.get_state_lock():
            if new_state != Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None):
                Main.kernel.assert_state_per_interface[(self._kernel_entry.source_ip, self._interface_id)] = new_state
                self._assert = new_state
                self.assert_logger.debug('Assert state transitions to ' + str(new_state))

                if not creating_interface:
                    self.change_tree()
                    self.evaluate_in_tree()

    ##########################################
    # Set Downstream Node Interest state
    ##########################################
    def set_downstream_node_interest_state(self, new_state: SFMRDownstreamStateABC):
        """
        Set interest state of downstream nodes (DownstreamInterested or NoDownstreamInterested)
        """
        with self.get_state_lock():
            if new_state != self._downstream_node_interest_state:
                self._downstream_node_interest_state = new_state
                self.downstream_logger.debug('Downstream interest state transitions to ' + str(new_state))

                self.verify_assert(creating_interface=False)
                self.change_tree()
                self.evaluate_in_tree()

    ###########################################
    # Recv packets
    ###########################################

    def change_interest_state(self, interest_state):
        """
        A neighbor has changed Interest state due to the reception of any control packet
        (Join or Prune or Sync)
        """
        #print("In change_interest_state interface " + str(self._interface_id))
        if interest_state:
            self.set_downstream_node_interest_state(SFMRPruneState.DI)

        else:
            self.set_downstream_node_interest_state(SFMRPruneState.NDI)

    ###########################################
    # Send packets
    ###########################################

    def get_sync_state(self, neighbor_ip):
        if self.are_downstream_nodes_interested() and Main.kernel.my_rpc.get((self._kernel_entry.source_ip, self._interface_id), None) is not None:
            return (Main.kernel.my_rpc.get((self._kernel_entry.source_ip, self._interface_id), None))
        else:
            return False

    ##########################################################
    def is_forwarding(self):
        """
        Determine if this interface must be included in the OIL at the multicast routing table
        """
        return self.is_in_tree() and self.is_assert_winner()

    def is_in_tree(self):
        """
        Verify if this interface is connected to interested hosts/nodes
        (based on Interest state of all neighbors and IGMP)
        """
        #print("def is_in_tree() in Tree Downstream")
        #print("In is in tree interface " + str(self._interface_id))
        return self.igmp_has_members() or self.are_downstream_nodes_interested()

    def are_downstream_nodes_interested(self):
        """
        Determine if there is interest from non-Upstream neighbors based on their interest state
        """
        #print("Are downstream nodes interested: " + str(self._downstream_node_interest_state.are_downstream_nodes_interested()))
        return self._downstream_node_interest_state.are_downstream_nodes_interested()

    def delete(self):
        """
        Tree interface is being removed... due to change of interface roles or
        due to the removal of the tree by this router
        Clear all state from this interface regarding this tree
        """
        super().delete()
        self._assert = None
        #self.send_assert_cancel()

    def is_downstream(self):
        return True

    def is_upstream(self):
        return False

    def notify_rpc_change(self, new_rpc: Metric):
        """
        The router suffered an RPC regarding the subnet of the tree's source
        """
        if new_rpc == Main.kernel.my_rpc.get((self._kernel_entry.source_ip, self._interface_id), None) and\
            self._assert == Main.kernel.assert_state_per_interface[(self._kernel_entry.source_ip, self._interface_id)]:
            return

        Main.kernel.my_rpc[(self._kernel_entry.source_ip, self._interface_id)] = AssertMetric(new_rpc.metric_preference, new_rpc.route_metric, self.get_ip())
        if not self.is_interface_connected_to_source() and \
            Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None) == AssertState.Winner:
            SFMRNonRootState.my_rpc_changes(self)
        self.verify_assert(creating_interface=False)

    def verify_assert(self, creating_interface=False):
        """
        verify changes in the assert due to changes in the interest
        """
        # self.downstream_logger.debug('best_neighbor_metric: ' + str(self._best_neighbor_metric))

        previous_assert_state = Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None)
        if self.is_in_tree():
            if Main.kernel.best_assert_neighbor_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None) is None \
                or Main.kernel.my_rpc.get((self._kernel_entry.source_ip, self._interface_id), None).is_better_than(Main.kernel.best_assert_neighbor_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None)):
                if Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None) != AssertState.Winner:
                    self.set_assert_state(AssertState.Winner, creating_interface)
                    if previous_assert_state == AssertState.NotAvailable:
                        self.send_assert()

            elif not Main.kernel.my_rpc.get((self._kernel_entry.source_ip, self._interface_id), None).is_better_than(Main.kernel.best_assert_neighbor_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None)):
                self.set_assert_state(AssertState.Loser, creating_interface)
                if previous_assert_state == AssertState.NotAvailable:
                    self.send_assert()

        elif not self.is_in_tree():
            routing_entries = []
            still_are_groups_DI = False
            for a in list(Main.kernel.routing.values()):
                for b in list(a.values()):
                    routing_entries.append(b)
            for entry in routing_entries:
                upstream_if_index = entry.inbound_interface_index
                if entry.interface_state.get(self._interface_id, None) is not None:
                    interface_state = entry.interface_state[self._interface_id]
                    if self._interface_id != upstream_if_index:
                        if interface_state._downstream_node_interest_state == SFMRPruneState.DI:
                            still_are_groups_DI=True
                            break
            if not still_are_groups_DI:
                if Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None) != AssertState.NotAvailable:
                    self.set_assert_state(AssertState.NotAvailable, creating_interface)
                    self.send_assert_cancel()

        if self._assert != Main.kernel.assert_state_per_interface[(self._kernel_entry.source_ip, self._interface_id)]:
            self._assert = Main.kernel.assert_state_per_interface[(self._kernel_entry.source_ip, self._interface_id)]
            if not creating_interface:
                    self.change_tree()
                    self.evaluate_in_tree()

    def my_assert_metric(self):
        """
        The assert metric of this interface for usage in assert state machine
        @rtype: AssertMetric
        """
        if self.is_downstream():
            return Main.kernel.my_rpc.get((self._kernel_entry.source_ip, self._interface_id), None)
        else:
            return AssertMetric.infinite_assert_metric()

    def is_assert_winner(self):
        """
        Determine if this interface is responsible for forwarding multicast data packets
        """
        return self._assert is not None and self._assert.is_assert_winner()

    def is_assert_loser(self):

        if Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None) is not None:
            return not Main.kernel.assert_state_per_interface.get((self._kernel_entry.source_ip, self._interface_id), None).is_assert_winner()
        else:
            return False

    ###########################################
    # Send packets
    ###########################################

    def send_assert(self):
        """
        Send an Assert message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None and self.is_downstream():
            self.get_interface().send_assert(source, group, Main.kernel.my_rpc[(self._kernel_entry.source_ip, self._interface_id)])

    def send_assert_cancel(self):
        """
        Send an Assert cancel message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None and self.is_downstream():
            self.get_interface().send_assert(source, group, Metric())

    def change_best_neighbor_metric(self, new_best_neighbor_metric):
        super().change_best_neighbor_metric(new_best_neighbor_metric)
        self.verify_assert(creating_interface=False)
