import logging

import Main

from .downstream_state import SFMRPruneState, SFMRDownstreamStateABC
from .metric import Metric
from .non_root_state_machine import SFMRNonRootState
from .tree_interface import TreeInterface
from .metric import AssertMetric, Metric
from .assert_state import AssertState, SFMRAssertABC


class TreeInterfaceDownstream(TreeInterface):
    LOGGER = logging.getLogger('protocol.KernelEntry.NonRootInterface')

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
        
        self._assert_state = AssertState.NotAvailable

        self.assert_logger.debug('Assert state transitions to ' + str(self._assert_state))
        self._my_assert_rpc = AssertMetric(rpc.metric_preference, rpc.route_metric, self.get_ip())
        self.verify_assert(creating_interface=True)


        # Deal with messages according to tree state and interface role change

        # Event 1
        #if was_root and interest_state:
        if was_root and was_in_tree:
            self.downstream_logger.debug("event 1")
            SFMRNonRootState.interface_roles_change(self)


        self.logger.debug('Created NonRootInterface')


    ############################################
    # Set ASSERT State
    ############################################
    def set_assert_state(self, new_state: SFMRAssertABC, creating_interface=False):
        """
        Set Assert state (AssertWinner , AssertLoser, NotAvailable)
        """

        with self.get_state_lock():
            if new_state != self._assert_state:
                self._assert_state = new_state
                self.assert_logger.debug('Interface ' + str(self._interface_id) + 'Assert state transitions to ' + str(new_state))

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
                self.downstream_logger.debug('Interface ' + str(self._interface_id) + 'Downstream interest state transitions to ' + str(new_state))

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
        print("In change_interest_state interface " + str(self._interface_id))
        if interest_state:
            self.set_downstream_node_interest_state(SFMRPruneState.DI)

        else:
            self.set_downstream_node_interest_state(SFMRPruneState.NDI)

    ###########################################
    # Send packets
    ###########################################

    def get_sync_state(self, neighbor_ip):
        if self.are_downstream_nodes_interested():
            return self._my_assert_rpc
        else:
            return False
            #return AssertMetric.infinite_assert_metric()

    ##########################################################
    def is_forwarding(self):
        """
        Determine if this interface must be included in the OIL at the multicast routing table
        """

        #return self.is_in_tree() and self.is_assert_winner() and not self.is_interface_connected_to_source()
        #if self.is_in_tree() and self.is_assert_winner():
            #self.downstream_logger.debug('Interface is FORWARDING')
        return self.is_in_tree() and self.is_assert_winner()

    def is_in_tree(self):
        """
        Verify if this interface is connected to interested hosts/nodes
        (based on Interest state of all neighbors and IGMP)
        """
        #print("def is_in_tree() in Tree Downstream")
        print("In is in tree interface " + str(self._interface_id))
        return self.igmp_has_members() or self.are_downstream_nodes_interested()

    def are_downstream_nodes_interested(self):
        """
        Determine if there is interest from non-Upstream neighbors based on their interest state
        """
        print("Are downstream nodes interested: " + str(self._downstream_node_interest_state.are_downstream_nodes_interested()))
        return self._downstream_node_interest_state.are_downstream_nodes_interested()

    def delete(self):
        """
        Tree interface is being removed... due to change of interface roles or
        due to the removal of the tree by this router
        Clear all state from this interface regarding this tree
        """
        super().delete()
        self._my_assert_rpc = None
        self._assert_state = None
        #self.send_assert_cancel()

    def is_downstream(self):
        return True

    def is_upstream(self):
        return False


    def notify_rpc_change(self, new_rpc: Metric):
        """
        The router suffered an RPC regarding the subnet of the tree's source
        """
        if new_rpc == self._my_assert_rpc:
            return

        self._my_assert_rpc = AssertMetric(new_rpc.metric_preference, new_rpc.route_metric, self.get_ip())
        if not self.is_interface_connected_to_source() and self._assert_state == AssertState.Winner:
            SFMRNonRootState.my_rpc_changes(self)
        self.verify_assert(creating_interface=False)

    def verify_assert(self, creating_interface=False):
        """
        verify changes in the assert due to changes in the interest
        """
        # self.downstream_logger.debug("entrou verify_assert")
        # self.downstream_logger.debug('best_neighbor_metric: ' + str(self._best_neighbor_metric))

        '''
        # NDI -> DI
        # MY RPC CHANGES AND BECOMES THE BEST
        # RECEIVE ASSERT WITH WORSE RPC THAN MINE
        # THE AW IS GONE
        if self.is_downstream() and self.is_in_tree() and not self.is_assert_winner():
            self.downstream_logger.debug('va1')
            if self._best_neighbor_metric is None:
                self.downstream_logger.debug('va12')
                self.set_assert_state(AssertState.Winner, creating_interface)

            elif self._my_assert_rpc.is_better_than(self._best_neighbor_metric):
                self.downstream_logger.debug('va2')
                self.set_assert_state(AssertState.Winner, creating_interface)

        # DI -> NDI
        elif self.is_downstream() and not self.is_in_tree() and self.is_assert_winner():
            self.downstream_logger.debug('va3')
            self.set_assert_state(AssertState.Loser, creating_interface)
            self.downstream_logger.debug('va4')

        # MY RPC CHANGES AND I AM NO LONGER AW
        # RECEIVE ASSERT WITH BETTER RPC THAN MINE
        elif self.is_downstream() and self.is_in_tree() and self.is_assert_winner():
            self.downstream_logger.debug('va5')
            if not self._my_assert_rpc.is_better_than(self._best_neighbor_metric):
                self.downstream_logger.debug('va6')
                self.set_assert_state(AssertState.Loser, creating_interface)
        '''
        ###################################################################
        previous_assert_state = self._assert_state
        if self.is_in_tree():
            if self._best_neighbor_metric is None or self._my_assert_rpc.is_better_than(self._best_neighbor_metric):
                if self._assert_state != AssertState.Winner:
                    self.set_assert_state(AssertState.Winner, creating_interface)
                    if previous_assert_state == AssertState.NotAvailable:
                        self.send_assert()

            elif not self._my_assert_rpc.is_better_than(self._best_neighbor_metric):
                self.set_assert_state(AssertState.Loser, creating_interface)
                if previous_assert_state == AssertState.NotAvailable:
                    self.send_assert()

        elif not self.is_in_tree():
            if self._assert_state != AssertState.NotAvailable:
                self.set_assert_state(AssertState.NotAvailable, creating_interface)
                self.send_assert_cancel()
            

        #self.downstream_logger.debug("saiu verify assert")

    def my_assert_metric(self):
        """
        The assert metric of this interface for usage in assert state machine
        @rtype: AssertMetric
        """
        if self.is_downstream():
            return self._my_assert_rpc
        else:
            return AssertMetric.infinite_assert_metric()

    def is_assert_winner(self):
        """
        Determine if this interface is responsible for forwarding multicast data packets
        """
        return self._assert_state is not None and self._assert_state.is_assert_winner()

    def is_assert_loser(self):
        return self._assert_state is not None and self._assert_state.is_assert_winner()


    ###########################################
    # Send packets
    ###########################################

    def send_assert(self):
        """
        Send an Assert message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None and self.is_downstream():
            self.get_interface().send_assert(source, group, self._my_assert_rpc)

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
