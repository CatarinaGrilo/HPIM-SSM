import logging

from hpimssm import Main

from .downstream_state import SFMRPruneState, SFMRDownstreamStateABC
from .metric import Metric
from .non_root_state_machine import SFMRNonRootState
from .tree_interface import TreeInterface
from .metric import AssertMetric, Metric
from .assert_state import AssertState


class TreeInterfaceDownstream(TreeInterface):
    LOGGER = logging.getLogger('protocol.KernelEntry.NonRootInterface')

    def __init__(self, kernel_entry, interface_id, rpc: Metric, interest_state, was_root, was_in_tree):
        extra_dict_logger = kernel_entry.kernel_entry_logger.extra.copy()
        extra_dict_logger['vif'] = interface_id
        extra_dict_logger['interfacename'] = Main.kernel.vif_index_to_name_dic[interface_id]
        logger = logging.LoggerAdapter(TreeInterfaceDownstream.LOGGER, extra_dict_logger)
        TreeInterface.__init__(self, kernel_entry, interface_id, logger)
        self.assert_logger = logging.LoggerAdapter(logger.logger.getChild('Assert'), logger.extra)
        self.downstream_logger = logging.LoggerAdapter(logger.logger.getChild('Downstream'), logger.extra)


        # Downstream Node Interest State
        if interest_state:
            self._downstream_node_interest_state = SFMRPruneState.DI
        else:
            self._downstream_node_interest_state = SFMRPruneState.NDI

        self.downstream_logger.debug('Downstream interest state transitions to ' + str(self._downstream_node_interest_state))


        # Deal with messages according to tree state and interface role change

        # Event 1
        if was_root and was_in_tree:
            self.downstream_logger.debug("event 1")
            SFMRNonRootState.interface_roles_change(self)

        self.verify_assert(creating_interface=True)

        self.logger.debug('Created NonRootInterface')

        '''
        # Event 2
        if interest_state and self.is_downstream() and not was_root:
            self.downstream_logger.debug("event 3")
            SFMRNonRootState.interface_becomes_assert_capable(self)
    
        '''


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
    def recv_data_msg(self):
        """
        This Non-Root interface received a data packet
        """
        return

    def change_interest_state(self, interest_state):
        """
        A neighbor has changed Interest state due to the reception of any control packet
        (Join or Prune or Sync)
        """
        if interest_state:
            self.set_downstream_node_interest_state(SFMRPruneState.DI)

        else:
            self.set_downstream_node_interest_state(SFMRPruneState.NDI)

    ###########################################
    # Send packets
    ###########################################

    def get_sync_state(self):
        return None


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
        print("def si_in_tree() in Tree Downstream")
        return self.igmp_has_members() or self.are_downstream_nodes_interested()

    def are_downstream_nodes_interested(self):
        """
        Determine if there is interest from non-Upstream neighbors based on their interest state
        """
        print("in are_downstream_nodes_interested function")
        print(self._downstream_node_interest_state.are_downstream_nodes_interested())
        return self._downstream_node_interest_state.are_downstream_nodes_interested()

    def delete(self):
        """
        Tree interface is being removed... due to change of interface roles or
        due to the removal of the tree by this router
        Clear all state from this interface regarding this tree
        """
        super().delete()
        #self._my_assert_rpc = None

    def is_downstream(self):
        return True

    def notify_rpc_change(self, new_rpc: Metric):
        """
        The router suffered an RPC regarding the subnet of the tree's source
        """
        print("ENTROU NOTIFY RPC CHANGE")
        if new_rpc == self._my_assert_rpc:
            return

        self._my_assert_rpc = AssertMetric(new_rpc.metric_preference, new_rpc.route_metric, self.get_ip())
        if self.is_assert_winner() and self.is_downstream():
            SFMRNonRootState.my_rpc_changes(self)
        elif self.is_assert_loser() and self._my_assert_rpc.is_better_than(self._assert_winner_metric) and \
                self.is_downstream():
            SFMRNonRootState.my_rpc_becomes_better_than_aw(self)

        print("SAIU NOTIFY RPC CHANGE")

    def verify_assert(self, creating_interface=False):
        """
        verify changes in the assert due to changes in the interest
        """
        self.downstream_logger.debug("ENTROU VERIFY ASSERT")

        if self.is_downstream() and self.is_in_tree() and self.is_no_info():
            #SFMRNonRootState.interface_becomes_assert_capable(self)
            self.set_assert_winner_metric(self.my_assert_metric())
            self.set_assert_state(AssertState.Winner, creating_interface)
            self.send_assert()

        elif self.is_downstream() and (self.is_assert_winner() or self.is_assert_loser()):
            if not self.is_in_tree():
                #SFMRNonRootState.interface_stops_being_assert_capable(self)
                if self.is_assert_winner():
                    self.send_assert_cancel()
                self.set_assert_winner_metric(AssertMetric.infinite_assert_metric())
                self.set_assert_state(AssertState.NoInfo, creating_interface)

        self.downstream_logger.debug("SAIU VERIFY ASSERT")
