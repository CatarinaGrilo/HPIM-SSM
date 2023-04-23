import logging
import traceback
from threading import Thread


import Main

from . import DataPacketsSocket
from .upstream_state import SFMRPruneState, SFMRUpstreamStateABC
from .root_state_machine import SFMRNewRootState  # SFMRRootState
from .tree_interface import TreeInterface
from .metric import AssertMetric, Metric


class TreeInterfaceUpstream(TreeInterface):
    LOGGER = logging.getLogger('protocol.KernelEntry.RootInterface')

    def __init__(self, kernel_entry, interface_id, interest_state, best_neighbor_metric, was_non_root, was_in_tree):
        extra_dict_logger = kernel_entry.kernel_entry_logger.extra.copy()
        extra_dict_logger['vif'] = interface_id
        extra_dict_logger['interfacename'] = Main.kernel.vif_index_to_name_dic[interface_id]
        logger = logging.LoggerAdapter(TreeInterfaceUpstream.LOGGER, extra_dict_logger)
        TreeInterface.__init__(self, kernel_entry, interface_id, best_neighbor_metric, logger)
        self.upstream_logger = logging.LoggerAdapter(logger.logger.getChild('Upstream'), logger.extra)

        # Event 1
        #if was_non_root and was_in_tree:
            #self.logger.debug('it was non root?')
        #    SFMRNewRootState.interfaces_roles_change(self)


        # Originator state
        # TODO TESTE SOCKET RECV DATA PCKTS
        self.socket_is_enabled = True
        (s, g) = self.get_tree_id()
        interface_name = self.get_interface_name()
        self.socket_pkt = DataPacketsSocket.get_s_g_bpf_filter_code(s, g, interface_name)

        # run receive method in background
        receive_thread = Thread(target=self.socket_recv)
        receive_thread.daemon = True
        receive_thread.start()

        self.logger.debug('Created RootInterface')

        # Ustream Node Interest State
        if interest_state:
            self._upstream_node_interest_state = SFMRPruneState.UI
            if was_non_root:
                self.send_assert_cancel()
        else:
            self._upstream_node_interest_state = SFMRPruneState.NUI


        self.upstream_logger.debug('Upstream interest state transitions to ' + str(self._upstream_node_interest_state))


    def socket_recv(self):
        while self.socket_is_enabled:
            try:
                self.socket_pkt.recvfrom(0)
                #print("PACOTE DADOS RECEBIDO")
                #self.logger.debug('Data packet received')
                self.recv_data_msg()
            except:
                traceback.print_exc()
                print(traceback.format_exc())
                continue

    
    ##########################################
    # Set Uptream Node Interest state
    ##########################################
    def set_upstream_node_interest_state(self, new_state: SFMRUpstreamStateABC):
        """
        Set interest state of downstream nodes (DownstreamInterested or NoDownstreamInterested)
        """
        with self.get_state_lock():
            if new_state != self._upstream_node_interest_state:
                self._upstream_node_interest_state = new_state
                self.upstream_logger.debug('Upstream interest state transitions to ' + str(new_state))

                self.change_tree()
                self.evaluate_in_tree()

    ###########################################
    # Recv packets
    ###########################################
    def recv_data_msg(self):
        """
        This root interface received a data packet
        """
        return

    def change_best_neighbor_metric(self, new_best_neighbor_metric):
        super().change_best_neighbor_metric(new_best_neighbor_metric)

    def change_interest_state(self, interest_state):
        """
        A neighbor has changed Interest state due to the reception of any control packet
        (Join or Prune or Sync)
        """
        if interest_state:
            self.set_upstream_node_interest_state(SFMRPruneState.UI)

        else:
            self.set_upstream_node_interest_state(SFMRPruneState.NUI)


    ###########################################
    # Change to in/out-tree
    ###########################################
    def send_my_interest(self):
        """
        Send a Join/Prune message through this interface based on the IT/OT state of this router
        """
        #print("send interest | Potential AW: "+str(self._kernel_entry.potential_aw))
        if self.is_node_in_tree():
            self.send_join(self._kernel_entry.potential_aw)
        else:
            self.send_prune(self._kernel_entry.potential_aw)

    def notify_potential_aw_change(self, new_potential_aw):
        """
        The potential aw of the router changed
        """
        #print("ENTROU NOTIFY Potential AW CHANGE")
        if self.is_node_in_tree():
            #print("IS_NODE IN TREE")
            self.send_prune(self._kernel_entry.potential_aw)
            self.send_join(new_potential_aw)
        else:
            return
        #print("SAIU NOTIFY Potential AW CHANGE")
    
    def notify_potential_aw_change_root_changed(self, new_potential_aw, new_root):
        """
        The potential aw of the router changed
        """
        #print("ENTROU NOTIFY Potential AW CHANGE")
        if self.is_node_in_tree():
            #print("IS_NODE IN TREE")
            if new_root:
                self.send_join(new_potential_aw)
            else:
                self.send_prune(self._kernel_entry.potential_aw)
        else:
            return
        #print("SAIU NOTIFY Potential AW CHANGE")

    def node_is_out_tree(self):
        """
        Node is no longer interested in receiving data packets...
        React to this event in order to transmit some control packets
        """
        # event 7
        self.logger.debug("Router state transitions to Not Interested")
        SFMRNewRootState.interfaces_roles_dont_change_and_router_transition_to_it_or_ot(self)

    def node_is_in_tree(self):
        """
        Node becomes interested in receiving data packets...
        React to this event in order to transmit some control packets
        """
        # event 7
        self.logger.debug("Router state transitions to Interested")
        SFMRNewRootState.interfaces_roles_dont_change_and_router_transition_to_it_or_ot(self)

    ####################################################################
    def is_forwarding(self):
        """
        This interface must not be included in the OIL of the multicast routing table, thus returning False
        """
        return False

    def is_in_tree(self):
        """
        Verify if this interface is connected to interested hosts/nodes
        (based on Interest state of all neighbors and IGMP)
        """
        print("def is_in_tree() in Tree upstream")
        return self.igmp_has_members() or self.are_upstream_nodes_interested()
    
    def are_upstream_nodes_interested(self):
        """
        Determine if there is interest from non-Upstream neighbors based on their interest state
        """
        print("Are upstream nodes interested: "+ str(self._upstream_node_interest_state.are_upstream_nodes_interested()))
        return self._upstream_node_interest_state.are_upstream_nodes_interested()


    def delete(self):
        """
        Tree interface is being removed... due to change of interface roles or
        due to the removal of the tree by this router
        Clear all state from this interface regarding this tree
        """
        self.socket_is_enabled = False
        if self.is_interface_connected_to_source():
            try:
                from socket import SHUT_RDWR
                self.socket_pkt.shutdown(SHUT_RDWR)
            except:
                pass

        self.socket_pkt.close()
        super().delete()

    def is_downstream(self):
        return False

    def is_upstream(self):
        #print("def is_upstream() in Tree Upstream")
        return self._upstream_node_interest_state.are_upstream_nodes_interested()

    ###########################################
    # Send packets
    ###########################################
    def get_sync_state(self, neighbor_ip):
        """
        Determine if this tree must be included in a new snapshot
        If interface not connected to the source)then this must be included in the snapshot,
         otherwise this tree is not included in the snapshot
        """
        if not self.is_interface_connected_to_source():
            #print("neighbor ip: "+ str(neighbor_ip)+ " potential_AW ip: " + str(self._kernel_entry.potential_aw)+"\n\n\n\n")
            if self.is_node_in_tree() and neighbor_ip == self._kernel_entry.potential_aw:
                return AssertMetric.infinite_assert_metric()
            else:
                return False
        else:
            return False

    def send_assert_cancel(self):
        #print("ROOT: send assert cancel")
        """
        Send an Assert cancel message through this interface
        """
        (source, group) = self.get_tree_id()
        if self.get_interface() is not None:
            self.get_interface().send_assert(source, group, Metric())
