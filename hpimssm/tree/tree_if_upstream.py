import logging
import traceback
from threading import Thread


from hpimssm import Main

from . import DataPacketsSocket
from .root_state_machine import SFMRNewRootState  # SFMRRootState
from .tree_interface import TreeInterface


class TreeInterfaceUpstream(TreeInterface):
    LOGGER = logging.getLogger('protocol.KernelEntry.RootInterface')

    def __init__(self, kernel_entry, interface_id, was_non_root, was_in_tree):
        extra_dict_logger = kernel_entry.kernel_entry_logger.extra.copy()
        extra_dict_logger['vif'] = interface_id
        extra_dict_logger['interfacename'] = Main.kernel.vif_index_to_name_dic[interface_id]
        logger = logging.LoggerAdapter(TreeInterfaceUpstream.LOGGER, extra_dict_logger)
        TreeInterface.__init__(self, kernel_entry, interface_id, logger)

        # Event 1
        #if was_non_root and was_in_tree:
            #self.logger.debug('it was non root?')
         #   SFMRNewRootState.interfaces_roles_change(self)


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

    def socket_recv(self):
        while self.socket_is_enabled:
            try:
                self.socket_pkt.recvfrom(0)
                print("PACOTE DADOS RECEBIDO")
                self.logger.debug('Data packet received')
                self.recv_data_msg()
            except:
                traceback.print_exc()
                print(traceback.format_exc())
                continue

    ###########################################
    # Recv packets
    ###########################################
    def recv_data_msg(self):
        """
        This root interface received a data packet
        """
        return

    ###########################################
    # Change to in/out-tree
    ###########################################
    def send_my_interest(self):
        """
        Send a Join/Prune message through this interface based on the IT/OT state of this router
        """
        if self.is_node_in_tree():
            self.send_join()
        else:
            self.send_prune()

    def node_is_out_tree(self):
        """
        Node is no longer interested in receiving data packets...
        React to this event in order to transmit some control packets
        """
        # event 7
        SFMRNewRootState.interfaces_roles_dont_change_and_router_transition_to_it_or_ot(self)

    def node_is_in_tree(self):
        """
        Node becomes interested in receiving data packets...
        React to this event in order to transmit some control packets
        """
        # event 7
        SFMRNewRootState.interfaces_roles_dont_change_and_router_transition_to_it_or_ot(self)

    ####################################################################
    def is_forwarding(self):
        """
        This interface must not be included in the OIL of the multicast routing table, thus returning False
        """
        return False

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


    def verify_assert(self, creating_interface=False):
        """
        verify changes in the assert due to changes in the interest
        """
        return
    ###########################################
    # Send packets
    ###########################################
    def get_sync_state(self):
        """
        Determine if this tree must be included in a new snapshot
        If interface not connected to the source)then this must be included in the snapshot,
         otherwise this tree is not included in the snapshot
        """
        if not self.is_interface_connected_to_source():
            if self.is_node_in_tree():
                return True
            elif self.get_ip() == '10.0.0.4':
                return True
        else:
            return False

