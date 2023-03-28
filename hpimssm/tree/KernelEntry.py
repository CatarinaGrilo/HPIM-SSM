import logging
from threading import Lock, RLock

from hpimssm import Main
from hpimssm import UnicastRouting

from .metric import Metric
from .tree_if_downstream import TreeInterfaceDownstream
from .tree_if_upstream import TreeInterfaceUpstream
from .tree_interface import TreeInterface


class KernelEntry:
    KERNEL_LOGGER = logging.getLogger('protocol.KernelEntry')

    print("CREATING KERNEL ENTRY")

    def __init__(self, source_ip: str, group_ip: str, interest_state_dic):
        self.kernel_entry_logger = logging.LoggerAdapter(self.KERNEL_LOGGER, {'tree': '(' + source_ip + ',' + group_ip + ')'})
        self.kernel_entry_logger.debug('Create KernelEntry')

        self.source_ip = source_ip
        print("BEGIN SOURCE_IP:")
        print(source_ip)
        print("END SOURCE IP")
        self.group_ip = group_ip
        print("BEGIN GROUP_IP:")
        print(group_ip)
        print("END GROUP IP")
        self._interest_interface_state = interest_state_dic


        ###### UNICAST INFO#################################################################
        (metric_administrative_distance, metric_cost, is_directly_connected, root_if) = \
            UnicastRouting.get_unicast_info(source_ip)
        # TODO verificar is directly connected
        self._rpc = Metric(metric_administrative_distance, metric_cost)
        if is_directly_connected:
            self.originator = True
        else:
            self.originator = False
        #######################################################################################
        # Locks
        self._multicast_change = Lock()
        self._lock_test2 = RLock()
        self.CHANGE_STATE_LOCK = RLock()

        # select root interface based on rpf check
        self.inbound_interface_index = root_if
        self.interface_state = {}  # type: dict(int, TreeInterface)

        # (S,G) starts OUT-TREE state... later check if node is in-tree via evaluate_in_tree_change()
        self._was_in_tree = False

        if self.originator:
            with self.CHANGE_STATE_LOCK:
                for i in Main.kernel.vif_index_to_name_dic.keys():
                    try:
                        if i != self.inbound_interface_index:
                            interest_state = self._interest_interface_state.get(i, False)
                            self.interface_state[i] = TreeInterfaceDownstream(self, i, self._rpc,
                                                                              interest_state=interest_state,
                                                                              was_root=False, was_in_tree=False)

                    except:
                        import traceback
                        print(traceback.format_exc())
                        continue

                if self.inbound_interface_index is not None:
                    self.interface_state[self.inbound_interface_index] = \
                        TreeInterfaceUpstream(self, self.inbound_interface_index, was_non_root=False, was_in_tree=False)
            #self.evaluate_assert()
            self.change()
            #self.evaluate_assert()
            self.evaluate_in_tree_change()
            print('Tree Originator created')


        else:
            with self.CHANGE_STATE_LOCK:
                for i in Main.kernel.vif_index_to_name_dic.keys():
                    try:
                        if i == self.inbound_interface_index:
                            continue
                        else:
                            interest_state = self._interest_interface_state.get(i, False)
                            self.interface_state[i] = TreeInterfaceDownstream(self, i, self._rpc,
                                                                              interest_state=interest_state,
                                                                              was_root=False, was_in_tree=False)

                    except Exception:
                        import traceback
                        print(traceback.format_exc())
                        continue
                #if not self.originator:
                    #self._was_in_tree = self.is_in_tree()
                if self.inbound_interface_index is not None:
                    self.interface_state[self.inbound_interface_index] = \
                        TreeInterfaceUpstream(self, self.inbound_interface_index, was_non_root=False, was_in_tree=False)
            #self.evaluate_assert()
            self.change()
            #self.evaluate_assert()
            self.evaluate_in_tree_change()

            print('Tree NonOriginator created')

    def get_inbound_interface_index(self):
        """
        Get VIF of root interface of this tree
        """
        return self.inbound_interface_index

    def get_outbound_interfaces_indexes(self):
        """
        Get OIL of this tree
        """
        outbound_indexes = [0] * Main.kernel.MAXVIFS
        for (index, state) in self.interface_state.items():
            outbound_indexes[index] = state.is_forwarding()

        return outbound_indexes


    ################################################
    # Receive (S,G) data packets or control packets
    ################################################
    def recv_data_msg(self, index):
        """
        Receive data packet regarding this tree in interface with VIF index
        """
        print("recv data")
        self.interface_state[index].recv_data_msg()

    def recv_assert_msg(self, index, received_metric):
        """
        Receive data packet regarding this tree in interface with VIF index
        """
        print("recv assert")

        self.interface_state[index].recv_assert_msg(received_metric)


    ###############################################################
    # Code related with tree state
    ###############################################################
    def check_interface_state(self, index, interest_state):
        """
        A neighbor changed Upstream state due to the reception of any control packet
        (IamUpstream or IamNoLongerUpstream or Interest or NoInterest or Sync)
        """
        if index not in self.interface_state:
            print('index no in interface_state')
            return

        self.check_interest_state(index, interest_state)
        #self.check_tree_state()

    def check_interest_state(self, index, interest_state):
        """
        A neighbor changed Interest state due to the reception of any control packet
        (Interest or NoInterest or Sync)
        """

        if index not in self.interface_state:
            return

        current_interest_state = self._interest_interface_state.get(index, None)
        self._interest_interface_state[index] = interest_state

        if current_interest_state != interest_state:
            self.interface_state[index].change_interest_state(interest_state)

    def check_tree_state(self):
        with self.CHANGE_STATE_LOCK:
            for interface in self.interface_state.values():
                if interface.is_downstream():
                    if interface.is_in_tree() or not interface.is_no_info():
                        return
            self.remove_entry()

    def check_igmp_state(self, index):
        """
        Reverify IGMP state of this tree in interface with VIF index...
        This is invoked whenver interface index enables or disables IGMP
        """
        print("ENTROU CHECK IGMP STATE")
        if index not in self.interface_state:
            return

        self.interface_state[index].check_igmp_state()
        print("SAI CHECK IGMP STATE")

    def get_interface_sync_state(self, vif_index):
        """
        Determine if this tree must be included in a new snapshot of interface with VIF vif_index
        """
        with self.CHANGE_STATE_LOCK:
            if vif_index not in self.interface_state:
                return None
            else:
                return self.interface_state[vif_index].get_sync_state()

    ###############################################################
    # Unicast Changes to RPF
    ###############################################################
    def network_update(self):
        """
        Router suffered an RPC change... React to this change
        """
        with self.CHANGE_STATE_LOCK:
            (metric_administrative_distance, metric_cost, is_directly_connected, new_inbound_interface_index) = \
                UnicastRouting.get_unicast_info(self.source_ip)
            new_rpc = Metric(metric_administrative_distance, metric_cost)

            if is_directly_connected:
                return
            if new_inbound_interface_index != self.inbound_interface_index:
                # get old interfaces
                old_upstream_interface = self.interface_state.get(self.inbound_interface_index, None)
                old_downstream_interface = self.interface_state.get(new_inbound_interface_index, None)

                non_root_interest_state = self._interest_interface_state.get(self.inbound_interface_index, False)
                root_interest_state = self._interest_interface_state.get(new_inbound_interface_index, False)

                # remove old interfaces
                if old_upstream_interface is not None:
                    old_upstream_interface.delete()
                if old_downstream_interface is not None:
                    old_downstream_interface.delete()

                # change type of interfaces
                if self.inbound_interface_index is not None:
                    print("Network_update: gonna create TreeInterfaceDownstream")
                    new_downstream_interface = TreeInterfaceDownstream(self, self.inbound_interface_index, new_rpc,
                                                                       non_root_interest_state,
                                                                       was_root=True, was_in_tree=self._was_in_tree)

                    print("Network_update: created TreeInterfaceDownstream")
                    self.interface_state[self.inbound_interface_index] = new_downstream_interface
                if new_inbound_interface_index is not None:
                    print("Network_update: gonna create TreeInterfaceUpstream")
                    new_upstream_interface = TreeInterfaceUpstream(self, new_inbound_interface_index,
                                                                   was_non_root=True, was_in_tree=self._was_in_tree)

                    print("Network_update: created TreeInterfaceUpstream")
                    self.interface_state[new_inbound_interface_index] = new_upstream_interface
                self.inbound_interface_index = new_inbound_interface_index

                if self._rpc != new_rpc:
                    self._rpc = new_rpc
                    for interface in self.interface_state.values():
                        print("IN NETWORK UPDATE1")
                        interface.notify_rpc_change(new_rpc)
                else:
                    pass

                # atualizar tabela de encaminhamento multicast
                #self.evaluate_assert()
                self.change()
                self.evaluate_in_tree_change()
            elif self._rpc != new_rpc:
                self._rpc = new_rpc
                for interface in self.interface_state.values():
                    print("IN NETWORK UPDATE2")
                    interface.notify_rpc_change(new_rpc)

    def is_in_tree(self):
        """
        Determine if router is interested in receiving data packets
        """
        for interface in self.interface_state.values():
            if interface.is_forwarding():
                return True

        return False

    def evaluate_in_tree_change(self):
        """
        Evaluate if there is a change of interest from this router
        """
        #if self.originator:
         #   return

        print("IN EVALUATE TREE CHANGE IN KERNEL ENTRY")
        with self._lock_test2:
            is_in_tree = self.is_in_tree()
            was_in_tree = self._was_in_tree
            self._was_in_tree = is_in_tree
            if was_in_tree != is_in_tree and self.inbound_interface_index is not None:
                if is_in_tree:
                    self.interface_state[self.inbound_interface_index].node_is_in_tree()
                else:
                    self.interface_state[self.inbound_interface_index].node_is_out_tree()

    def evaluate_assert(self):
        for interface in self.interface_state.values():
            if interface.is_downstream():
                interface.verify_assert(creating_interface=True)

    def get_rpc(self):
        """
        Get RPC
        """
        return self._rpc

    def get_source(self):
        """
        Get source IP of this tree
        """
        return self.source_ip

    def get_group(self):
        """
        Get group IP of this tree
        """
        return self.group_ip

    def get_interface_state_dict(self):

        return self.interface_state

    def get_inbound_index(self):

        return self.inbound_interface_index

    def change(self):
        """
        Reset multicast routing table due to changes in state
        """
        self.kernel_entry_logger.debug("updating multicast routing table")
        with self._multicast_change:
            if self.inbound_interface_index is not None:
                Main.kernel.set_multicast_route(self)

    def remove_entry(self):
        """
        Remove entry from the multicast routing table
        """

        self.kernel_entry_logger.debug("Removing entry from multicast routing table")
        Main.kernel.remove_multicast_route(self)

    def delete_state(self):
        """
        Delete all stored state regarding this tree
        """
        for state in self.interface_state.values():
            state.delete()
        self.interface_state.clear()

    ######################################
    # Interface change
    #######################################
    def new_interface(self, index):
        """
        New interface with VIF index added
        """
        print("NEW_INTERFACE ANTES")
        with self.CHANGE_STATE_LOCK:
            print("NEW_INTERFACE DEPOIS")
            if index in self.interface_state:
                return

            (_, _, _, inbound_interface_index) = UnicastRouting.get_unicast_info(self.source_ip)
            # TODO verificar is directly connected

            interest_state = False
            self._interest_interface_state[index] = interest_state

            # new interface is of type non-root
            if inbound_interface_index != index:
                self.interface_state[index] = TreeInterfaceDownstream(self, index, self._rpc,
                                                                      interest_state=interest_state,
                                                                      was_root=False, was_in_tree=False)

            # new interface is of type root and there wasn't any root interface previously configured
            elif inbound_interface_index == index and self.inbound_interface_index is None:
                self.inbound_interface_index = index
                self.interface_state[index] = TreeInterfaceUpstream(self, self.inbound_interface_index,
                                                                    was_non_root=False, was_in_tree=False)

            # new interface is of type root and there was a root interface previously configured
            elif inbound_interface_index == index and self.inbound_interface_index is not None:
                old_upstream_interface = self.interface_state.get(self.inbound_interface_index, None)

                non_root_interest_state = self._interest_interface_state.get(self.inbound_interface_index, False)

                # change type of interfaces
                if self.inbound_interface_index is not None:
                    new_downstream_interface = TreeInterfaceDownstream(self, self.inbound_interface_index, self._rpc,
                                                                       non_root_interest_state,
                                                                       was_root=True, was_in_tree=False)

                    self.interface_state[self.inbound_interface_index] = new_downstream_interface
                if inbound_interface_index is not None:
                    new_upstream_interface = TreeInterfaceUpstream(self, inbound_interface_index,
                                                                   was_non_root=True, was_in_tree=False)

                    self.interface_state[inbound_interface_index] = new_upstream_interface
                self.inbound_interface_index = inbound_interface_index

                # remove old interfaces
                if old_upstream_interface is not None:
                    old_upstream_interface.delete()

            #self.evaluate_assert()
            self.change()
            self.evaluate_in_tree_change()


    def remove_interface(self, index):
        """
        Interface with VIF index removed
        """
        with self.CHANGE_STATE_LOCK:
            if index not in self.interface_state:
                return

            #check if removed interface is root interface
            if self.inbound_interface_index == index:
                self.inbound_interface_index = None

            # remove cached info about removed interface

            self._interest_interface_state.pop(index, None)

            self.interface_state.pop(index).delete()
            self.change()
            self.evaluate_in_tree_change()

