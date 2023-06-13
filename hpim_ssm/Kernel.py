import ipaddress
import socket
import struct
import traceback
from threading import Thread, RLock
import threading

import Main
import UnicastRouting
from InterfaceIGMP import InterfaceIGMP
from InterfaceProtocol import InterfaceProtocol
from RWLock.RWLock import RWLockWrite
from tree import protocol_globals
from tree.KernelEntry import KernelEntry


class Kernel:

    #print("in creating Kernel")
    # MRT
    MRT_BASE    = 200
    MRT_INIT    = (MRT_BASE)      # /* Activate the kernel mroute code 	*/
    MRT_DONE    = (MRT_BASE + 1)  # /* Shutdown the kernel mroute		*/
    MRT_ADD_VIF = (MRT_BASE + 2)  # /* Add a virtual interface		    */
    MRT_DEL_VIF = (MRT_BASE + 3)  # /* Delete a virtual interface		*/
    MRT_ADD_MFC = (MRT_BASE + 4)  # /* Add a multicast forwarding entry	*/
    MRT_DEL_MFC = (MRT_BASE + 5)  # /* Delete a multicast forwarding entry	*/
    MRT_VERSION = (MRT_BASE + 6)  # /* Get the kernel multicast version	*/
    MRT_ASSERT  = (MRT_BASE + 7)  # /* Activate PIM assert mode		    */
    MRT_PIM     = (MRT_BASE + 8)  # /* enable PIM code			        */
    MRT_TABLE   = (MRT_BASE + 9)  # /* Specify mroute table ID		    */
    #MRT_ADD_MFC_PROXY = (MRT_BASE + 10)  # /* Add a (*,*|G) mfc entry	*/
    #MRT_DEL_MFC_PROXY = (MRT_BASE + 11)  # /* Del a (*,*|G) mfc entry	*/
    #MRT_MAX = (MRT_BASE + 11)


    # Max Number of Virtual Interfaces
    MAXVIFS = 32

    # SIGNAL MSG TYPE
    IGMPMSG_NOCACHE = 1
    IGMPMSG_WRONGVIF = 2
    IGMPMSG_WHOLEPKT = 3  # NOT USED ON PIM-DM


    # Interface flags
    VIFF_TUNNEL      = 0x1  # IPIP tunnel
    VIFF_SRCRT       = 0x2  # NI
    VIFF_REGISTER    = 0x4  # register vif
    VIFF_USE_IFINDEX = 0x8  # use vifc_lcl_ifindex instead of vifc_lcl_addr to find an interface

    def __init__(self):
        # Kernel is running
        self.running = True

        # KEY : interface_ip, VALUE : vif_index
        self.vif_dic = {}
        self.vif_index_to_name_dic = {}
        self.vif_name_to_index_dic = {}

        # KEY : source_ip, VALUE : {group_ip: KernelEntry}
        self.routing = {}

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)

        # MRT INIT
        s.setsockopt(socket.IPPROTO_IP, Kernel.MRT_INIT, 1)

        # MRT PIM
        s.setsockopt(socket.IPPROTO_IP, Kernel.MRT_PIM, 0)
        s.setsockopt(socket.IPPROTO_IP, Kernel.MRT_ASSERT, 0)

        self.socket = s
        self.rwlock = RLock()


        #self.create_virtual_interface("0.0.0.0", "pimreg", index=0, flags=Kernel.VIFF_REGISTER)


        self.protocol_interface = {} # name: interface_protocol
        self.igmp_interface = {}  # name: interface_igmp
        
        # logs
        self.interface_logger = Main.logger.getChild('KernelInterface')
        self.tree_logger = Main.logger.getChild('KernelTree')

        #self.interface_logger.debug("created KERNEL")
        self.lock = threading.Lock()


        # receive signals from kernel with a background thread
        handler_thread = Thread(target=self.handler)
        handler_thread.daemon = True
        handler_thread.start()

    def create_virtual_interface(self, ip_interface: str or bytes, interface_name: str, index, flags=0x0):
        if type(ip_interface) is str:
            ip_interface = socket.inet_aton(ip_interface)

        struct_mrt_add_vif = struct.pack("HBBI 4s 4s", index, flags, 1, 0, ip_interface,
                                         socket.inet_aton("0.0.0.0"))
        self.socket.setsockopt(socket.IPPROTO_IP, Kernel.MRT_ADD_VIF, struct_mrt_add_vif)
        self.vif_dic[socket.inet_ntoa(ip_interface)] = index
        self.vif_index_to_name_dic[index] = interface_name
        self.vif_name_to_index_dic[interface_name] = index

        for source_dict in list(self.routing.values()):
            for kernel_entry in list(source_dict.values()):
                kernel_entry.new_interface(index)

        self.interface_logger.debug('Create virtual interface: %s -> %d', interface_name, index)
        return index

    def create_protocol_interface(self, interface_name: str):
        #print("IN KERNEL: CREATE PROTOCOL INTERFACE")
        thread = None
        with self.rwlock:
            protocol_interface = self.protocol_interface.get(interface_name)
            igmp_interface = self.igmp_interface.get(interface_name)
            vif_already_exists = protocol_interface or igmp_interface
            if protocol_interface:
                # already exists
                return
            elif igmp_interface:
                index = igmp_interface.vif_index
            else:
                index = list(range(0, self.MAXVIFS) - self.vif_index_to_name_dic.keys())[0]

            if interface_name not in self.protocol_interface:
                pim_interface = InterfaceProtocol(interface_name, index)     #CREATE INSTANCE OF INTERFACE PRTOOCOL
                self.protocol_interface[interface_name] = pim_interface
                ip_interface = pim_interface.ip_interface
                if not vif_already_exists:
                    self.create_virtual_interface(ip_interface=ip_interface, interface_name=interface_name, index=index)
                pim_interface.enable()
                thread = Thread(target=self.recheck_all_trees, args=(index,))
                thread.start()

        if thread is not None:
            thread.join()

    def create_igmp_interface(self, interface_name: str):
        thread = None
        with self.rwlock:
            protocol_interface = self.protocol_interface.get(interface_name)
            igmp_interface = self.igmp_interface.get(interface_name)
            vif_already_exists = protocol_interface or igmp_interface
            if igmp_interface:
                # already exists
                return
            elif protocol_interface:
                index = protocol_interface.vif_index
            else:
                index = list(range(0, self.MAXVIFS) - self.vif_index_to_name_dic.keys())[0]

            if interface_name not in self.igmp_interface:
                igmp_interface = InterfaceIGMP(interface_name, index)
                self.igmp_interface[interface_name] = igmp_interface
                ip_interface = igmp_interface.ip_interface
                if not vif_already_exists:
                    self.create_virtual_interface(ip_interface=ip_interface, interface_name=interface_name, index=index)
                igmp_interface.enable()
                thread = Thread(target=self.recheck_igmp_all_trees, args=(index,))
                thread.start()

        if thread is not None:
            thread.join()

    def remove_interface(self, interface_name, igmp: bool = False, pim: bool = False):
        thread = None
        with self.rwlock:
            ip_interface = None
            pim_interface = self.protocol_interface.get(interface_name)
            igmp_interface = self.igmp_interface.get(interface_name)
            if (not igmp and not pim) or (interface_name not in self.vif_name_to_index_dic):
                return
            if pim and pim_interface is not None:
                pim_interface = self.protocol_interface.pop(interface_name)
                ip_interface = pim_interface.ip_interface
                pim_interface.remove()
            if igmp and igmp_interface is not None:
                igmp_interface = self.igmp_interface.pop(interface_name)
                ip_interface = igmp_interface.ip_interface
                igmp_interface.remove()

            if interface_name not in self.igmp_interface and interface_name not in self.protocol_interface:
                self.remove_virtual_interface(ip_interface)
            else:
                vif_index = self.vif_name_to_index_dic.get(interface_name)
                thread = Thread(target=self.recheck_all_trees, args=(vif_index,))
                thread.start()

        if thread is not None:
            thread.join()

    def remove_virtual_interface(self, ip_interface):
        index = self.vif_dic.pop(ip_interface, None)
        struct_vifctl = struct.pack("HBBI 4s 4s", index, 0, 0, 0, socket.inet_aton("0.0.0.0"), socket.inet_aton("0.0.0.0"))

        try:
            self.socket.setsockopt(socket.IPPROTO_IP, Kernel.MRT_DEL_VIF, struct_vifctl)
        except socket.error:
            pass

        interface_name = self.vif_index_to_name_dic.pop(index, None)
        self.vif_name_to_index_dic.pop(interface_name, None)

        # remove this interface from KernelEntries
        for source_dict in list(self.routing.values()):
            for kernel_entry in list(source_dict.values()):
                kernel_entry.remove_interface(index)

        self.interface_logger.debug('Remove virtual interface: %s -> %d', interface_name, index)

    def notify_interface_changes(self, interface_name):
        with self.rwlock:
            if interface_name is None or interface_name not in self.vif_name_to_index_dic:
                return
            igmp_was_enabled = interface_name in self.igmp_interface
            protocol_was_enabled = interface_name in self.protocol_interface

        self.remove_interface(interface_name, igmp=True, pim=True)
        if igmp_was_enabled:
            self.create_igmp_interface(interface_name)
        if protocol_was_enabled:
            self.create_protocol_interface(interface_name)

    def add_interface_security(self, interface_name, security_id, security_algorithm, security_key):
        with self.rwlock:
            if interface_name not in self.protocol_interface:
                return

            interface = self.protocol_interface.get(interface_name) #type: InterfaceProtocol
            interface.add_security_key(security_id, security_algorithm, security_key)

    def remove_interface_security(self, interface_name, security_id):
        with self.rwlock:
            if interface_name not in self.protocol_interface:
                return

            interface = self.protocol_interface.get(interface_name) #type: InterfaceProtocol
            interface.remove_security_key(security_id)

    def set_multicast_route(self, kernel_entry: KernelEntry):

        source_ip = socket.inet_aton(kernel_entry.source_ip)
        group_ip = socket.inet_aton(kernel_entry.group_ip)

        outbound_interfaces = kernel_entry.get_outbound_interfaces_indexes()

        if len(outbound_interfaces) != Kernel.MAXVIFS:
            raise Exception

        #outbound_interfaces_and_other_parameters = list(kernel_entry.outbound_interfaces) + [0]*4
        outbound_interfaces_and_other_parameters = outbound_interfaces + [0]*4

        #outbound_interfaces, 0, 0, 0, 0 <- only works with python>=3.5
        #struct_mfcctl = struct.pack("4s 4s H " + "B"*Kernel.MAXVIFS + " IIIi", source_ip, group_ip, inbound_interface_index, *outbound_interfaces, 0, 0, 0, 0)
        struct_mfcctl = struct.pack("4s 4s H " + "B"*Kernel.MAXVIFS + " IIIi", source_ip, group_ip,
                                    kernel_entry.inbound_interface_index, *outbound_interfaces_and_other_parameters)

        self.socket.setsockopt(socket.IPPROTO_IP, Kernel.MRT_ADD_MFC, struct_mfcctl)

    def set_flood_multicast_route(self, source_ip, group_ip, inbound_interface_index):
        if inbound_interface_index is None:
            return
        source_ip = socket.inet_aton(source_ip)
        group_ip = socket.inet_aton(group_ip)

        outbound_interfaces = [1]*self.MAXVIFS
        outbound_interfaces[inbound_interface_index] = 0

        #outbound_interfaces_and_other_parameters = list(kernel_entry.outbound_interfaces) + [0]*4
        outbound_interfaces_and_other_parameters = outbound_interfaces + [0]*3 + [protocol_globals.INITIAL_FLOOD_TIME]

        #outbound_interfaces, 0, 0, 0, 0 <- only works with python>=3.5
        #struct_mfcctl = struct.pack("4s 4s H " + "B"*Kernel.MAXVIFS + " IIIi", source_ip, group_ip, inbound_interface_index, *outbound_interfaces, 0, 0, 0, 0)
        struct_mfcctl = struct.pack("4s 4s H " + "B"*Kernel.MAXVIFS + " IIIi", source_ip, group_ip, inbound_interface_index, *outbound_interfaces_and_other_parameters)
        self.socket.setsockopt(socket.IPPROTO_IP, Kernel.MRT_ADD_MFC, struct_mfcctl)

    def remove_multicast_route(self, kernel_entry: KernelEntry):
        #self.interface_logger.debug("Removing multicast route")
        Thread(target=self._remove_multicast_route, args=(kernel_entry,)).start()

    def _remove_multicast_route(self, kernel_entry):
        source_ip = socket.inet_aton(kernel_entry.source_ip)
        group_ip = socket.inet_aton(kernel_entry.group_ip)
        outbound_interfaces_and_other_parameters = [0] + [0]*Kernel.MAXVIFS + [0]*4

        struct_mfcctl = struct.pack("4s 4s H " + "B"*Kernel.MAXVIFS + " IIIi", source_ip, group_ip, *outbound_interfaces_and_other_parameters)
        source_ip = kernel_entry.source_ip
        group_ip = kernel_entry.group_ip

        if not (source_ip in self.routing and group_ip in self.routing[source_ip]):
            return
        
        info_about_tree_can_be_removed = True
        for interface in self.protocol_interface.values():
            if not info_about_tree_can_be_removed:
                break
            for n in list(interface.neighbors.values()):
                (neighbor_interest_state, neighbor_assert_state) = n.get_tree_state(tree=(source_ip, group_ip))
                if neighbor_interest_state or neighbor_assert_state is not None:
                    self.create_entry(kernel_entry.source_ip, kernel_entry.group_ip)
                    info_about_tree_can_be_removed = False
                    break
                
        with self.rwlock:
            if info_about_tree_can_be_removed:
                self.interface_logger.debug("Removing multicast route")
                try:
                    self.socket.setsockopt(socket.IPPROTO_IP, Kernel.MRT_DEL_MFC, struct_mfcctl)
                except socket.error:
                    pass
                if self.routing.get(kernel_entry.source_ip, None) is not None:
                    if self.routing[kernel_entry.source_ip].get(kernel_entry.group_ip, None):
                        self.routing[kernel_entry.source_ip].pop(kernel_entry.group_ip)
                        kernel_entry.delete_state()
                        if len(self.routing[source_ip]) == 0:
                            self.routing.pop(source_ip)

            # if info_about_tree_can_be_removed:
            #     for interface in self.protocol_interface.values():
            #         interface.remove_tree_state(kernel_entry.source_ip, kernel_entry.group_ip)

    def exit(self):
        self.running = False

        # MRT DONE
        self.socket.setsockopt(socket.IPPROTO_IP, Kernel.MRT_DONE, 1)
        self.socket.close()

    def handler(self):
        while self.running:
            try:
                msg = self.socket.recv(20)
                (_, _, im_msgtype, im_mbz, im_vif, _, im_src, im_dst) = struct.unpack("II B B B B 4s 4s", msg[:20])
                #print((im_msgtype, im_mbz, socket.inet_ntoa(im_src), socket.inet_ntoa(im_dst)))

                if im_mbz != 0:
                    continue

                # print(im_msgtype)
                # print(im_mbz)
                # print(im_vif)
                # print(socket.inet_ntoa(im_src))
                # print(socket.inet_ntoa(im_dst))
                #print((im_msgtype, im_mbz, socket.inet_ntoa(im_src), socket.inet_ntoa(im_dst)))

                ip_src = socket.inet_ntoa(im_src)
                ip_dst = socket.inet_ntoa(im_dst)

                if im_msgtype == Kernel.IGMPMSG_NOCACHE:
                    print("IGMP NO CACHE")
                    self.igmpmsg_nocache_handler(ip_src, ip_dst, im_vif)
                elif im_msgtype == Kernel.IGMPMSG_WRONGVIF:
                    print("WRONG VIF HANDLER")
                    self.igmpmsg_wrongvif_handler(ip_src, ip_dst, im_vif)
                #elif im_msgtype == Kernel.IGMPMSG_WHOLEPKT:
                #    print("IGMP_WHOLEPKT")
                #    self.igmpmsg_wholepacket_handler(ip_src, ip_dst)
                else:
                    raise Exception
            except Exception:
                traceback.print_exc()
                continue

    # receive multicast (S,G) packet and multicast routing table has no (S,G) entry
    def igmpmsg_nocache_handler(self, ip_src, ip_dst, iif):
        # (_, _, is_directly_connected, rpf_if,_) = UnicastRouting.get_unicast_info(ip_src)

        # with self.rwlock:
        #     if ip_src in self.routing and ip_dst in self.routing[ip_src]:
        #         self.routing[ip_src][ip_dst].recv_data_msg(iif)
        #     elif is_directly_connected:
        #         if protocol_globals.INITIAL_FLOOD_ENABLED:
        #             # flood
        #             self.set_flood_multicast_route(ip_src, ip_dst, rpf_if)
        #         if rpf_if is not None:
        #             self.create_entry(ip_src, ip_dst)
        #             self.routing[ip_src][ip_dst].recv_data_msg(iif)
        #     elif not is_directly_connected and protocol_globals.INITIAL_FLOOD_ENABLED:
        #         # flood
        #         self.set_flood_multicast_route(ip_src, ip_dst, rpf_if)
        return

    # receive multicast (S,G) packet in a outbound_interface
    def igmpmsg_wrongvif_handler(self, ip_src, ip_dst, iif):
        #source_group_pair = (ip_src, ip_dst)
        #self.get_routing_entry(source_group_pair, create_if_not_existent=True).recv_data_msg(iif)
        return

    # notify KernelEntries about changes at the unicast routing table
    def notify_unicast_changes(self, subnet):
        with self.rwlock:
            for source_ip in list(self.routing.keys()):
                source_ip_obj = ipaddress.ip_address(source_ip)
                if source_ip_obj not in subnet:
                    continue

                for group_ip in list(self.routing[source_ip].keys()):
                    self.routing[source_ip][group_ip].network_update()

    def recv_interest_msg(self, source_group, interface: "InterfaceProtocol"):

        ip_src = source_group[0]
        ip_dst = source_group[1]
        #print("In recv_interest_msg interface: " + str(interface.ip_interface))
        with self.rwlock:
            if interface not in self.protocol_interface.values():
                return

            interest_state, assert_state = interface.get_tree_state(source_group)

            if (ip_src not in self.routing) or (ip_dst not in self.routing.get(ip_src, {})):
                self.interface_logger.debug('recv_int_1 ' + str(interface.ip_interface))
                self.create_entry(ip_src, ip_dst)

            elif (ip_src in self.routing) and (ip_dst in self.routing[ip_src]):
                self.interface_logger.debug('recv_int_2 ' + str(interface.ip_interface))
                self.routing[ip_src][ip_dst].check_interface_state(interface.vif_index, interest_state, assert_state)

            else:
                #self.interface_logger.debug('in recv_interest_msg_else')
                interface.remove_tree_state(ip_src, ip_dst)

    def recv_assert_msg(self, source_group, interface: "InterfaceProtocol"):

        #self.interface_logger.debug("ENTROU RCV ASSERT")
        ip_src = source_group[0]
        ip_dst = source_group[1]
        #print("In recv_assert_msg interface: " + str(interface.ip_interface))
        with self.rwlock:
            if interface not in self.protocol_interface.values():
                return

            interest_state, assert_state = interface.get_tree_state(source_group)

            if (ip_src not in self.routing) or (ip_dst not in self.routing.get(ip_src, {})):
                self.interface_logger.debug('ram1' + str(interface.ip_interface))
                self.create_entry(ip_src, ip_dst)
                self.routing[ip_src][ip_dst].check_interface_state(interface.vif_index, interest_state, assert_state)
            elif (ip_src in self.routing) and (ip_dst in self.routing[ip_src]):
                self.interface_logger.debug('ram2' + str(interface.ip_interface))
                self.routing[ip_src][ip_dst].check_interface_state(interface.vif_index, interest_state, assert_state)
            else:
                self.interface_logger.debug('ram3' + str(interface.ip_interface))
                interface.remove_tree_state(ip_src, ip_dst)

        #self.interface_logger.debug("SAIU RCV ASSERT")

    def create_entry(self, ip_src, ip_dst):
        (_, _, is_directly_connected, _, _) = UnicastRouting.get_unicast_info(ip_src)

        #print("Is directly connected to the source: ", is_directly_connected)

        interest_state_dict = {}
        assert_state_dict = {}

        if ip_src not in self.routing or ip_dst not in self.routing[ip_src]:

            for interface in self.protocol_interface.values():
                interest_state, assert_state = interface.get_tree_state((ip_src, ip_dst))
                interest_state_dict[interface.vif_index] = interest_state
                assert_state_dict[interface.vif_index] = assert_state

            other_interfaces = self.protocol_interface.keys() - self.vif_name_to_index_dic.keys()
            for interface_name in other_interfaces:
                vif_index = self.vif_name_to_index_dic.get(interface_name)
                interest_state_dict[vif_index] = False
                assert_state_dict[vif_index] = None

            if ip_src not in self.routing:
                self.routing[ip_src] = {}

            if ip_dst not in self.routing[ip_src]:
                self.routing[ip_src][ip_dst] = KernelEntry(ip_src, ip_dst, interest_state_dict, assert_state_dict)

    def snapshot_multicast_routing_table(self, vif_index, neighbor_ip):
        trees_to_sync = {}
        for (ip_src, src_dict) in self.routing.items():
            for (ip_dst, kernel_entry) in self.routing[ip_src].items():
                tree = kernel_entry.get_interface_sync_state(vif_index, neighbor_ip)

                if kernel_entry.get_tree_interface(vif_index).is_downstream() and tree is not False:
                    trees_to_sync[(ip_src, ip_dst)] = tree
                elif not kernel_entry.get_tree_interface(vif_index).is_downstream() and tree is None:
                    trees_to_sync[(ip_src, ip_dst)] = tree
        return trees_to_sync


    def recheck_all_trees(self, vif_index: int):
        with self.rwlock:
            interface_name = self.vif_index_to_name_dic.get(vif_index, None)
            interface = self.protocol_interface.get(interface_name, None)

            known_trees = set()
            if interface is not None:
                for n in list(interface.neighbors.values()):
                    known_trees = known_trees.union(n.get_known_trees())

            for (source, src_dict) in self.routing.items():
                for group in src_dict.keys():
                    known_trees.add((source, group))

            for tree in known_trees:
                if interface is not None:
                    interest_state, assert_state = interface.get_tree_state(tree)
                else:
                    interest_state, assert_state = (False, None)

                if tree[0] not in self.routing or tree[1] not in self.routing.get(tree[0], {}):
                    self.create_entry(tree[0], tree[1])
                elif tree[0] in self.routing and tree[1] in self.routing[tree[0]]:
                    self.routing[tree[0]][tree[1]].check_interface_state(vif_index, interest_state, assert_state)


    def recheck_igmp_all_trees(self, vif_index: int):
        #print("ENTROU RECHECK IGMP")
        with self.rwlock:
            for src_dict in self.routing.values():
                for entry in src_dict.values():
                    entry.check_igmp_state(vif_index)
            #print("SAIU RECHECK IGMP")

    def recheck_all_trees_in_all_interfaces(self):
        for i in list(self.vif_dic.values()):
            self.recheck_all_trees(i)