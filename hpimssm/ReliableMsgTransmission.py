from threading import Timer, RLock

from hpimssm.Packet.Packet import Packet
from hpimssm.tree.protocol_globals import MSG_FORMAT, MESSAGE_RETRANSMISSION_TIME, ACK_FAILURE_THRESHOLD

if MSG_FORMAT == "BINARY":
    from hpimssm.Packet.PacketProtocolHeader import PacketNewProtocolHeader as PacketProtocolHeader
    from hpimssm.Packet.PacketProtocolAssert import PacketNewProtocolAssert as PacketProtocolAssert
    from hpimssm.Packet.PacketProtocolInterest import PacketNewProtocolJoin as PacketProtocolJoin
    from hpimssm.Packet.PacketProtocolInterest import PacketNewProtocolPrune as PacketProtocolPrune
else:
    from hpimssm.Packet.PacketProtocolHeader import PacketProtocolHeader
    from hpimssm.Packet.PacketProtocolAssert import PacketProtocolAssert
    from hpimssm.Packet.PacketProtocolInterest import PacketProtocolJoin
    from hpimssm.Packet.PacketProtocolInterest import PacketProtocolPrune


class ReliableMessageTransmission(object):
    def __init__(self, interface):
        self._interface = interface
        self._msg_multicast = None
        # self._msg_unicast = {}
        self._neighbors_that_acked = set()
        self._number_of_failed_acks = {}
        self._retransmission_timer = None
        self._lock = RLock()

    def send_assert(self, source, group, rpc):
        """
        Send reliably a new Assert message
        """

        with self._lock:
            self.cancel_all_messages()

            (bt, sn) = self._interface.get_sequence_number()

            metric_preference = rpc.metric_preference
            metric = rpc.route_metric

            ph = PacketProtocolAssert(source, group, metric_preference, metric, sn)
            self._msg_multicast = Packet(payload=PacketProtocolHeader(ph, boot_time=bt))

            self.set_retransmission_timer()
            self._interface.send(self._msg_multicast)


    def send_join(self, source, group):
        """
        Send reliably a new Join message
        """
        self._interface.interface_logger.debug('Sending Join message')

        with self._lock:
            self.cancel_all_messages()

            (bt, sn) = self._interface.get_sequence_number()

            ph = PacketProtocolJoin(source, group, sn)
            self._msg_multicast = Packet(payload=PacketProtocolHeader(ph, boot_time=bt))

            self.set_retransmission_timer()
            self._interface.send(self._msg_multicast)


    def send_prune(self, source, group):
        """
        Send reliably a new Prune message
        """
        self._interface.interface_logger.debug("Sending Prune message"
                                               "")
        with self._lock:
            self.cancel_all_messages()

            (bt, sn) = self._interface.get_sequence_number()

            ph = PacketProtocolPrune(source, group, sn)
            self._msg_multicast = Packet(payload=PacketProtocolHeader(ph, boot_time=bt))

            self.set_retransmission_timer()
            self._interface.send(self._msg_multicast)

    def receive_ack(self, neighbor_ip, bt, sn):
        """
        Received Ack regarding this tree
        """
        with self._lock:
            msg = self._msg_multicast
            if msg is not None and (bt > msg.payload.boot_time or
                                    bt == msg.payload.boot_time and sn >= msg.payload.payload.sequence_number):
                self._neighbors_that_acked.add(neighbor_ip)
                if self.did_all_neighbors_acked():
                    self.cancel_messsage_multicast()


    def did_all_neighbors_acked(self):
        """
        Verify if all known neighbors have acked a multicast message
        """
        with self._lock:
            return self._interface.did_all_neighbors_acked(self._neighbors_that_acked)

    def cancel_messsage_multicast(self):
        """
        Stop reliably monitoring a Join/Prune/Assert message
        """
        with self._lock:
            self._neighbors_that_acked.clear()
            self._msg_multicast = None

            self.clear_retransmission_timer()
            self._number_of_failed_acks.clear()

    def cancel_all_messages(self):
        """
        Stop reliably monitoring any message regarding this tree
        (Join/Prune/Assert)
        """
        with self._lock:
            self.clear_retransmission_timer()
            self._neighbors_that_acked.clear()
            self._number_of_failed_acks.clear()
            self._msg_multicast = None
            # self._msg_unicast.clear()

    ##########################################
    # Set timers
    ##########################################
    # Reliable timer
    def set_retransmission_timer(self):
        """
        Set retransmission timer used to control retransmission of control messages
        """
        self.clear_retransmission_timer()
        self._retransmission_timer = Timer(MESSAGE_RETRANSMISSION_TIME, self.retransmission_timeout)
        self._retransmission_timer.start()

    def clear_retransmission_timer(self):
        """
        Stop retransmission timer
        """
        if self._retransmission_timer is not None:
            self._retransmission_timer.cancel()

    ###########################################
    # Timer timeout
    ###########################################
    def retransmission_timeout(self):
        """
        Retransmission timer has expired
        """
        neighbors_not_acked = set()
        with self._lock:
            # recheck if all neighbors acked
            if self._msg_multicast is not None and self.did_all_neighbors_acked():
                self.cancel_messsage_multicast()
            elif self._msg_multicast is not None:
                # take note of all neighbors that have not acked the multicast msg
                neighbors_not_acked = self.get_interface_neighbors() - self._neighbors_that_acked

            # didnt received acks from every neighbor... so lets resend msg and reschedule timer
            msg = self._msg_multicast
            if msg is not None:
                self._interface.send(msg)

            if self._msg_multicast is not None:  # or len(self._msg_unicast) > 0:
                self.set_retransmission_timer()

            # update number of failed acks per neighbor and check which ones should be considered to have failed
            for neighbor_ip in neighbors_not_acked:
                self._number_of_failed_acks[neighbor_ip] = self._number_of_failed_acks.get(neighbor_ip, 0) + 1
            self.check_neighbor_failures()

    #############################################
    # Get Sequence Number for CheckpointSN
    #############################################
    def get_sequence_number(self):
        """
        Get the lowest sequence number of a control message that is being currently reliably transmitted...
        This method will be used to determine the CheckpointSN to be transmitted in Hello messages
        """
        bt_sn = (None, None)
        with self._lock:
            msg = self._msg_multicast
            if msg is not None:
                bt_sn = (msg.payload.boot_time, msg.payload.payload.sequence_number - 1)

        return bt_sn

    #############################################
    # Check neighbor failures
    # Force neighbor failure in case neighbor does not ack successive control messages
    #############################################
    def check_neighbor_failures(self):
        #self._interface.interface_logger.debug('CHECK NEIGHBOR FAILURES')
        with self._lock:
            for (neighbor_ip, ack_failures) in self._number_of_failed_acks.copy().items():
                if ack_failures > ACK_FAILURE_THRESHOLD:
                    print("NEIGHBOR FAILED DUE TO ACK LACK: " + neighbor_ip)
                    self.force_neighbor_failure(neighbor_ip)

    def force_neighbor_failure(self, neighbor_ip):
        #self._interface.interface_logger.debug('FORCE NEIGHBOR FAILURES')
        with self._lock:
            self._interface.force_neighbor_failure(neighbor_ip)
            self._number_of_failed_acks.pop(neighbor_ip, None)

    def get_interface_neighbors(self):
        return self._interface.get_neighbors_ip()