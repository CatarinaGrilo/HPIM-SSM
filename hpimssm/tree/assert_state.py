from abc import ABCMeta, abstractmethod

from hpimssm.utils import TYPE_CHECKING

from .metric import AssertMetric

if TYPE_CHECKING:
    from .tree_if_downstream import TreeInterfaceDownstream


class AssertStateABC(metaclass=ABCMeta):

    @staticmethod
    @abstractmethod
    def is_assert_winner():
        raise Exception

    @staticmethod
    @abstractmethod
    def is_assert_loser():
        raise Exception

    @staticmethod
    @abstractmethod
    def is_no_info():
        raise Exception

    @staticmethod
    @abstractmethod
    def receivedPreferedMetric(interface: "TreeInterfaceDownstream", better_metric):
        """
        Receive Preferred Assert
        @type interface: TreeInterface
        @type better_metric: AssertMetric
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def receivedInferiorMetric(interface: "TreeInterfaceDownstream", inferior_metric):
        """
        Receive Inferior Assert
        @type interface: TreeInterface
        @type inferior_metric: AssertMetric
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def winnerLivelinessTimerExpires(interface: "TreeInterfaceDownstream"):
        """
        Winner’s NLT(N,I) Expires
        @type interface: TreeInterface
        """
        raise NotImplementedError()


class NoInfoState(AssertStateABC):
    """
    NoInfoState (NI)
    This router has no (S,G) Assert state on interface I.
    """
    @staticmethod
    def is_assert_winner():
        """
        Determine if this state is AssertWinner
        """
        return False

    @staticmethod
    def is_assert_loser():
        """
        Determine if this state is AssertLoser
        """
        return False

    @staticmethod
    def is_no_info():
        """
        Determine if this state is NoInfo
        """
        return True

    @staticmethod
    def receivedPreferedMetric(interface: "TreeInterfaceDownstream", better_metric):
        """
        @type interface: TreeInterface
        @type better_metric: AssertMetric
        """
        pass

    @staticmethod
    def receivedInferiorMetric(interface: "TreeInterfaceDownstream", inferior_metric):
        """
        Receive Inferior Assert
        @type interface: TreeInterface
        @type inferior_metric: AssertMetric
        """
        pass

    @staticmethod
    def winnerLivelinessTimerExpires(interface: "TreeInterfaceDownstream"):
        assert False, "this should never occur"

    def __str__(self) -> str:
        return "NoInfo"


class WinnerState(AssertStateABC):
    """
    I am Assert Winner (W)
    This router has won an (S,G) Assert on interface I. It is now
    responsible for forwarding traffic from S destined for G via
    interface I.
    """

    @staticmethod
    def is_assert_winner():
        """
        Determine if this state is AssertWinner
        """
        return True

    @staticmethod
    def is_assert_loser():
        """
        Determine if this state is AssertLoser
        """
        return False

    @staticmethod
    def is_no_info():
        """
        Determine if this state is NoInfo
        """
        return False

    @staticmethod
    def receivedPreferedMetric(interface: "TreeInterfaceDownstream", better_metric):
        """
        @type interface: TreeInterface
        @type better_metric: AssertMetric
        """
        print("IN RECEIVED PREFERED METRIC - ASSERT WINNER STATE")

        interface.assert_logger.debug('receivedPreferedMetric, W -> L')

        interface.set_assert_winner_metric(better_metric)
        interface.set_assert_state(AssertState.Loser)

        # interface stops being assert capable

    @staticmethod
    def receivedInferiorMetric(interface: "TreeInterfaceDownstream", inferior_metric):
        """
        @type interface: TreeInterface
        @type inferior_metric: AssertMetric
        """
        # i am assert winner and received inferior metric
        # someone is mistaken
        interface.send_assert()


    @staticmethod
    def winnerLivelinessTimerExpires(interface: "TreeInterfaceDownstream"):
        assert False, "this should never occur"

    def __str__(self) -> str:
        return "Winner"


class LoserState(AssertStateABC):
    """
    I am Assert Loser (L)
    This router has lost an (S,G) Assert on interface I. It must not
    forward packets from S destined for G onto interface I.
    """
    @staticmethod
    def is_assert_winner():
        """
        Determine if this state is AssertWinner
        """
        return False

    @staticmethod
    def is_assert_loser():
        """
        Determine if this state is AssertLoser
        """
        return True

    @staticmethod
    def is_no_info():
        """
        Determine if this state is NoInfo
        """
        return False

    @staticmethod
    def receivedPreferedMetric(interface: "TreeInterfaceDownstream", better_metric):
        """
        @type interface: TreeInterface
        @type better_metric: AssertMetric
        """

        print("IN RECEIVED PREFERED METRIC - ASSERT LOSER STATE")

        interface.assert_logger.debug('receivedPreferedMetric, L -> L')

        interface.set_assert_winner_metric(better_metric)
        interface.set_assert_state(AssertState.Loser)

    @staticmethod
    def receivedInferiorMetric(interface: "TreeInterfaceDownstream", inferior_metric):
        """
        @type interface: TreeInterface
        @type inferior_metric: AssertMetric
        """
        pass

    @staticmethod
    def receivedInferiorMetricFromWinner(interface: "TreeInterfaceDownstream", inferior_metric):
        """
        @type interface: TreeInterface
        @type inferior_metric: AssertMetric
        """
        interface.assert_logger.debug('receivedPreferedMetric, L -> W')
        interface.set_assert_winner_metric(interface.my_assert_metric())
        interface.set_assert_state(AssertState.Winner)
        interface.send_assert()

    @staticmethod
    def updateAWinfo(interface: "TreeInterfaceDownstream", better_metric):
        """
        @type interface: TreeInterface
        @type better_metric: AssertMetric
        """
        interface.set_assert_winner_metric(better_metric)
        interface.set_assert_state(AssertState.Loser)

    @staticmethod
    def winnerLivelinessTimerExpires(interface: "TreeInterfaceDownstream"):

        print("winnerLivelinessTimerExpires_begin")
        interface.assert_logger.debug('winnerLivelinessTimerExpires, L -> W')
        interface.set_assert_winner_metric(interface.my_assert_metric())
        interface.set_assert_state(AssertState.Winner)

        interface.send_assert()
        print("winnerLivelinessTimerExpires_end")

    def __str__(self) -> str:
        return "Loser"


class AssertState():
    NoInfo = NoInfoState()
    Winner = WinnerState()
    Loser = LoserState()