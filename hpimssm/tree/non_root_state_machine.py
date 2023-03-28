from hpimssm.utils import TYPE_CHECKING

from .assert_state import AssertState

if TYPE_CHECKING:
    from .tree_if_downstream import TreeInterfaceDownstream
from .metric import AssertMetric


class SFMRNonRootState:
    @staticmethod
    def interface_roles_change(interface: 'TreeInterfaceDownstream'):
        """
        Interfaces roles change
        """
        #todo analyze this
        interface.logger.debug('interface_roles_change')
        interface.send_prune()

    @staticmethod
    def interface_becomes_assert_capable(interface: 'TreeInterfaceDownstream'):
        """
        Interface becomes assert capable
        Sends Assert
        Store self as AW
        Store my RPC as the AW RPC
        """
        interface.logger.debug('interface_becomes_assert_capable')
        interface.set_assert_winner_metric(interface.my_assert_metric())
        interface.set_assert_state(AssertState.Winner)
        interface.send_assert()

    @staticmethod
    def interface_stops_being_assert_capable(interface: 'TreeInterfaceDownstream'):
        """
        Interface stops being assert capable
        Send assert with infinite cost
        Delete Assert Info: AW + AW_RPC
        """
        interface.logger.debug('interface_stops_being_assert_capable')

        if interface.is_assert_winner():
            interface.send_assert_cancel()
        interface.set_assert_winner_metric(AssertMetric.infinite_assert_metric())
        interface.set_assert_state(AssertState.NoInfo)

    @staticmethod
    def my_rpc_changes(interface: 'TreeInterfaceDownstream') -> None:
        """
        interface not directly connected to the source AND
        MyRPC changes
        """
        interface.logger.debug('my_rpc_changes')
        interface.set_assert_winner_metric(interface.my_assert_metric())
        interface.send_assert()

    @staticmethod
    def my_rpc_becomes_better_than_aw(interface: 'TreeInterfaceDownstream'):

        interface.logger.debug('my_rpc_becomes_better_than_aw')
        interface.set_assert_winner_metric(interface.my_assert_metric())
        interface.set_assert_state(AssertState.Winner)
        interface.send_assert()


