from utils import TYPE_CHECKING

import Main
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
        if Main.kernel.assert_state_per_interface.get((interface._kernel_entry.source_ip, interface._interface_id), None) != AssertState.NotAvailable:
            Main.kernel.assert_state_per_interface[(interface._kernel_entry.source_ip, interface._interface_id)] = AssertState.NotAvailable
            interface.send_assert_cancel()

    @staticmethod
    def my_rpc_changes(interface: 'TreeInterfaceDownstream') -> None:
        """
        Interface not directly connected to the source AND
        MyRPC changes
        """
        interface.logger.debug('my_rpc_changes')
        interface.send_assert()
