from .assert_state import AssertState
from .metric import AssertMetric

from utils import TYPE_CHECKING

if TYPE_CHECKING:
    from .tree_if_upstream import TreeInterfaceUpstream


class SFMRNewRootState:

    @staticmethod
    def interfaces_roles_change(interface: 'TreeInterfaceUpstream'):
        """
        Interfaces roles change (NonRoot->Root)
        """
        #interface.logger.debug('interfaces_roles_change')
        if interface.is_node_in_tree():
            interface.send_prune(interface._kernel_entry.potential_aw)

    @staticmethod
    def interfaces_roles_dont_change_and_router_transition_to_it_or_ot(interface: 'TreeInterfaceUpstream') -> None:
        """
        Interfaces roles dont change (this interface remains Root) AND
        router changes its interest in receiving data packets (becomes interested or not interested)
        """
        #interface.logger.debug('interfaces_roles_dont_change_and_router_transition_to_it_or_ot')
        interface.send_my_interest()
