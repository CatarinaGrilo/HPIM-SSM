from abc import ABCMeta, abstractmethod


class SFMRUpstreamStateABC(metaclass=ABCMeta):
    @staticmethod
    @abstractmethod
    def are_upstream_nodes_interested() -> bool:
        raise NotImplementedError()


class SFMRUpstreamInterested(SFMRUpstreamStateABC):
    @staticmethod
    def are_upstream_nodes_interested():
        """
        Determine if this state considers Upstream nodes to be Interested in receiving data packets
        """
        return True

    def __str__(self):
        return 'UpstreamInterest'


class SFMRNoUpstreamInterested(SFMRUpstreamStateABC):
    @staticmethod
    def are_upstream_nodes_interested():
        """
        Determine if this state considers Upstream nodes to be Interested in receiving data packets
        """
        return False

    def __str__(self):
        return 'NoUpstreamInterest'


class SFMRPruneState():
    UI = SFMRUpstreamInterested()
    NUI = SFMRNoUpstreamInterested()