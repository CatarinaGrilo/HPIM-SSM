import ipaddress


class Metric(object):
    def __init__(self, metric_preference: int = 0x7FFFFFFF, route_metric: int = 0xFFFFFFFF, ip_address: str = "0.0.0.0"):
        if type(ip_address) is str:
            ip_address = ipaddress.ip_address(ip_address)

        self._ip_address = ip_address
        self._metric_preference = metric_preference
        self._route_metric = route_metric

    def is_better_than(self, other):
        """
        Verify if this RPC state is better than other
        """
        if self.metric_preference != other.metric_preference:
            return self.metric_preference < other.metric_preference
        else:
            return self.route_metric < other.route_metric

    def __eq__(self, other):
        return self.metric_preference == other.metric_preference and self.route_metric == other.route_metric

    @property
    def metric_preference(self):
        """
        Obtain metric preference of this Metric
        """
        return self._metric_preference

    @metric_preference.setter
    def metric_preference(self, value):
        """
        Set metric preference of this Metric
        """
        self._metric_preference = value

    @property
    def route_metric(self):
        """
        Obtain route metric of this Metric
        """
        return self._route_metric

    @route_metric.setter
    def route_metric(self, value):
        """
        Set route metric of this Metric
        """
        self._route_metric = value

    @property
    def ip_address(self):
        return self._ip_address

    @ip_address.setter
    def ip_address(self, value):
        if type(value) is str:
            value = ipaddress.ip_address(value)

        self._ip_address = value

    def get_ip(self):
        return str(self._ip_address)

    def is_worse(self, other):
        return not self.is_better_than(other)

    def equal_metric(self, other):
        return self.metric_preference == other.metric_preference and self.metric_preference == other.metric_preference \
               and self.ip_address == other.ip_address

    def i_am_assert_winner(self, tree_if):
        return self.get_ip() == tree_if.get_ip()

    @staticmethod
    def infinite_assert_metric():
        return Metric()


class AssertMetric(Metric):
    def __init__(self, metric_preference: int = 0x7FFFFFFF, route_metric: int = 0xFFFFFFFF, ip_address: str = "0.0.0.0"):
        super().__init__(metric_preference, route_metric)

        if type(ip_address) is str:
            ip_address = ipaddress.ip_address(ip_address)

        self._metric_preference = metric_preference
        self._route_metric = route_metric
        self._ip_address = ip_address

    def is_better_than(self, other):
        """
        Verify if this RPC state is better than other
        """
        return super().is_better_than(other) or (super().__eq__(other) and self.ip_address > other.ip_address)

    def is_worse(self, other):
        """
        Verify if this RPC state is worse than other
        """
        return not self.is_better_than(other)

    def equal_metric(self, other):
        return self.metric_preference == other.metric_preference and self.metric_preference == other.metric_preference \
               and self.ip_address == other.ip_address

    @staticmethod
    def infinite_assert_metric():
        """
        @type metric: AssertMetric
        """
        return Metric()


    @staticmethod
    def spt_assert_metric(tree_if):
        '''
        @type metric: AssertMetric
        @type tree_if: TreeInterface
        '''
        (source_ip, _) = tree_if.get_tree_id()
        from hpimsm import UnicastRouting
        (metric_preference, metric_cost, _) = UnicastRouting.get_metric(source_ip)
        return AssertMetric(metric_preference, metric_cost, tree_if.get_ip())

    def i_am_assert_winner(self, tree_if):
        """
        Verify if this AssertMetric is storing my state
        """
        return self.get_ip() == tree_if.get_ip()

    @property
    def ip_address(self):
        """
        Obtain IP address of this AssertMetric
        """
        return self._ip_address

    @ip_address.setter
    def ip_address(self, value):
        """
        Set IP address of this AssertMetric
        """
        if type(value) is str:
            value = ipaddress.ip_address(value)

        self._ip_address = value

    def get_ip(self):
        """
        Obtain IP address of this AssertMetric in a string format
        """
        return str(self._ip_address)

    def __str__(self):
        return "Metric Preference: " + str(self.metric_preference) + "; Metric: " + str(self.route_metric)