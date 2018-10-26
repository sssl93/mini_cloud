# coding:utf-8
def format_security_rule(data):
    """
    Format security rule.
    :param data: source data of rule
    :return:
    """
    directions = {'ingress': u'入口', 'egress': u'出口'}
    port_ranges = {'-1/-1': u'任何', '*': u'任何'}
    data['display_direction'] = directions.get(data['direction'], data['direction'])
    data['display_port_range'] = port_ranges.get(data['port_range'], data['port_range'])
