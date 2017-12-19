from __future__ import unicode_literals

import pytest
import mock

import ipaddress

import holepunch


def _str_to_cidr(s):
    return ipaddress.ip_interface(s)


class TestPortRanges:
    def test_success_cases(self):
        # (input, expected_output)
        cases = [
            (['5'], [(5, 5)]),
            (['20-22'], [(20, 22)]),
            (['90', '1-120', '80-80'], [(90, 90), (1, 120), (80, 80)])
        ]

        for port_strings, expected in cases:
            output = holepunch.parse_port_ranges(port_strings)
            assert output == expected

    def test_error_cases(self):
        # (input, error message)
        cases = [
            (['5-2'], 'Port range must be ordered from low to high'),
            (['1', '2-4', '5-2'], 'Port range must be ordered from low to high'),
            (['apples'], r'.*invalid literal.*'),
            (['1-2-3'], r'Expected port or port range'),
            (['9999999'], r'Ports must be in range')
        ]

        for port_strings, msg in cases:
            with pytest.raises(ValueError, match=msg):
                holepunch.parse_port_ranges(port_strings)


def test_find_intended_security_group():
    # list of (security_groups, group_name, expected_output)
    cases = [
        (['1', '2', '3', '4', 'pretty close_'], 'pretty_close', 'pretty close_'),
        ([], 'foo', None),
        (['1', '2', '3'], 'pretty_far', None)
    ]

    for groups, name, expected in cases:
        output = holepunch.find_intended_security_group(
            [{'GroupName': g} for g in groups], name)

        assert output == expected


# mostly to ensure py2 gets bytes right
def test_get_external_ip():
    read_mock = mock.Mock()
    read_mock.read.return_value = b'192.168.1.1'

    with mock.patch('holepunch.urlopen', return_value=read_mock):
        assert holepunch.get_external_ip() == ipaddress.ip_address('192.168.1.1')


def test_find_matching_security_groups():
    client_mock = mock.Mock()
    client_mock.describe_security_groups.return_value = {'SecurityGroups': ['bar']}

    output = holepunch.find_matching_security_groups(client_mock, 'foo')

    assert output == ['bar', 'bar']

    for filter_name in ['group-name', 'group-id']:
        client_mock.describe_security_groups.assert_any_call(Filters=[{
            'Name': filter_name,
            'Values': ['foo']
        }])


class TestBuildIngressPermissions:
    def test_adding_ips(self):
        sg_permissions = [
            dict(zip(['IpProtocol', 'FromPort', 'ToPort', 'IpRanges'], vals))
            for vals in [
                    ('tcp', 90, 90, [{'CidrIp': '1.1.1.1/32', 'Description': 'foo'}]),
                    ('udp', 91, 91, [{'CidrIp': '1.1.1.1/32', 'Description': 'foo'}]),
            ]
        ]

        new, existing = holepunch.build_ingress_permissions(
            {'IpPermissions': sg_permissions},
            _str_to_cidr('1.1.1.1'),
            [(90, 9090)],
            ['tcp', 'udp'],
            'bar')
        print('existing = %s' % repr(existing))
        assert new == [{
            'IpProtocol': proto,
            'FromPort': 90,
            'ToPort': 9090,
            'IpRanges': [{'CidrIp': '1.1.1.1/32', 'Description': 'bar'}]
        } for proto in ['tcp', 'udp']]

        assert existing == []

    def test_ignores_existing_ips(self):
        sg_permissions = [
            dict(zip(['IpProtocol', 'FromPort', 'ToPort', 'IpRanges'], vals))
            for vals in [
                    ('tcp', 90, 9090, [{'CidrIp': '1.1.1.1/32', 'Description': 'foo'}]),
                    ('udp', 90, 9090, [{'CidrIp': '1.1.1.1/32', 'Description': 'foo'}]),
            ]
        ]

        new, existing = holepunch.build_ingress_permissions(
            {'IpPermissions': sg_permissions},
            _str_to_cidr('1.1.1.1'),
            [(90, 9090), (91,91)],
            {'tcp'},
            'bar')

        assert new == [{
            'IpProtocol': 'tcp',
            'FromPort': 91,
            'ToPort': 91,
            'IpRanges': [{'CidrIp': '1.1.1.1/32', 'Description': 'bar'}]
        }]

        assert existing == [{
            'IpProtocol': 'tcp',
            'FromPort': 90,
            'ToPort': 9090,
            'IpRanges': [{'CidrIp': '1.1.1.1/32', 'Description': 'bar'}]
        }]

    def test_ignores_existing_ips_when_some_dont_match(self):
        sg_permissions = [
            dict(zip(['IpProtocol', 'FromPort', 'ToPort', 'IpRanges'], vals))
            for vals in [
                    ('tcp', 90, 9090, [{'CidrIp': '1.1.1.1/32', 'Description': 'bar'},
                                       {'CidrIp': '2.2.2.2/32', 'Description': 'foo'}]),
            ]
        ]

        new, existing = holepunch.build_ingress_permissions(
            {'IpPermissions': sg_permissions},
            _str_to_cidr('1.1.1.1'),
            [(90, 9090)],
            {'tcp'},
            'bar')

        assert new == []
        assert existing == [{
            'IpProtocol': 'tcp',
            'FromPort': 90,
            'ToPort': 9090,
            'IpRanges': [{'CidrIp': '1.1.1.1/32', 'Description': 'bar'}]
        }]

    def test_ipv6_support(self):
        sg_permissions = [
            dict(zip(['IpProtocol', 'FromPort', 'ToPort', 'Ipv6Ranges'], vals))
            for vals in [
                    ('tcp', 90, 9090, [{'CidrIpv6': '1:1:1:1::/32', 'Description': 'bar'},
                                       {'CidrIpv6': '2:2:2:2::/32', 'Description': 'foo'}]),
            ]
        ]

        new, existing = holepunch.build_ingress_permissions(
            {'IpPermissions': sg_permissions},
            ipaddress.ip_interface('1:1:1:1::/32'),
            [(90, 9090)],
            {'tcp'},
            'bar')

        assert new == []
        assert existing == [{
            'IpProtocol': 'tcp',
            'FromPort': 90,
            'ToPort': 9090,
            'Ipv6Ranges': [{'CidrIpv6': '1:1:1:1::/32', 'Description': 'bar'}]
        }]
