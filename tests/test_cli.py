import pytest
import mock

import holepunch


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
def test_get_local_cidr():
    read_mock = mock.Mock()
    read_mock.read.return_value = b'foo'

    with mock.patch('holepunch.urlopen', return_value=read_mock):
        assert holepunch.get_local_cidr() == 'foo/32'


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
