import pytest

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
