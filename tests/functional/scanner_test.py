import pytest
import muspell_ssl


class TestScanner():

    @pytest.mark.parametrize("host, port", [
        ("google.com", 445),
        ("google.com", 443),
        ("172.217.173.110", 443),
        ("uol.com", 443),
        ("localhost", 8443),
    ])
    def test_sample(self, host, port):
        scanner = muspell_ssl.Scanner(hostname=host, port=port)
        assert scanner is not None
        scanner.run()
