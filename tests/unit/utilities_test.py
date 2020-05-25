import os
import pytest
import muspell_ssl
from muspell_ssl import Utilities


class TestUtilities():


    def test_environment_setup(self):
        assert os.environ.get("SAMPLEENV") == "123"

    def test_dns_lookup(self):
        ip = Utilities.dns_lookup(hostname="google.com", port=443)
        assert ip is not None
        assert isinstance(ip, str)
        assert ip == "172.217.30.46"

    def test_unlikely_host(self):
        with pytest.raises(muspell_ssl.errors.UnableToResolveDNS):
            _ = Utilities.dns_lookup(
                hostname="iwllneverexitInThisUniverse1234.com",
                port=443)
