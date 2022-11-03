from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
import pytest
from sigma.backends.ala.ala import AzureLogAnalyticsBackend
from sigma.collection import SigmaCollection


@pytest.fixture()
def ala_backend():
    return AzureLogAnalyticsBackend()


def test_ala_in_expression(ala_backend : AzureLogAnalyticsBackend):
    assert ala_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    CommandLine|contains|all:
                        - 'cmd'
                    CommandLine2:
                        - '/c'
                    CommandLine3|re:
                    - 'copy'
                condition: selection
            falsepositives:
                - unknown
            level: high
        """)
    ) == "test_category | where (CommandLine contains 'cmd' and (CommandLine2 =~ '/c') and (CommandLine3 matches regex @'(?i)copy'))"

def test_ala_regex_query(ala_backend : AzureLogAnalyticsBackend):
    assert ala_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == "test_category | where ((fieldA matches regex @'(?i)foo.*bar') and (fieldB =~ 'foo') and (fieldC =~ 'bar'))"


def test_ala_single_regex_query(ala_backend : AzureLogAnalyticsBackend):
    assert ala_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """)
    ) == "test_category | where ((fieldA matches regex @'(?i)foo.*bar'))"


def test_ala_cidr_query_single(ala_backend : AzureLogAnalyticsBackend):
    assert ala_backend.convert(
        SigmaCollection.from_yaml("""
title: Test
status: test
logsource:
  category: test_category
  product: test_product
detection:
  sel:
    fieldA|cidr: 192.168.0.0/16
    fieldB: foo
    fieldC: bar
  condition: sel
        """)
    ) == """test_category | where (ipv4_is_in_range(fieldA, "192.168.0.0/16") and (fieldB =~ 'foo') and (fieldC =~ 'bar'))"""


def test_ala_cidr_query_in_list(ala_backend : AzureLogAnalyticsBackend):
    assert ala_backend.convert(
        SigmaCollection.from_yaml("""
title: Test
status: test
logsource:
  category: test_category
  product: test_product
detection:
  sel:
    fieldA|cidr: 
     - 192.168.0.0/16
     - 172.16.0.0/32
    fieldB: foo
    fieldC: bar
  condition: sel
        """)
    ) == """test_category | where ((ipv4_is_in_range(fieldA, "192.168.0.0/16") or ipv4_is_in_range(fieldA, "172.16.0.0/32")) and (fieldB =~ 'foo') and (fieldC =~ 'bar'))"""