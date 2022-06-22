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
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == "test_product | where (fieldA == 'valueA' or fieldA == 'valueB' or fieldA == 'valueC*')"


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
    ) == "test_product | where (fieldA matches regex '(?i)foo.*bar' and fieldB == 'foo' and fieldC == 'bar')"


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
    ) == "test_product | where (fieldA matches regex '(?i)foo.*bar')"


def test_ala_cidr_query(ala_backend : AzureLogAnalyticsBackend):
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
    ) == "test_product | where (sip:192.168.0.0/16 and fieldB == 'foo' and fieldC == 'bar')"