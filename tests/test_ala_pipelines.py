import pytest
from sigma.collection import SigmaCollection
from sigma.backends.ala.ala import AzureLogAnalyticsBackend
from sigma.pipelines.ala.ala import (
    windows_service_source_mapping,
    azure_log_analytics_windows_pipeline,
    windows_field_mapping
)
from sigma.exceptions import SigmaTransformationError


@pytest.mark.parametrize(
    ("service", "source"),
    windows_service_source_mapping.items()
)
def test_ala_windows_pipeline_simple(service, source):
    assert AzureLogAnalyticsBackend(processing_pipeline=azure_log_analytics_windows_pipeline()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: {service}
            detection:
                selection:
                    CommandLine|contains|all:
                        - 'cmd'
                    CommandLine2:
                        - '/c'
                    CommandLine3|re:
                    - 'copy'
                condition: selection
        """)
    ) == f"{source} | where (CommandLine contains 'cmd' and (CommandLine2 =~ '/c') and (CommandLine3 matches regex @'(?i)copy'))"


@pytest.mark.parametrize(
    ("field", "mapping"),
    windows_field_mapping.items()
)
def test_ala_windows_field_mapping(field, mapping):
    assert AzureLogAnalyticsBackend(processing_pipeline=azure_log_analytics_windows_pipeline()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                category: test_category
            detection:
                sel:
                    {field}: 123
                condition: sel
        """)
    ) == f"windows | where ({mapping} =~ 123)"
