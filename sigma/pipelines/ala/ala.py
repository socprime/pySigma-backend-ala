from sigma.pipelines.common import \
    logsource_windows
#     logsource_windows_process_creation, \
#     logsource_windows_registry_add, \
#     logsource_windows_registry_delete, \
#     logsource_windows_registry_event, \
#     logsource_windows_registry_set, \
#     logsource_windows_file_event, \
#     logsource_linux_process_creation
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation
# from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline


windows_service_source_mapping = {
    'application': 'SecurityEvent',
    'process_creation': 'SysmonEvent',
    'registry_event': 'SysmonEvent',
    'file_event': 'SysmonEvent',
    'image_load': 'SysmonEvent',
    'service_creation': 'SecurityEvent',
    'ps_script': 'Event',
    'ps_module': 'Event',
}

windows_field_mapping = {
    'claims.name': 'Caller',
    'properties.message': 'OperationNameValue',
    'properties.eventCategory': 'CategoryValue',
    'resourceProviderName.value': 'ResourceProviderValue',
    'category': 'Category',
    'activityDisplayName': 'OperationName',
    'loggedByService': 'LoggedByService',
    'result': 'Result',
    'initiatedBy.user.userPrincipalName': 'initiatedBy.user.userPrincipalName',
    'dns_query_name': 'dns.question.name',
    'ComputerName': 'Computer',
    'Event-ID': 'EventID',
    'Event_ID': 'EventID',
    'eventId': 'EventID',
    'event_id': 'EventID',
    'event-id': 'EventID',
    'eventid': 'EventID',
    'hashes': 'FileHash',
    'Hashes': 'FileHash',
    'file_hash': 'FileHash',
    'url.query': 'URL',
    'resource.URL': 'URL',
    'src_ip': 'SourceIp',
    'source.ip': 'SourceIp',
    'FileName': 'TargetFilename',
    'dst_ip': 'DestinationIP',
    'destination.ip': 'DestinationIP',
    'Commandline': 'CommandLine',
    'cmd': 'CommandLine',
    'Image': 'NewProcessName',
    'ParentImage': 'ParentImage'
}

def azure_log_analytics_windows_pipeline():
    return ProcessingPipeline(
        name="Azure Windows log source conditions",
        priority=20,
        items=[
            ProcessingItem(         # log sources mapped from windows_service_source_mapping
                identifier=f"azure_windows_{service}",
                transformation=AddConditionTransformation({ "source": source}),
                rule_conditions=[logsource_windows(service)],
            )
            for service, source in windows_service_source_mapping.items()
        ] + [
            ProcessingItem(     # Field mappings
                identifier="azure_windows_field_mapping",
                transformation=FieldMappingTransformation(windows_field_mapping)
            )
        ]
    )