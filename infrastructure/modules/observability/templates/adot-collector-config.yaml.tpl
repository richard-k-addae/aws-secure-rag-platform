receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

extensions:
  health_check:
    endpoint: 0.0.0.0:13133

processors:
  memory_limiter:
    check_interval: 1s
    limit_percentage: 75
    spike_limit_percentage: 20
  batch:
    send_batch_size: 256
    timeout: 5s
  resource:
    attributes:
      - key: service.instance.id
        action: delete

exporters:
  awsemf:
    region: ${aws_region}
    log_group_name: ${log_group_name}
    log_stream_name: "collector-{TaskId}"
    namespace: ${namespace}
    dimension_rollup_option: "NoDimensionRollup"
    resource_to_telemetry_conversion:
      enabled: false
    metric_declarations:
      - dimensions: [[http.route, http.request.method, http.response.status_code]]
        metric_name_selectors:
          - "^http\\.server\\.request\\.duration$"
      - dimensions: [[outcome, role]]
        metric_name_selectors:
          - "^rag\\.query\\.duration$"
      - dimensions: [[role]]
        metric_name_selectors:
          - "^rag\\.query\\.retrieved_chunks$"
      - dimensions: [[operation, outcome]]
        metric_name_selectors:
          - "^rag\\.retrieval\\.duration$"
          - "^rag\\.retrieval\\.results$"
          - "^db\\.client\\.operation\\.duration$"
      - dimensions: [[operation, model, outcome]]
        metric_name_selectors:
          - "^gen_ai\\.client\\.operation\\.duration$"
      - dimensions: [[operation, model, token.type]]
        metric_name_selectors:
          - "^gen_ai\\.client\\.token\\.usage$"
      - dimensions: [[classification, outcome]]
        metric_name_selectors:
          - "^rag\\.ingest\\.duration$"
          - "^rag\\.ingest\\.chunks$"
      - dimensions: [[event], [event, role]]
        metric_name_selectors:
          - "^rag\\.security\\.events$"

service:
  extensions: [health_check]
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [awsemf]
