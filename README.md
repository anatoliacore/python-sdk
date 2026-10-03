# AnatoliaCore Python SDK

```bash
pip install anatoliacore
export ANATOLIACORE_API_KEY='ac_live_...'
anatoliacore instances list
```

Until the first PyPI release is published, install the checked-out package with
`pip install ./sdk/python`.

```python
from anatoliacore import AnatoliaCore

cloud = AnatoliaCore(api_key="ac_live_...")
instances = cloud.list_instances()
```

Mutation methods create a random idempotency key unless one is supplied. Keep
and reuse an explicit key when retrying the same logical operation.

Use `request_with_metadata` when a mutation needs durable operation polling:

```python
result = cloud.request_with_metadata("POST", "/instances", body={"name": "web", "cpu_cores": 2})
operation = cloud.wait_operation(result.operation_id) if result.operation_id else None
```

Validate webhook signatures with `verify_webhook` before parsing or acting on
an event. The helper enforces HMAC, timestamp tolerance, event ID binding, and a
safe payload size limit.
