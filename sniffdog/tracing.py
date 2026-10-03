"""Send only timing and numeric scan metadata to optional Sentry tracing."""

from contextlib import contextmanager
import os


_sdk = None


def before_send(event, hint):
    return None


def before_send_transaction(event, hint):
    kept = {key: event[key] for key in ("event_id", "type", "transaction",
                                         "start_timestamp", "timestamp") if key in event}
    trace = event.get("contexts", {}).get("trace", {})
    kept["contexts"] = {"trace": {key: trace[key] for key in
                                  ("trace_id", "span_id", "parent_span_id", "op", "status")
                                  if key in trace}}
    kept["spans"] = []
    for item in event.get("spans", []):
        clean = {key: item[key] for key in ("op", "description", "start_timestamp",
                                            "timestamp", "status", "span_id", "parent_span_id",
                                            "trace_id") if key in item}
        clean["data"] = {key: value for key, value in item.get("data", {}).items()
                         if isinstance(value, (int, float)) and not isinstance(value, bool)}
        kept["spans"].append(clean)
    return kept


def configure() -> bool:
    global _sdk
    dsn = os.getenv("SENTRY_DSN")
    if not dsn:
        _sdk = None
        return False
    try:
        import sentry_sdk
    except ImportError:
        _sdk = None
        return False
    try:
        sentry_sdk.init(dsn=dsn, traces_sample_rate=1.0, send_default_pii=False,
                        before_send=before_send, before_send_transaction=before_send_transaction,
                        default_integrations=False, auto_enabling_integrations=False)
    except (ValueError, OSError):
        _sdk = None
        return False
    _sdk = sentry_sdk
    return True


@contextmanager
def transaction():
    if _sdk is None:
        yield None
    else:
        with _sdk.start_transaction(name="scan", op="scan") as active:
            yield active


@contextmanager
def span(name: str):
    if _sdk is None:
        yield None
    else:
        with _sdk.start_span(op=name, description=name) as active:
            yield active


def count(name: str, value: int | float) -> None:
    if _sdk is None or not isinstance(value, (int, float)) or isinstance(value, bool):
        return
    active = _sdk.get_current_scope().span
    if active is not None:
        active.set_data(name, value)
