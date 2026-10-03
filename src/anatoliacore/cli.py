from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from anatoliacore.client import AnatoliaCore, AnatoliaCoreError


def _json_object(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError("value must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise argparse.ArgumentTypeError("value must be a JSON object")
    return decoded


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="anatoliacore", description="AnatoliaCore Cloud CLI")
    parser.add_argument(
        "--base-url", default=os.getenv("ANATOLIACORE_BASE_URL", "https://console.anatoliacore.com/api/public/v1")
    )
    subparsers = parser.add_subparsers(dest="resource", required=True)

    instances = subparsers.add_parser("instances")
    instance_commands = instances.add_subparsers(dest="action", required=True)
    instance_commands.add_parser("list")
    get_instance = instance_commands.add_parser("get")
    get_instance.add_argument("id")
    create_instance = instance_commands.add_parser("create")
    create_instance.add_argument("--json", required=True, type=_json_object)
    create_instance.add_argument("--idempotency-key")
    power_instance = instance_commands.add_parser("power")
    power_instance.add_argument("id")
    power_instance.add_argument("power_action", choices=["power_on", "power_off", "reboot", "hard_reset"])
    power_instance.add_argument("--idempotency-key")
    delete_instance = instance_commands.add_parser("delete")
    delete_instance.add_argument("id")
    delete_instance.add_argument("--confirm-name", required=True)
    delete_instance.add_argument("--idempotency-key")

    vdcs = subparsers.add_parser("vdcs")
    vdc_commands = vdcs.add_subparsers(dest="action", required=True)
    vdc_commands.add_parser("list")
    create_vdc = vdc_commands.add_parser("create")
    create_vdc.add_argument("--json", required=True, type=_json_object)
    create_vdc.add_argument("--idempotency-key")

    operations = subparsers.add_parser("operations")
    operation_commands = operations.add_subparsers(dest="action", required=True)
    get_operation = operation_commands.add_parser("get")
    get_operation.add_argument("id")
    wait_operation = operation_commands.add_parser("wait")
    wait_operation.add_argument("id")
    wait_operation.add_argument("--timeout", type=float, default=300)

    catalog = subparsers.add_parser("catalog")
    catalog.add_subparsers(dest="action", required=True).add_parser("instance-types")

    raw = subparsers.add_parser("raw")
    raw.add_argument("method", choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    raw.add_argument("path")
    raw.add_argument("--json", type=_json_object)
    raw.add_argument("--idempotency-key")
    return parser


def _run(client: AnatoliaCore, args: argparse.Namespace):
    if args.resource == "instances":
        if args.action == "list":
            return client.list_instances()
        if args.action == "get":
            return client.get_instance(args.id)
        if args.action == "create":
            return client.create_instance(args.json, idempotency_key=args.idempotency_key)
        if args.action == "power":
            return client.power_instance(args.id, args.power_action, idempotency_key=args.idempotency_key)
        if args.action == "delete":
            return client.delete_instance(
                args.id,
                confirmation_name=args.confirm_name,
                idempotency_key=args.idempotency_key,
            )
    if args.resource == "vdcs":
        if args.action == "list":
            return client.list_vdcs()
        if args.action == "create":
            return client.create_vdc(args.json, idempotency_key=args.idempotency_key)
    if args.resource == "operations":
        if args.action == "get":
            return client.get_operation(args.id)
        if args.action == "wait":
            return client.wait_operation(args.id, timeout=args.timeout)
    if args.resource == "catalog":
        return client.list_instance_types()
    if args.resource == "raw":
        return client.request(args.method, args.path, body=args.json, idempotency_key=args.idempotency_key)
    raise RuntimeError("Unsupported command")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    api_key = os.getenv("ANATOLIACORE_API_KEY", "")
    if not api_key:
        print("ANATOLIACORE_API_KEY is required", file=sys.stderr)
        return 2
    try:
        result = _run(AnatoliaCore(api_key=api_key, base_url=args.base_url), args)
    except AnatoliaCoreError as exc:
        print(json.dumps({"error": exc.code, "message": exc.message, "request_id": exc.request_id}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
