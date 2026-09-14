#!/usr/bin/env python3
"""Build an auditable cloud-cost report from a user-supplied pricing manifest."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


INPUT_SCHEMA = "oasis-cloud-cost-input-v1"
OUTPUT_SCHEMA = "oasis-cloud-cost-report-v1"
CATEGORIES = ("compute", "storage", "data_transfer")


def decimal_value(value: object, field: str) -> Decimal:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not number.is_finite() or number < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return number


def integer_value(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be a non-negative integer") from error
    if number < 0 or str(number) != str(value):
        raise ValueError(f"{field} must be a non-negative integer")
    return number


def require_text(container: dict[str, Any], field: str, context: str) -> str:
    value = container.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}.{field} must be non-empty text")
    return value.strip()


def require_utc_timestamp(value: str, context: str) -> str:
    if not value.endswith("Z"):
        raise ValueError(f"{context} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{context} must be a valid ISO-8601 UTC timestamp") from error
    return value


def priced_line(
    campaign_id: str, category: str, row: dict[str, Any], index: int,
) -> dict[str, Any]:
    context = f"{campaign_id}.{category}[{index}]"
    quantity = decimal_value(row.get("quantity"), f"{context}.quantity")
    unit_price = decimal_value(
        row.get("unit_price_usd"), f"{context}.unit_price_usd"
    )
    unit = require_text(row, "unit", context)
    region = require_text(row, "region", context)
    description = require_text(row, "description", context)
    subtotal = quantity * unit_price
    return {
        "campaign_id": campaign_id,
        "category": category,
        "region": region,
        "description": description,
        "quantity": float(quantity),
        "unit": unit,
        "unit_price_usd": float(unit_price),
        "subtotal_usd": float(subtotal),
    }


def build_report(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema") != INPUT_SCHEMA:
        raise ValueError(f"expected schema {INPUT_SCHEMA}")
    if payload.get("template") is True:
        raise ValueError("cost template must be populated before use")
    if payload.get("currency") != "USD":
        raise ValueError("currency must be USD")
    pricing = payload.get("pricing")
    if not isinstance(pricing, dict):
        raise ValueError("pricing must be an object")
    pricing_source = require_text(pricing, "source_url", "pricing")
    if not pricing_source.startswith("https://"):
        raise ValueError("pricing.source_url must use https")
    pricing_retrieved = require_utc_timestamp(
        require_text(pricing, "retrieved_at_utc", "pricing"),
        "pricing.retrieved_at_utc",
    )
    campaigns = payload.get("campaigns")
    if not isinstance(campaigns, list) or not campaigns:
        raise ValueError("campaigns must be a non-empty list")

    seen: set[str] = set()
    line_items: list[dict[str, Any]] = []
    campaign_summaries: list[dict[str, Any]] = []
    for index, campaign in enumerate(campaigns):
        if not isinstance(campaign, dict):
            raise ValueError(f"campaigns[{index}] must be an object")
        campaign_id = require_text(campaign, "campaign_id", f"campaigns[{index}]")
        route = require_text(campaign, "route", f"campaigns[{index}]")
        if campaign_id in seen:
            raise ValueError(f"duplicate campaign_id: {campaign_id}")
        seen.add(campaign_id)
        measured = integer_value(
            campaign.get("measured_runs"), f"{campaign_id}.measured_runs"
        )
        warmups = integer_value(
            campaign.get("warmup_runs"), f"{campaign_id}.warmup_runs"
        )
        failed = integer_value(
            campaign.get("failed_runs"), f"{campaign_id}.failed_runs"
        )
        campaign_lines = []
        for category in CATEGORIES:
            rows = campaign.get(category)
            if not isinstance(rows, list) or not rows:
                raise ValueError(
                    f"{campaign_id}.{category} must contain at least one "
                    "measured line item (zero quantity is allowed)"
                )
            campaign_lines.extend(
                priced_line(campaign_id, category, row, row_index)
                for row_index, row in enumerate(rows)
                if isinstance(row, dict)
            )
            if len([row for row in campaign_lines if row["category"] == category]) == 0:
                raise ValueError(f"{campaign_id}.{category} has no valid line item")
        line_items.extend(campaign_lines)
        by_category = {
            category: sum(
                Decimal(str(row["subtotal_usd"]))
                for row in campaign_lines if row["category"] == category
            )
            for category in CATEGORIES
        }
        campaign_summaries.append({
            "campaign_id": campaign_id,
            "route": route,
            "measured_runs": measured,
            "warmup_runs": warmups,
            "failed_runs": failed,
            "attempted_runs": measured + warmups + failed,
            "compute_usd": float(by_category["compute"]),
            "storage_usd": float(by_category["storage"]),
            "data_transfer_usd": float(by_category["data_transfer"]),
            "total_usd": float(sum(by_category.values(), Decimal(0))),
        })

    category_totals = {
        category: float(sum(
            (Decimal(str(row["subtotal_usd"])) for row in line_items
             if row["category"] == category),
            Decimal(0),
        ))
        for category in CATEGORIES
    }
    return {
        "schema": OUTPUT_SCHEMA,
        "currency": "USD",
        "pricing_source_url": pricing_source,
        "pricing_retrieved_at_utc": pricing_retrieved,
        "pricing_notes": str(pricing.get("notes", "")),
        "covered_campaign_ids": sorted(seen),
        "campaigns": campaign_summaries,
        "line_items": line_items,
        "totals": {
            **{f"{name}_usd": value for name, value in category_totals.items()},
            "grand_total_usd": float(sum(
                (Decimal(str(value)) for value in category_totals.values()),
                Decimal(0),
            )),
            "measured_runs": sum(
                row["measured_runs"] for row in campaign_summaries
            ),
            "warmup_runs": sum(
                row["warmup_runs"] for row in campaign_summaries
            ),
            "failed_runs": sum(
                row["failed_runs"] for row in campaign_summaries
            ),
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Cloud experiment cost report",
        "",
        f"Pricing source: {report['pricing_source_url']}",
        f"Pricing retrieved at: `{report['pricing_retrieved_at_utc']}`",
        "",
        "| Campaign | Route | Measured | Warm-up | Failed | Compute (USD) | Storage (USD) | Transfer (USD) | Total (USD) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["campaigns"]:
        lines.append(
            f"| {row['campaign_id']} | {row['route']} | "
            f"{row['measured_runs']} | {row['warmup_runs']} | "
            f"{row['failed_runs']} | {row['compute_usd']:.6f} | "
            f"{row['storage_usd']:.6f} | "
            f"{row['data_transfer_usd']:.6f} | {row['total_usd']:.6f} |"
        )
    totals = report["totals"]
    lines.extend([
        "",
        "## Totals",
        "",
        f"- Measured runs: {totals['measured_runs']}",
        f"- Warm-up runs: {totals['warmup_runs']}",
        f"- Failed runs: {totals['failed_runs']}",
        f"- Compute: USD {totals['compute_usd']:.6f}",
        f"- Storage: USD {totals['storage_usd']:.6f}",
        f"- Data transfer: USD {totals['data_transfer_usd']:.6f}",
        f"- Grand total: USD {totals['grand_total_usd']:.6f}",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", "--json-out", dest="out", type=Path,
                        required=True)
    parser.add_argument("--md-out", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    report = build_report(payload)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.md_out:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(render_markdown(report), encoding="utf-8")
    print(f"wrote={args.out}")
    if args.md_out:
        print(f"wrote={args.md_out}")
    print(f"grand_total_usd={report['totals']['grand_total_usd']:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
