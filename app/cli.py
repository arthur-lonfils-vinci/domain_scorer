import argparse
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from app.analyzers.domain_analyzer import analyze_domain
from app.analyzers.email_analyzer import analyze_email

console = Console()


CATEGORY_MAP = {
    "vendor_": "External Vendors",
    "dns_": "DNS",
    "spf_dkim": "DNS",
    "mx_record": "DNS",
    "tld_risk": "DNS",
    "tls_": "TLS",
    "domain_age": "WHOIS",
    "lexical_entropy": "Heuristics",
    "asn_reputation": "Network / ASN",
    "robots_txt": "Web Presence",
    "favicon_hash": "Web Presence",
    "email_localpart": "Email Heuristics",
}


def classify_feature(name: str) -> str:
    """Return category name for a feature."""
    for prefix, category in CATEGORY_MAP.items():
        if name.startswith(prefix):
            return category
    return "Other"


def display_result(data: dict) -> None:
    target = data.get("target", "?")
    target_type = data.get("type", "?")
    score = data.get("score", 0.0)
    threat = data.get("threat", "Unknown")

    console.print(
        Panel(
            f"[bold yellow]{target_type.upper()}:[/bold yellow] {target}",
            expand=False,
        )
    )
    console.print(f"[bold green]Overall score:[/bold green] {score}")
    console.print(f"[bold red]Threat level:[/bold red] {threat}\n")

    feature_scores = data.get("feature_scores", {})
    feature_reasons = data.get("feature_reasons", {})

    if not feature_scores:
        console.print("[dim]No feature scores available.[/dim]")
        return

    table = Table(title="Feature Scores", show_lines=True)
    table.add_column("Feature", style="cyan", no_wrap=True)
    table.add_column("Score", justify="right", style="green")
    table.add_column("Reason", style="magenta")

    for name, score in feature_scores.items():
        reason = feature_reasons.get(name, "")
        table.add_row(name, f"{score:.3f}", reason)

    console.print(table)


def display_explain(data: dict) -> None:
    """Explain features grouped by categories."""
    target = data.get("target")
    console.print(Panel(f"[bold blue]Explanation for {target}[/bold blue]", expand=False))

    root = Tree(f"[yellow]Threat Explanation Breakdown[/yellow]")

    feature_scores = data.get("feature_scores", {})
    feature_reasons = data.get("feature_reasons", {})

    # Build category → nodes
    categories = {}
    for name in feature_scores:
        cat = classify_feature(name)
        categories.setdefault(cat, []).append(name)

    for category, names in sorted(categories.items()):
        cat_tree = root.add(f"[bold green]{category}[/bold green]")
        for name in names:
            score = feature_scores[name]
            reason = feature_reasons.get(name, "")
            cat_tree.add(f"[cyan]{name}[/cyan] → [white]score={score}[/white]\n    [dim]{reason}[/dim]")

    console.print(root)


def main():
    parser = argparse.ArgumentParser(
        description="Threat scoring CLI (domain/email)",
    )
    parser.add_argument(
        "target",
        help="Domain or email to score",
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=["auto", "domain", "email"],
        default="auto",
        help="Force interpretation as domain/email or auto-detect (default: auto)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of pretty tables",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Show grouped breakdown of feature impact",
    )

    args = parser.parse_args()
    target = args.target

    # Choose analyzer
    if args.type == "domain":
        result = analyze_domain(target)
    elif args.type == "email":
        result = analyze_email(target)
    else:
        result = analyze_email(target) if "@" in target else analyze_domain(target)

    # Output modes
    if args.json:
        console.print_json(json.dumps(result, indent=2))
    else:
        display_result(result)
        if args.explain:
            display_explain(result)


if __name__ == "__main__":
    main()
