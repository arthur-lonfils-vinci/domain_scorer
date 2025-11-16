import argparse
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from app.features import hybrid_score
from app.email_features import email_score

console = Console()


# ----------------------------------------------------
# Display Functions
# ----------------------------------------------------

def render_human_output(data, target):
    """Pretty Rich output for CLI."""
    console.print(Panel(f"[bold yellow]Target: {target}[/bold yellow]", expand=False))
    console.print(f"[bold green]Overall score:[/bold green] {data['score']}")
    console.print(f"[bold red]Threat Level:[/bold red] {data['threat']}\n")

    table = Table(title="Feature Scores", show_lines=True)
    table.add_column("Feature", style="cyan", no_wrap=True)
    table.add_column("Score", justify="right", style="green")
    table.add_column("Reason", style="magenta")

    for feature, value in data["feature_scores"].items():
        # Find the matching reason
        reason = next((r for r in data["reasons"] if feature.split('_')[0] in r.lower()), "")
        table.add_row(feature, str(value), reason)

    console.print(table)


# ----------------------------------------------------
# CLI Command Logic
# ----------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Domain & Email Threat Scoring System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", help="Score a domain")
    group.add_argument("--email", help="Score an email")
    group.add_argument("--auto", help="Auto-detect domain or email")

    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--raw", action="store_true", help="Print raw score only")

    args = parser.parse_args()

    # Determine target
    if args.domain:
        target = args.domain
        result = hybrid_score(target)

    elif args.email:
        target = args.email
        result = email_score(target)

    else:
        target = args.auto
        if "@" in target:
            result = email_score(target)
        else:
            result = hybrid_score(target)

    # Output mode
    if args.json:
        print(json.dumps(result, indent=2))
        return

    if args.raw:
        print(result["score"])
        return

    # Default: Pretty rendering
    render_human_output(result, target)


if __name__ == "__main__":
    main()
