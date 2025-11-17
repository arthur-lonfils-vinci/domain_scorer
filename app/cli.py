import argparse
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

from app.analyzers.domain_analyzer import analyze_domain
from app.analyzers.email_analyzer import analyze_email
from app.features.registry import FEATURES

console = Console()

# ----------------------------------------------------------
# Table display for each layer
# ----------------------------------------------------------

def display_layer(title: str, layer: dict):
    panel = Panel(f"[bold cyan]{title}: {layer['target']}[/bold cyan]", expand=False)
    console.print(panel)

    table = Table(show_lines=True)
    table.add_column("Feature")
    table.add_column("Weight", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Reason", overflow="fold")

    weights = layer.get("weights", {})

    for feat, score in layer["features"].items():
        weight = weights.get(feat, 0.0)
        table.add_row(
            feat,
            f"{weight:.3f}",  # NEW
            f"{score:.3f}",
            layer["reasons"].get(feat, "")
        )

    console.print(table)
    console.print()


# ----------------------------------------------------------
# Main result rendering
# ----------------------------------------------------------

def display_result(data: dict):
    console.print(
        Panel(
            f"[yellow bold]{data['type'].upper()}[/yellow bold]: {data['target']}",
            expand=False
        )
    )

    console.print(f"[green]Overall score:[/green] {data['score']}")
    console.print(f"[red]Threat level:[/red] {data['threat']}")
    console.print()

    layers = data.get("layers")

    # Domain
    if data["type"] == "domain":
        display_layer("Root Domain", layers["root"])
        display_layer("FQDN / Subdomain", layers["fqdn"])

    # Email
    elif data["type"] == "email":
        display_layer("Email User Part", layers["user"])
        display_layer("FQDN / Subdomain", layers["fqdn"])
        display_layer("Root Domain", layers["root"])


# ----------------------------------------------------------
# Explain view
# ----------------------------------------------------------

def display_explain(data: dict):
    layers = data["layers"]
    root = Tree(f"[bold yellow]Explanation for {data['target']}[/bold yellow]")

    for lname, layer in layers.items():
        ln = root.add(f"[green]{lname.upper()} Layer[/green]")

        for feat, score in layer["features"].items():
            category = FEATURES[feat].category.value
            node = ln.add(f"[cyan]{feat}[/cyan] — {category}")
            node.add(f"score={score}")
            node.add(f"[dim]{layer['reasons'].get(feat, '')}[/dim]")

    console.print(root)


# ----------------------------------------------------------
# CLI entrypoint
# ----------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Threat scoring CLI")

    parser.add_argument("target", help="Domain or email")

    parser.add_argument(
        "-t", "--type",
        choices=["auto", "domain", "email"],
        default="auto"
    )

    parser.add_argument("--json", action="store_true")
    parser.add_argument("--explain", action="store_true")

    args = parser.parse_args()

    if args.type == "domain":
        result = analyze_domain(args.target)
    elif args.type == "email":
        result = analyze_email(args.target)
    else:
        result = analyze_email(args.target) if "@" in args.target else analyze_domain(args.target)

    if args.json:
        console.print_json(json.dumps(result, indent=2))
        return

    display_result(result)

    if args.explain:
        display_explain(result)


if __name__ == "__main__":
    main()
