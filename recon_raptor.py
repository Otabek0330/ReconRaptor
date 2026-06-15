#!/usr/bin/env python3
"""
Recon Raptor — Multi-phase reconnaissance tool
Subdomain enumeration · DNS resolution · HTTP probing
Directory traversal · IP enrichment · Reporting

Usage:
  recon_raptor scan -d example.com
  recon_raptor scan -D domains.txt -w wordlist.txt
  recon_raptor scan -d example.com --quick
  recon_raptor check
  sudo recon_raptor install --all
  sudo recon_raptor install --exclude gowitness,nuclei
  recon_raptor install --dry-run
  recon_raptor config --init
  recon_raptor config --show
  recon_raptor config --validate
"""

import sys
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT_DIR))

VERSION = "1.0.0"

try:
    from rich.console import Console
    from rich.text import Text
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None


def print_banner():
    art = r"""
      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝

      ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗
      ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
      ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
      ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
      ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    """
    if _RICH:
        banner = Text()
        banner.append(art, style="bold blue")
        console.print(banner)
        console.print(
            f"  [dim]Subdomain Enum  •  DNS  •  HTTP Probe  •  Dir Traversal  •  IP Enrichment  •  v{VERSION}[/dim]\n"
        )
    else:
        print(art)
        print(f"  Subdomain Enum · DNS · HTTP Probe · Dir Traversal · IP Enrichment  v{VERSION}\n")


def build_parser():
    parser = argparse.ArgumentParser(
        prog='recon_raptor',
        description='Multi-phase subdomain enumeration and directory traversal tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  recon_raptor scan -d example.com
  recon_raptor scan -D domains.txt -w /path/to/wordlist.txt
  recon_raptor scan -d example.com --quick
  recon_raptor scan -d example.com --full --skip-traversal
  sudo recon_raptor install --all
  sudo recon_raptor install --exclude gowitness,gau,nuclei
  recon_raptor install --dry-run
  recon_raptor check
  recon_raptor config --init
        """
    )

    sub = parser.add_subparsers(dest='command', metavar='command')
    sub.required = True

    # ── scan ─────────────────────────────────────────────────────────────────
    sp = sub.add_parser('scan', help='Run the full recon pipeline')

    target = sp.add_mutually_exclusive_group(required=True)
    target.add_argument('-d', '--domain', metavar='DOMAIN',
                        help='Single target domain (e.g. example.com)')
    target.add_argument('-D', '--domains', metavar='FILE',
                        help='File containing target domains, one per line')

    sp.add_argument('-w', '--wordlist', metavar='FILE',
                    help='Wordlist for bruteforce — any language, tool auto-cleans it')
    sp.add_argument('-o', '--output', metavar='DIR',
                    help='Output directory (overrides config output_dir)')
    sp.add_argument('--config', metavar='FILE', default=None,
                    help='Path to config.yaml (default: config.yaml next to this script)')

    profiles = sp.add_mutually_exclusive_group()
    profiles.add_argument('--quick', action='store_true',
                          help='Passive enum + HTTP probe only — no bruteforce or traversal')
    profiles.add_argument('--full', action='store_true',
                          help='All phases including optional extras')

    sp.add_argument('--skip-passive',   dest='skip_passive',   action='store_true')
    sp.add_argument('--skip-brute',     dest='skip_brute',     action='store_true')
    sp.add_argument('--skip-resolve',   dest='skip_resolve',   action='store_true')
    sp.add_argument('--skip-http',      dest='skip_http',      action='store_true')
    sp.add_argument('--skip-traversal', dest='skip_traversal', action='store_true')
    sp.add_argument('--skip-enrich',    dest='skip_enrich',    action='store_true')

    # ── check ────────────────────────────────────────────────────────────────
    cp = sub.add_parser('check', help='Show installed tools and capability status')
    cp.add_argument('--config', metavar='FILE', default=None)

    # ── install ──────────────────────────────────────────────────────────────
    ip = sub.add_parser('install',
                        help='Install required tools — requires sudo (use --dry-run without sudo)')
    ip.add_argument('--all', dest='install_all', action='store_true',
                    help='Install all tools including optional ones')
    ip.add_argument('--exclude', metavar='TOOLS',
                    help='Comma-separated list of tools to skip (e.g. gowitness,nuclei)')
    ip.add_argument('--dry-run', dest='dry_run', action='store_true',
                    help='Print every install command without executing — no sudo needed')

    # ── config ───────────────────────────────────────────────────────────────
    cfp = sub.add_parser('config', help='Manage configuration file')
    cfg_group = cfp.add_mutually_exclusive_group(required=True)
    cfg_group.add_argument('--init',     action='store_true',
                           help='Create config.yaml from bundled defaults')
    cfg_group.add_argument('--show',     action='store_true',
                           help='Print current effective configuration')
    cfg_group.add_argument('--validate', action='store_true',
                           help='Validate config.yaml and report issues')

    return parser


def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == 'scan':
        from modules.core.config  import load_config
        from modules.core.scanner import run_scan
        cfg = load_config(args.config)
        run_scan(args, cfg)

    elif args.command == 'check':
        from modules.core.config   import load_config
        from modules.core.preflight import run_check
        cfg = load_config(args.config)
        run_check(cfg)

    elif args.command == 'install':
        from modules.core.installer import run_install
        run_install(args)

    elif args.command == 'config':
        from modules.core.config import load_config, init_config, validate_config
        if args.init:
            init_config()
        elif args.show:
            try:
                import yaml
            except ImportError:
                print("[!] pyyaml not installed. Run: pip install pyyaml")
                sys.exit(1)
            cfg = load_config()
            print(yaml.dump(cfg, default_flow_style=False, sort_keys=False))
        elif args.validate:
            cfg = load_config()
            validate_config(cfg)


if __name__ == '__main__':
    main()
