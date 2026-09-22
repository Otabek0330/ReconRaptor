#!/usr/bin/env python3
"""
Recon Raptor v1.1.0 — Multi-phase reconnaissance tool

Usage:
  recon_raptor scan -d example.com -w subdomain_wl.txt -dw dir_wl.txt
  recon_raptor scan -D domains.txt --quick
  recon_raptor scan -d example.com --skip-ports --skip-traversal
  recon_raptor check
  sudo recon_raptor install --all
  recon_raptor install --dry-run
  recon_raptor config --init
"""

import sys
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT_DIR))

VERSION = "1.1.0"

try:
    from rich.console import Console
    from rich.text    import Text
    _RICH   = True
    # Banner goes to STDERR so `config --show` (and any piped command) emits
    # only its real output on stdout.
    console = Console(stderr=True)
except ImportError:
    _RICH   = False
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
            f"  [dim]Subdomain Enum  •  DNS  •  Port Scan  •  HTTP Probe  "
            f"•  Dir Traversal  •  IP Enrichment  •  v{VERSION}[/dim]\n")
    else:
        # Non-rich fallback: still keep the banner off stdout.
        print(art, file=sys.stderr)
        print(f"  Subdomain Enum · DNS · Port Scan · HTTP Probe · "
              f"Dir Traversal · IP Enrichment  v{VERSION}\n", file=sys.stderr)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='recon_raptor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  recon_raptor scan -d example.com
  recon_raptor scan -d example.com -w ~/wordlists/subdomains.txt -dw ~/wordlists/dirs.txt
  recon_raptor scan -D domains.txt --quick
  recon_raptor scan -d example.com --skip-ports --skip-traversal
  recon_raptor scan -d example.com --full
  sudo recon_raptor install --all
  sudo recon_raptor install --exclude gowitness,gau,nuclei
  recon_raptor install --dry-run
  recon_raptor check
  recon_raptor config --init
  recon_raptor config --validate
        """
    )

    sub = parser.add_subparsers(dest='command', metavar='command')
    sub.required = True

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = sub.add_parser('scan', help='Run the full recon pipeline')

    target = sp.add_mutually_exclusive_group(required=True)
    target.add_argument('-d', '--domain', metavar='DOMAIN',
                        help='Single target domain (e.g. example.com)')
    target.add_argument('-D', '--domains', metavar='FILE',
                        help='File with one domain per line')

    sp.add_argument('-w',  '--wordlist',     metavar='FILE',
                    help='Subdomain bruteforce wordlist')
    sp.add_argument('-dw', '--dir-wordlist', metavar='FILE', dest='dir_wordlist',
                    help='Directory traversal wordlist (DIFFERENT from -w)')
    sp.add_argument('-o',  '--output',       metavar='DIR',
                    help='Output directory (overrides config output_dir)')
    sp.add_argument('--config', metavar='FILE', default=None,
                    help='Path to config.yaml')
    sp.add_argument('--fresh', action='store_true',
                    help='Ignore any existing checkpoint — re-run every phase from scratch')

    profiles = sp.add_mutually_exclusive_group()
    profiles.add_argument('--quick', action='store_true',
                          help='Passive enum + HTTP probe only')
    profiles.add_argument('--full',  action='store_true',
                          help='All phases + optional extras')

    sp.add_argument('--skip-passive',   dest='skip_passive',   action='store_true')
    sp.add_argument('--skip-brute',     dest='skip_brute',     action='store_true')
    sp.add_argument('--skip-resolve',   dest='skip_resolve',   action='store_true')
    sp.add_argument('--skip-ports',     dest='skip_ports',     action='store_true',
                    help='Skip port scanning phase')
    sp.add_argument('--skip-http',      dest='skip_http',      action='store_true')
    sp.add_argument('--skip-traversal', dest='skip_traversal', action='store_true')
    sp.add_argument('--skip-enrich',    dest='skip_enrich',    action='store_true')

    # ── check ─────────────────────────────────────────────────────────────────
    cp = sub.add_parser('check', help='Show installed tools and capability status')
    cp.add_argument('--config', metavar='FILE', default=None)

    # ── install ───────────────────────────────────────────────────────────────
    ip = sub.add_parser('install',
                        help='Install tools (requires sudo; use --dry-run without)')
    ip.add_argument('--all',     dest='install_all', action='store_true',
                    help='Include optional tools (gowitness, gau, nuclei)')
    ip.add_argument('--exclude', metavar='TOOLS',
                    help='Comma-separated tools to skip')
    ip.add_argument('--dry-run', dest='dry_run', action='store_true',
                    help='Print all install commands, execute nothing')

    # ── config ────────────────────────────────────────────────────────────────
    cfp = sub.add_parser('config', help='Manage configuration file')
    cfp.add_argument('--config', metavar='FILE', default=None,
                     help='Path to config.yaml (for --show / --validate)')
    cfg_group = cfp.add_mutually_exclusive_group(required=True)
    cfg_group.add_argument('--init',     action='store_true',
                           help='Create config.yaml from defaults')
    cfg_group.add_argument('--show',     action='store_true',
                           help='Print effective configuration')
    cfg_group.add_argument('--validate', action='store_true',
                           help='Validate config.yaml')

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Keep the banner off stdout for `config --show` so its YAML is pipeable.
    if not (args.command == 'config' and getattr(args, 'show', False)):
        print_banner()

    if args.command == 'scan':
        from modules.core.config  import load_config
        from modules.core.scanner import run_scan
        run_scan(args, load_config(args.config))

    elif args.command == 'check':
        from modules.core.config    import load_config
        from modules.core.preflight import run_check
        run_check(load_config(args.config))

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
                print("[!] pyyaml not installed: pip install pyyaml")
                sys.exit(1)
            print(yaml.dump(load_config(args.config),
                            default_flow_style=False, sort_keys=False))
        elif args.validate:
            validate_config(load_config(args.config))


if __name__ == '__main__':
    main()