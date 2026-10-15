"""
telve: kod asistanlarını (Cursor, Claude Code) Telveguard'a bağlar.

    telve setup --gateway https://telveguard.sirket.local
    telve login
    telve install cursor            # Cursor hook'ları
    telve install claude --route    # Claude Code hook'ları + model trafiği Telveguard'dan
    telve doctor
"""
import argparse
import json
import sys
import webbrowser
from pathlib import Path

from . import __version__, client, hooks, install
from .config import ConfigError, load, managed_path, save_user


def _cfg():
    try:
        return load()
    except ConfigError as e:
        sys.exit(f"telve: {e}")


def cmd_setup(args) -> int:
    cfg = _cfg()
    if "gateway" in cfg.managed_keys:
        print(f"Gateway adresi kurum tarafından belirlenmiş: {cfg.gateway_url} ({managed_path()})")
        return 0
    updates = {"gateway": args.gateway.rstrip("/")}
    if args.ca_file:
        updates["ca_file"] = str(Path(args.ca_file).resolve())
    path = save_user(updates)
    cfg = _cfg()
    info = client.gateway_info(cfg)
    print(f"Kaydedildi: {path}\nGateway {info.get('version')} · kimlik modu: {info['auth_mode']}")
    if info["auth_mode"] == "jwt":
        print("Sıradaki adım: telve login")
    return 0


def cmd_login(args) -> int:
    cfg = _cfg()
    if args.token:
        token = sys.stdin.readline().strip() if args.token == "-" else args.token
        client.save_credentials({"access_token": token, "expires_at": 0})
        print("Token kaydedildi.")
        return 0
    info = client.gateway_info(cfg)
    if info["auth_mode"] != "jwt":
        print("Gateway header modunda (geliştirme): giriş gerekmez. Kimlik: telve setup ile user / team.")
        return 0
    oidc = {**(info.get("oidc") or {}), **(cfg.oidc or {})}

    def announce(url, code):
        print(f"Tarayıcıda açın: {url}\nKod: {code}")
        if not args.no_browser:
            webbrowser.open(url)
    try:
        client.device_login(cfg, oidc, announce)
    except client.AuthRequired as e:
        sys.exit(f"telve: {e}")
    print("Giriş yapıldı.")
    return 0


def cmd_logout(args) -> int:
    print("Çıkış yapıldı." if client.clear_credentials() else "Zaten giriş yapılmamış.")
    return 0


def cmd_token(args) -> int:
    """Claude Code apiKeyHelper: stdout'a yalnızca token."""
    try:
        print(client.access_token(_cfg()))
    except (client.AuthRequired, client.GatewayError) as e:
        print(f"telve: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_hook(args) -> int:
    cfg = _cfg()
    if args.tool == "cursor":
        return hooks.run(lambda data: hooks.cursor(cfg, data))
    return hooks.run(lambda data: hooks.claude(cfg, data, routed=args.routed))


def cmd_install(args, remove: bool = False) -> int:
    cfg = _cfg()
    command = args.command or install.telve_command()
    if args.tool == "cursor":
        path = install.cursor_path(args.scope)
        data = install.cursor_config({} if args.print else install._load(path), command,
                                     cfg.fail_closed, remove)
    else:
        if getattr(args, "route", False) and not cfg.gateway_url:
            sys.exit("telve: --route için önce telve setup --gateway ...")
        path = install.claude_path(args.scope)
        data = install.claude_config({} if args.print else install._load(path), command, cfg.gateway_url,
                                     getattr(args, "route", False), cfg.fail_closed, remove)
    if args.print:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    try:
        install.write(path, data)
    except PermissionError:
        sys.exit(f"telve: {path} yazılamadı; kurumsal kapsam yönetici yetkisi ister (sudo) ya da --print ile MDM'e verin")
    print(f"{'Kaldırıldı' if remove else 'Kuruldu'}: {path}")
    if not remove and args.tool == "cursor":
        print("Cursor'u yeniden başlatın. Hata ayrıntısı: Output paneli > Hooks.")
    return 0


def cmd_check(args) -> int:
    cfg = _cfg()
    text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8", errors="replace")
    try:
        result = client.check(cfg, args.client, args.event, text, args.model, args.routed)
    except (client.AuthRequired, client.GatewayError) as e:
        sys.exit(f"telve: {e}")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["action"] in ("allow", "warn", "mask") else 2


def cmd_doctor(args) -> int:
    ok = True

    def line(good, label, detail=""):
        nonlocal ok
        ok &= bool(good) or good is None
        mark = {True: "✓", False: "✗", None: "–"}[good if good is None else bool(good)]
        print(f"{mark} {label}" + (f": {detail}" if detail else ""))

    print(f"telve {__version__}")
    try:
        cfg = load()
    except ConfigError as e:
        line(False, "Yapılandırma", str(e))
        return 1
    line(bool(cfg.gateway_url), "Gateway", cfg.gateway_url or "tanımlı değil (telve setup --gateway ...)")
    line(None, "Kaynaklar", ", ".join(cfg.sources) or "varsayılanlar")
    line(None, "Erişilemezse", "durdur (fail_closed)" if cfg.fail_closed else "yerel tarama")
    if cfg.gateway_url:
        try:
            info = client.gateway_info(cfg)
            line(True, "Bağlantı", f"Telveguard {info.get('version')} · {info['auth_mode']}")
            r = client.check(cfg, "claude-code", "shell", "telve doctor")
            who = r.get("identity") or {}
            line(True, "Kimlik", f"{who.get('user')} ({', '.join(who.get('teams') or [])}) · "
                                 f"{'doğrulanmış (OIDC)' if who.get('source') == 'jwt' else 'beyan (header modu)'}")
        except (client.GatewayError, client.AuthRequired) as e:
            line(False, "Bağlantı / kimlik", str(e))
    for tool, paths in (("Cursor", install.cursor_path), ("Claude Code", install.claude_path)):
        found = {scope: install.installed(paths(scope)) for scope in ("enterprise", "user", "project")}
        active = [s for s, v in found.items() if v]
        line(bool(active) or None, f"{tool} hook'ları", ", ".join(active) if active else "kurulu değil")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="telve", description="Kod asistanlarını Telveguard'a bağlar.")
    p.add_argument("--version", action="version", version=f"telve {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="gateway adresini kaydet")
    s.add_argument("--gateway", required=True)
    s.add_argument("--ca-file", help="kurum içi CA sertifikası (PEM)")
    s.set_defaults(func=cmd_setup)

    s = sub.add_parser("login", help="kurum hesabıyla giriş (OIDC cihaz akışı)")
    s.add_argument("--token", help="cihaz akışı yerine hazır token ('-': stdin)")
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(func=cmd_login)

    sub.add_parser("logout", help="kayıtlı oturumu sil").set_defaults(func=cmd_logout)
    sub.add_parser("token", help="geçerli access token (Claude Code apiKeyHelper)").set_defaults(func=cmd_token)

    s = sub.add_parser("hook", help="araçların çağırdığı hook (stdin JSON -> stdout JSON)")
    s.add_argument("tool", choices=["cursor", "claude"])
    s.add_argument("--routed", action="store_true", help="Claude Code model trafiği Telveguard'dan geçiyor")
    s.set_defaults(func=cmd_hook)

    for name, remove in (("install", False), ("uninstall", True)):
        s = sub.add_parser(name, help=f"hook'ları {'kur' if not remove else 'kaldır'}")
        s.add_argument("tool", choices=["cursor", "claude"])
        s.add_argument("--scope", choices=["user", "project", "enterprise"], default="user")
        s.add_argument("--print", action="store_true", help="yazma, içeriği bas (MDM paketi için)")
        s.add_argument("--command", help="hook komutunun yolu (varsayılan: bulunan telve)")
        if not remove:
            s.add_argument("--route", action="store_true",
                           help="Claude Code: model trafiğini de Telveguard'a yönlendir")
        s.set_defaults(func=lambda a, r=remove: cmd_install(a, r))

    s = sub.add_parser("check", help="bir metni / dosyayı politikadan geçir (deneme)")
    s.add_argument("file", help="dosya ya da '-' (stdin)")
    s.add_argument("--client", choices=["cursor", "claude-code"], default="cursor")
    s.add_argument("--event", choices=["prompt", "file", "shell", "tool_input", "tool_output"], default="prompt")
    s.add_argument("--model", default="")
    s.add_argument("--routed", action="store_true")
    s.set_defaults(func=cmd_check)

    sub.add_parser("doctor", help="kurulumu denetle").set_defaults(func=cmd_doctor)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except client.GatewayError as e:
        sys.exit(f"telve: {e}")


if __name__ == "__main__":
    sys.exit(main())
