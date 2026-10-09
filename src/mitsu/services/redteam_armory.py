"""Package inspection and explicit terminal-driven tool installation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from mitsu.armory.catalog import InstallMethod, ToolSpec
from mitsu.services.host_environment import HostEnvironment


class ArmoryError(RuntimeError):
    """Raised when a catalogued tool cannot be managed on this host."""


@dataclass(frozen=True)
class ToolStatus:
    installed: bool
    managed: bool
    method_id: str | None = None


_TERMINALS = (
    "ghostty",
    "kitty",
    "gnome-terminal",
    "xfce4-terminal",
    "konsole",
    "alacritty",
    "wezterm",
    "foot",
    "xterm",
    "x-terminal-emulator",
)
_INSTALL_METHOD_LABELS = {
    "gem": "RubyGems user install",
    "pipx": "isolated pipx environment",
    "cargo": "Cargo user install",
    "go": "Go user install",
    "git": "managed source checkout",
    "python-source": "isolated Python environment",
    "python-project": "isolated Python environment",
    "official-script": "upstream installer",
}


def _method_label(method_id: str) -> str:
    if method_id.startswith("system:"):
        return "native package manager"
    kind = method_id.split(":", 1)[0]
    return _INSTALL_METHOD_LABELS.get(kind, kind)


def _package_query(manager_id: str, package: str) -> list[str] | None:
    if manager_id == "apt-get":
        return ["dpkg-query", "-W", "-f=${db:Status-Status}", package]
    if manager_id == "pacman":
        return ["pacman", "-Q", package]
    if manager_id in {"dnf", "yum", "zypper"}:
        return ["rpm", "-q", package]
    if manager_id == "apk":
        return ["apk", "info", "-e", package]
    return None


def _package_is_installed(manager_id: str, package: str) -> bool:
    query = _package_query(manager_id, package)
    if query is None or not shutil.which(query[0]):
        return False
    try:
        result = subprocess.run(
            query,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode:
        return False
    return manager_id != "apt-get" or result.stdout.strip() == "installed"


def _run_query(command: list[str], timeout: float = 12.0) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _method_installed(method: InstallMethod, tool: ToolSpec) -> bool:
    if method.kind == "gem":
        command = shutil.which("gem")
        result = _run_query([command, "list", "--local", "--exact", method.package]) if command else None
        return bool(result and any(line.split(" ", 1)[0] == f"{method.package}" for line in result.stdout.splitlines()))
    if method.kind == "pipx":
        pipx = shutil.which("pipx")
        command = [pipx, "list", "--json"] if pipx else [shutil.which("python3") or "python3", "-m", "pipx", "list", "--json"]
        result = _run_query(command)
        if not result or result.returncode:
            return False
        try:
            environments = json.loads(result.stdout).get("venvs", {})
        except (json.JSONDecodeError, AttributeError):
            return False
        package_names = {str(name).casefold().replace("_", "-") for name in environments}
        return method.package.casefold().replace("_", "-") in package_names
    if method.kind == "cargo":
        cargo = shutil.which("cargo")
        result = _run_query([cargo, "install", "--list"]) if cargo else None
        if not result or result.returncode:
            return False
        return any(line.startswith(f"{method.package} v") for line in result.stdout.splitlines())
    if method.kind == "go":
        binary = _go_binary_path(method.executable)
        return bool(binary and binary.is_file())
    if method.kind in {"git", "python-source", "python-project"}:
        marker = _tool_install_directory(tool) / ".mitsu-armory-managed"
        try:
            return marker.read_text(encoding="utf-8").strip() == tool.id
        except OSError:
            return False
    if method.kind == "official-script":
        if method.package == "metasploit-framework":
            # The upstream installer registers a native package. Package
            # inspection handles status and removal for this tool.
            return False
        recorded = _read_install_registry().get(tool.id)
        if recorded != method.id:
            return False
        binary = Path.home() / ".local" / "bin" / method.executable
        return binary.is_file() and os.access(binary, os.X_OK)
    return False


def _go_binary_path(executable: str) -> Path | None:
    go = shutil.which("go")
    if not go:
        return None
    result = _run_query([go, "env", "GOBIN", "GOPATH"], timeout=8.0)
    if not result or result.returncode:
        return None
    values = result.stdout.splitlines()
    if len(values) < 2:
        return None
    root = values[0].strip() or (Path(values[1].split(os.pathsep)[0]) / "bin")
    binary = Path(root) / executable
    return binary if binary.is_file() and os.access(binary, os.X_OK) else None


def _data_root() -> Path:
    configured = os.environ.get("XDG_DATA_HOME")
    return (Path(configured) if configured else Path.home() / ".local" / "share") / "mitsu"


def _tool_install_directory(tool: ToolSpec) -> Path:
    return _data_root() / "armory" / tool.id


def _registry_path() -> Path:
    return _data_root() / "armory" / "managed.json"


def _read_install_registry() -> dict[str, str]:
    try:
        value = json.loads(_registry_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(key): str(method) for key, method in value.items() if isinstance(method, str)}


def _write_install_registry(registry: dict[str, str]) -> None:
    path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".managed-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(registry, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def record_managed_install(tool_id: str, method_id: str) -> None:
    registry = _read_install_registry()
    registry[tool_id] = method_id
    _write_install_registry(registry)


def forget_managed_install(tool_id: str) -> None:
    registry = _read_install_registry()
    if tool_id in registry:
        registry.pop(tool_id)
        _write_install_registry(registry)


def inspect_tool(tool: ToolSpec, environment: HostEnvironment) -> ToolStatus:
    package = tool.packages.get(environment.package_manager_id, "")
    managed = bool(package and _package_is_installed(environment.package_manager_id, package))
    if managed:
        return ToolStatus(True, True, f"system:{environment.package_manager_id}:{package}")
    for method in tool.install_methods:
        if _method_installed(method, tool):
            return ToolStatus(True, True, method.id)
    present = any(shutil.which(executable) for executable in tool.executables)
    return ToolStatus(installed=present, managed=False)


def _package_action(manager_id: str, operation: str, packages: tuple[str, ...] | list[str]) -> list[str]:
    if operation not in {"install", "uninstall"}:
        raise ArmoryError("Choose install or uninstall.")
    if not packages:
        raise ArmoryError("No package name was supplied for this operation.")
    if manager_id == "apt-get":
        return ["apt-get", "install" if operation == "install" else "remove", "-y", *packages]
    if manager_id == "pacman":
        return ["pacman", "-S", "--needed", *packages] if operation == "install" else ["pacman", "-R", *packages]
    if manager_id in {"dnf", "yum"}:
        return [manager_id, "install" if operation == "install" else "remove", "-y", *packages]
    if manager_id == "zypper":
        return ["zypper", "--non-interactive", "install" if operation == "install" else "remove", *packages]
    if manager_id == "apk":
        return ["apk", "add" if operation == "install" else "del", *packages]
    raise ArmoryError("Mitsu could not identify a supported package manager.")


def _package_available(manager_id: str, package: str) -> bool:
    if manager_id == "apt-get":
        apt_cache = shutil.which("apt-cache")
        result = _run_query([apt_cache, "show", package], timeout=8.0) if apt_cache else None
        return bool(result and result.stdout.strip())
    if manager_id == "pacman":
        pacman = shutil.which("pacman")
        result = _run_query([pacman, "-Si", package], timeout=8.0) if pacman else None
        return bool(result and result.returncode == 0)
    if manager_id in {"dnf", "yum"}:
        manager = shutil.which(manager_id)
        result = _run_query(
            [manager, "-q", "list", "--available", package], timeout=12.0
        ) if manager else None
        return bool(result and result.returncode == 0 and package in result.stdout)
    if manager_id == "zypper":
        zypper = shutil.which("zypper")
        result = _run_query(
            [zypper, "--quiet", "search", "--details", "--match-exact", package], timeout=12.0
        ) if zypper else None
        return bool(result and result.returncode == 0 and package in result.stdout)
    if manager_id == "apk":
        apk = shutil.which("apk")
        result = _run_query([apk, "search", "--exact", package], timeout=8.0) if apk else None
        return bool(result and result.returncode == 0 and result.stdout.strip())
    return True


def _pipx_command() -> list[str] | None:
    pipx = shutil.which("pipx")
    if pipx:
        return [pipx]
    python = shutil.which("python3")
    result = _run_query([python, "-m", "pipx", "--version"]) if python else None
    if result and result.returncode == 0:
        return [python, "-m", "pipx"]
    return None


def _method_command(method: InstallMethod, operation: str, tool: ToolSpec) -> str:
    if method.kind == "gem":
        gem = shutil.which("gem") or "gem"
        arguments = [gem, "install", "--user-install", method.package] if operation == "install" else [
            gem, "uninstall", "--user-install", "--all", "--executables", "--ignore-dependencies", method.package,
        ]
        return shlex.join(arguments)
    if method.kind == "pipx":
        command = _pipx_command() or ["pipx"]
        arguments = [*command, "install", method.source or method.package] if operation == "install" else [
            *command, "uninstall", method.package,
        ]
        return shlex.join(arguments)
    if method.kind == "cargo":
        cargo = shutil.which("cargo") or "cargo"
        arguments = [cargo, "install", "--locked", method.package] if operation == "install" else [
            cargo, "uninstall", method.package,
        ]
        return shlex.join(arguments)
    if method.kind == "go":
        if operation == "install":
            go = shutil.which("go") or "go"
            return shlex.join([go, "install", "-v", f"{method.package}@latest"])
        binary = _go_binary_path(method.executable)
        if binary is None or not binary.is_file():
            raise ArmoryError(f"Could not locate {method.executable} in Go's configured bin directory.")
        return shlex.join([shutil.which("rm") or "rm", "--", str(binary)])
    if method.kind in {"git", "python-source", "python-project"}:
        directory = _tool_install_directory(tool)
        marker = directory / ".mitsu-armory-managed"
        if operation == "uninstall":
            try:
                owned = marker.read_text(encoding="utf-8").strip() == tool.id
            except OSError:
                owned = False
            if not owned:
                raise ArmoryError("Mitsu could not verify ownership of the managed source directory.")
            return shlex.join([shutil.which("rm") or "rm", "-rf", "--", str(directory)])
        source = shlex.quote(method.source)
        parent = shlex.quote(str(directory.parent))
        target = shlex.quote(str(directory))
        clone = (
            f"mkdir -p {parent} && "
            f"temporary=$(mktemp -d {parent}/.{tool.id}.XXXXXX) && "
            f"trap 'rm -rf -- \"$temporary\"' EXIT && "
            f"git clone --depth 1 -- {source} \"$temporary/source\" && "
            f"[ ! -e {target} ] && mv -- \"$temporary\" {target}"
        )
        if method.kind == "git":
            return f"{clone} && printf '%s\\n' {shlex.quote(tool.id)} > {shlex.quote(str(marker))}"
        if method.kind == "python-project":
            python = shutil.which("python3") or "python3"
            install_project = (
                f'"$target/venv/bin/python" -m pip install --disable-pip-version-check '
                f'"$target/source"'
            )
            if method.requirements_file:
                manifest = shlex.quote(str(Path("source") / method.requirements_file))
                install_project += (
                    f' && "$target/venv/bin/python" -m pip install '
                    f'--disable-pip-version-check -r "$target/{manifest}"'
                )
            return (
                f"target={target} && {clone} && "
                f"trap 'rm -rf -- \"$target\"' EXIT && "
                f"{shlex.quote(python)} -m venv \"$target/venv\" && "
                f"{install_project} && "
                f"printf '%s\\n' {shlex.quote(tool.id)} > {shlex.quote(str(marker))} && trap - EXIT"
            )
        if not method.requirements_file:
            raise ArmoryError(f"The Python source method for {tool.name} has no requirements manifest.")
        python = shutil.which("python3") or "python3"
        manifest = shlex.quote(str(Path("source") / method.requirements_file))
        return (
            f"target={target} && {clone} && "
            f"trap 'rm -rf -- \"$target\"' EXIT && "
            f"{shlex.quote(python)} -m venv \"$target/venv\" && "
            f"\"$target/venv/bin/python\" -m pip install --disable-pip-version-check "
            f"-r \"$target/{manifest}\" && "
            f"printf '%s\\n' {shlex.quote(tool.id)} > {shlex.quote(str(marker))} && trap - EXIT"
        )
    if method.kind == "official-script":
        if operation == "uninstall":
            if method.package == "metasploit-framework":
                raise ArmoryError("Mitsu removes Metasploit through the native package manager.")
            binary = Path.home() / ".local" / "bin" / method.executable
            if _read_install_registry().get(tool.id) != method.id:
                raise ArmoryError("Mitsu could not verify that it installed this upstream binary.")
            return shlex.join([shutil.which("rm") or "rm", "--", str(binary)])
        url = shlex.quote(method.source)
        if method.package == "metasploit-framework":
            curl = shutil.which("curl") or "curl"
            sudo = shutil.which("sudo")
            if os.geteuid() != 0 and not sudo:
                raise ArmoryError("sudo is required for the official Metasploit installer.")
            elevated = [sudo, "bash"] if sudo and os.geteuid() != 0 else ["bash"]
            url = shlex.quote(method.source)
            pipeline = f"{shlex.quote(curl)} --fail --location --proto '=https' --tlsv1.2 {url} | {shlex.join(elevated)}"
            return f"bash -o pipefail -c {shlex.quote(pipeline)}"
        curl = shutil.which("curl") or "curl"
        shell = shutil.which("sh") or "/bin/sh"
        bin_directory = shlex.quote(str(Path.home() / ".local" / "bin"))
        args = [curl, "--fail", "--location", "--proto", "=https", "--tlsv1.2", method.source]
        pipeline = f"mkdir -p {bin_directory} && {shlex.join(args)} | {shlex.quote(shell)} -s -- -b {bin_directory}"
        return f"bash -o pipefail -c {shlex.quote(pipeline)}"
    raise ArmoryError(f"Unsupported install method: {method.kind}.")


def _method_runtime_available(method: InstallMethod) -> bool:
    if method.kind == "pipx":
        return _pipx_command() is not None
    if method.kind in {"python-source", "python-project"}:
        return bool(shutil.which("git") and shutil.which("python3"))
    if method.kind == "official-script":
        return bool(shutil.which("curl") and shutil.which("bash"))
    executable = {
        "gem": "gem",
        "go": "go",
        "cargo": "cargo",
        "git": "git",
    }.get(method.kind)
    return bool(executable and shutil.which(executable))


def _select_install_method(tool: ToolSpec, environment: HostEnvironment) -> tuple[str, str]:
    manager_id = environment.package_manager_id
    package = tool.packages.get(manager_id)
    package_available = bool(package and _package_available(manager_id, package))
    if package_available:
        return f"system:{manager_id}:{package}", "native package manager"
    for method in tool.install_methods:
        if method.supported_managers and manager_id not in method.supported_managers:
            continue
        if _method_runtime_available(method):
            return method.id, _method_label(method.id)
        prerequisites = (method.prerequisite_packages or {}).get(manager_id, ())
        if prerequisites and shutil.which(manager_id):
            return method.id, _method_label(method.id)
    raise ArmoryError(
        f"No supported install source is available for {tool.name} on this host. Check the native package repositories or install a supported toolchain."
    )


def _method_by_id(tool: ToolSpec, method_id: str) -> InstallMethod:
    method = next((candidate for candidate in tool.install_methods if candidate.id == method_id), None)
    if method is None:
        raise ArmoryError(f"The saved install source for {tool.name} is no longer in the catalog.")
    return method


def _terminal_command(terminal_id: str, terminal_path: str, script: str) -> list[str]:
    shell = shutil.which("sh") or "/bin/sh"
    shell_command = [shell, "-c", script]
    if terminal_id == "ghostty":
        return [terminal_path, "-e", *shell_command]
    if terminal_id == "kitty":
        # A single-instance kitty invocation otherwise returns as soon as it
        # hands the command to the existing GUI process. Wait for its window
        # to close so Mitsu can keep tracking package status during the install.
        return [
            terminal_path,
            "--single-instance",
            "--wait-for-single-instance-window-close",
            *shell_command,
        ]
    if terminal_id == "gnome-terminal":
        return [terminal_path, "--wait", "--", *shell_command]
    if terminal_id == "xfce4-terminal":
        command_text = shlex.join(shell_command)
        return [terminal_path, "--disable-server", "--command", command_text]
    if terminal_id == "konsole":
        return [terminal_path, "--separate", "-e", *shell_command]
    if terminal_id == "alacritty":
        return [terminal_path, "-e", *shell_command]
    if terminal_id == "wezterm":
        return [terminal_path, "start", "--always-new-process", "--", *shell_command]
    if terminal_id == "foot":
        return [terminal_path, "-e", *shell_command]
    if terminal_id == "xterm":
        return [terminal_path, "-e", *shell_command]
    return [terminal_path, "-e", *shell_command]


def _find_terminal() -> tuple[str, str] | None:
    aliases = {
        "ghostty": "ghostty",
        "kitty": "kitty",
        "wezterm": "wezterm",
        "alacritty": "alacritty",
        "foot": "foot",
        "xfce4-terminal": "xfce4-terminal",
        "gnome-terminal": "gnome-terminal",
        "konsole": "konsole",
        "xterm": "xterm",
    }
    preferred = aliases.get(os.environ.get("TERM_PROGRAM", "").casefold())
    configured = Path(os.environ.get("TERMINAL", "")).name
    preferred = preferred or (configured if configured in _TERMINALS else None)
    if os.environ.get("KITTY_WINDOW_ID"):
        preferred = "kitty"
    candidates = ((preferred,) if preferred else ()) + tuple(
        terminal for terminal in _TERMINALS if terminal != preferred
    )
    return next(
        ((terminal, path) for terminal in candidates if (path := shutil.which(terminal))),
        None,
    )


def open_install_terminal(
    tool: ToolSpec,
    environment: HostEnvironment,
    operation: str,
) -> tuple[subprocess.Popen, str]:
    """Open a terminal for one allowlisted package or upstream installer."""

    if operation not in {"install", "uninstall"}:
        raise ArmoryError("Choose install or uninstall.")
    manager_id = environment.package_manager_id
    if operation == "install":
        method_id, method_name = _select_install_method(tool, environment)
    else:
        status = inspect_tool(tool, environment)
        if not status.installed or not status.managed or not status.method_id:
            raise ArmoryError(f"Mitsu cannot safely identify a managed installation of {tool.name}.")
        method_id = status.method_id
        method_name = _method_label(method_id)

    terminal = _find_terminal()
    if terminal is None:
        raise ArmoryError("No supported terminal emulator was found to show the package operation.")

    preflight: list[str] = []
    if method_id.startswith("system:"):
        _, selected_manager, package = method_id.split(":", 2)
        manager_path = shutil.which(selected_manager)
        if not manager_path:
            raise ArmoryError(f"{selected_manager} is no longer available on PATH.")
        package_command = _package_action(selected_manager, operation, (package,))
        package_command[0] = manager_path
        if os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if not sudo:
                raise ArmoryError("sudo is required to manage system packages, but it was not found.")
            package_command = [sudo, "--", *package_command]
        command = shlex.join(package_command)
        source = f"{package} · {environment.package_manager_name}"
    else:
        method = _method_by_id(tool, method_id)
        source = method.source or method.package
        requirements = (method.prerequisite_packages or {}).get(manager_id, ())
        runtime_packages = {
            "go": {"go", "golang", "golang-go"},
            "cargo": {"cargo"},
            "gem": {"ruby"},
            "pipx": {"pipx", "python-pipx", "python3-pipx", "py3-pipx"},
            "git": {"git"},
            "python-source": {"git", "python", "python3"},
            "python-project": {"git", "python", "python3"},
            "official-script": {"curl", "bash"},
        }.get(method.kind, set()) if _method_runtime_available(method) else set()
        missing_requirements = ()
        if operation == "install" and manager_id:
            missing_requirements = tuple(
                package
                for package in requirements
                if package not in runtime_packages
                and not _package_is_installed(manager_id, package)
            )
        if missing_requirements:
            manager_path = shutil.which(manager_id)
            if not manager_path:
                raise ArmoryError(f"{environment.package_manager_name} is no longer available on PATH.")
            prerequisite_command = _package_action(manager_id, "install", missing_requirements)
            prerequisite_command[0] = manager_path
            if os.geteuid() != 0:
                sudo = shutil.which("sudo")
                if not sudo:
                    raise ArmoryError("sudo is required to install the toolchain prerequisite, but it was not found.")
                prerequisite_command = [sudo, "--", *prerequisite_command]
            preflight.append(shlex.join(prerequisite_command))
        command = _method_command(method, operation, tool)

    operation_title = "Install" if operation == "install" else "Remove"
    script_lines = [
        f"printf '\\nMitsu RedTeam Armory · {operation_title} {tool.name}\\n'",
        f"printf 'Method: {method_name}\\nSource: {source}\\n\\n'",
    ]
    for prerequisite in preflight:
        script_lines.extend((prerequisite, "if [ \"$?\" -ne 0 ]; then printf '\\nPrerequisite installation failed.\\n'; exit 1; fi"))
    script_lines.extend((
        f"if {command}; then",
        "  result=0",
        "else",
        "  result=$?",
        "fi",
        "if [ \"$result\" -eq 0 ]; then",
        f"  printf '\\n{operation_title} complete. Return to Mitsu to refresh the list.\\n'",
        "else",
        f"  printf '\\n{operation_title} failed with exit code %s. Review the output above.\\n' \"$result\"",
        "fi",
        "printf '\\nPress Enter to close this terminal… '",
        "IFS= read -r _ || :",
        "exit \"$result\"",
    ))
    script = "\n".join(script_lines)
    terminal_id, terminal_path = terminal
    try:
        process = subprocess.Popen(
            _terminal_command(terminal_id, terminal_path, script),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as error:
        raise ArmoryError(f"Could not open {terminal_id}: {error}") from error
    return process, method_id
