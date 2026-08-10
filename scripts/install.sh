#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v uv >/dev/null 2>&1; then
    printf '%s\n' "Mitsu's installer needs uv. Install uv, then run this script again." >&2
    exit 1
fi

uv tool install --force "$repo_root"

# Save a small host snapshot for Mitsu's package-management screens. The app
# refreshes this metadata if the OS or package manager changes later.
config_root=${XDG_CONFIG_HOME:-"$HOME/.config"}/mitsu
mkdir -p "$config_root"
chmod 700 "$config_root"
os_id=unknown
os_name=Linux
if [ -r /etc/os-release ]; then
    os_id=$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d "\"'" | tr -cd 'A-Za-z0-9._-')
    os_name=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1 | tr -d "\"'" | tr -cd 'A-Za-z0-9 ._()-')
    [ -n "$os_id" ] || os_id=unknown
    [ -n "$os_name" ] || os_name=Linux
fi
case "$os_id" in
    arch|blackarch|garuda|manjaro) manager_order='pacman apt-get dnf zypper apk yum' ;;
    debian|kali|linuxmint|pop|ubuntu) manager_order='apt-get pacman dnf zypper apk yum' ;;
    fedora|rhel|centos|rocky|almalinux) manager_order='dnf pacman apt-get zypper apk yum' ;;
    opensuse|opensuse-leap|opensuse-tumbleweed|sles) manager_order='zypper pacman apt-get dnf apk yum' ;;
    alpine) manager_order='apk pacman apt-get dnf zypper yum' ;;
    *) manager_order='apt-get pacman dnf zypper apk yum' ;;
esac
package_manager=none
for candidate in $manager_order; do
    if command -v "$candidate" >/dev/null 2>&1; then
        package_manager=$candidate
        break
    fi
done
printf '{"os_id":"%s","os_name":"%s","package_manager":"%s"}\n' \
    "$os_id" "$os_name" "$package_manager" > "$config_root/host.json"
chmod 600 "$config_root/host.json"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    printf '%s\n' "Mitsu is installed. If Docker is missing, SearXNG setup can open Docker's official installer."
    printf '%s\n' "If Docker is installed but unavailable, start its daemon and check your Docker group access."
    exit 0
fi

printf '%s\n' "Prefetching Mitsu's default SearXNG image…"
if docker pull ghcr.io/searxng/searxng:latest; then
    printf '%s\n' "Mitsu and its SearXNG image are ready. SearXNG stays stopped until you enable it in setup."
elif docker pull docker.io/searxng/searxng:latest; then
    printf '%s\n' "Mitsu and its SearXNG image are ready. SearXNG stays stopped until you enable it in setup."
else
    printf '%s\n' "Mitsu is installed. SearXNG will retry downloading its image during setup."
fi
