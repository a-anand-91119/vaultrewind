#!/usr/bin/env bash
# Disposable bootable Linux fixture. Never point these commands at an existing server.
set -euo pipefail
umask 077
fixture_dir="${VAULTREWIND_VM_DIR:-$PWD/.runtime/vm}"
fixture_port="${VAULTREWIND_VM_SSH_PORT:-22229}"
mkdir -p "$fixture_dir"
case "${1:-help}" in
  prepare)
    command -v qemu-system-x86_64 >/dev/null
    command -v cloud-localds >/dev/null
    if [[ ! -f "$fixture_dir/id_ed25519" ]]; then ssh-keygen -q -t ed25519 -N '' -f "$fixture_dir/id_ed25519"; fi
    python3 - "$fixture_dir" <<'PY'
import hashlib, pathlib, sys, urllib.request
directory=pathlib.Path(sys.argv[1])
base='https://cloud.debian.org/images/cloud/trixie/latest/'
name='debian-13-generic-amd64.qcow2'
checks=urllib.request.urlopen(base+'SHA512SUMS').read().decode()
expected=next(line.split()[0] for line in checks.splitlines() if len(line.split())>1 and line.split()[-1].lstrip('*')==name)
path=directory/name
if not path.exists(): urllib.request.urlretrieve(base+name,path)
if hashlib.file_digest(path.open('rb'),'sha512').hexdigest()!=expected: raise SystemExit('Debian image checksum mismatch')
(directory/'base-checksum.txt').write_text(expected+'  '+name+'\n')
PY
    qemu-img create -q -f qcow2 -F qcow2 -b "$fixture_dir/debian-13-generic-amd64.qcow2" "$fixture_dir/fixture.qcow2" 24G
    fixture_pubkey="$(cat "$fixture_dir/id_ed25519.pub")"
    cat > "$fixture_dir/user-data" <<EOF
#cloud-config
hostname: vaultrewind-disposable
disable_root: false
ssh_pwauth: false
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - $fixture_pubkey
package_update: true
packages: [docker.io, python3, python3-venv, sudo, curl, sqlite3]
runcmd:
  - [systemctl, enable, --now, docker]
  - [sh, -c, 'touch /root/vaultrewind-fixture-ready']
EOF
    printf 'instance-id: vaultrewind-disposable\nlocal-hostname: vaultrewind-disposable\n' > "$fixture_dir/meta-data"
    cloud-localds "$fixture_dir/seed.img" "$fixture_dir/user-data" "$fixture_dir/meta-data"
    ;;
  start)
    if [[ -f "$fixture_dir/qemu.pid" ]] && kill -0 "$(cat "$fixture_dir/qemu.pid")" 2>/dev/null; then
      echo 'Fixture is already running'; exit 0
    fi
    qemu-system-x86_64 -accel tcg -machine q35 -smp 2 -m 2048 -display none \
      -drive "file=$fixture_dir/fixture.qcow2,if=virtio,format=qcow2" \
      -drive "file=$fixture_dir/seed.img,if=virtio,format=raw,readonly=on" \
      -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$fixture_port-:22" -device virtio-net-pci,netdev=net0 \
      -serial "file:$fixture_dir/console.log" -pidfile "$fixture_dir/qemu.pid" -daemonize
    echo "Disposable fixture started; loopback SSH port $fixture_port. Console: $fixture_dir/console.log"
    ;;
  status)
    [[ -f "$fixture_dir/qemu.pid" ]] && kill -0 "$(cat "$fixture_dir/qemu.pid")"
    tail -12 "$fixture_dir/console.log"
    ;;
  stop)
    if [[ -f "$fixture_dir/qemu.pid" ]]; then kill "$(cat "$fixture_dir/qemu.pid")"; fi
    ;;
  *) echo 'Usage: scripts/vm-fixture.sh prepare|start|status|stop'; exit 2 ;;
esac
