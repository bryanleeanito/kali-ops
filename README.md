# kali-ops — Co-Pilot Sistem Kali untuk AI Agent

Plugin OpenCode (v2) yang membuat **AI Agent bekerja sama dengan sistem Kali**:
tahu state mesin tanpa menebak, bisa memeriksa tool/jaringan/service/firewall/paket,
dan **tidak bisa merusak sistem** karena perubahan selalu lewat permission engine.

Dibuat 2026-10-21 (mesin Kali, OpenCode #2).

## Kenapa kit ini ada

Track offensive & track kernel butuh "mata" ke sistem: apakah toolnya ada? service
mana yang gagal? port apa yang listening? disk hampir penuh? firewall statusnya?
Tanpa itu, agent cenderung menebak — dan menebak = false positive (dilarang
AGENTS.md platform).

## Yang CEO (tool native namespace `kali`)

| tool | fungsi | nature |
|---|---|---|
| `kali_sys_status` | distro, kernel, uptime, CPU, RAM, disk (/ & /boot), service gagal, update apt menunggu, proxy env | read-only |
| `kali_tool_check` | tool terpasang? path, versi, paket apt penyedia, kandidat paket kalau belum ada | read-only |
| `kali_net_status` | interface + IP, route, DNS, listening port + proses owning, Tor/proxy, tes konektivitas | read-only |
| `kali_svc_status` | status unit systemd (aktif/enable/log tail) + daftar unit gagal | read-only |
| `kali_fw_status` | ufw, nftables, iptables (baca rule, tidak mengubah) | read-only |
| `kali_disk_usage` | top-N penyusun disk (default /root) + partisi + inode | read-only |
| `kali_pkg_info` | status/versi/ukuran/dependensi paket apt | read-only |
| `kali_pkg_change` | install/remove/update paket — **dry-run dulu**, eksekusi hanya atas izin user | MENULIS (gate) |

Plus **context injection**: tiap request model menerima snapshot sistem ringkas
(distro, kernel, RAM, disk, Tor, user) → agent selalu tahu dunia kerjanya.

## Guardrail (permission hook `evaluate`)

**DENY** (tidak bisa di-bypass, ada alasannya):
hapus `/` `/etc` `/boot` `/usr` `/bin` `/sbin` `/lib` `/var` `/home` atau `~` ·
format disk (`mkfs*`, `wipefs*`, `sgdisk --zap-all`) · tulis mentah ke device
(`dd … of=/dev/*`, `> /dev/sd*`) · matikan firewall (`ufw disable`, `iptables -F`,
`nft flush ruleset`) · ubah user (`userdel`, `useradd`, `passwd`, tulis `/etc/passwd`) ·
`chmod -R 777 /` · `chown -R … /` · `history -c` · `shred`.

**ASK** (wajib izin user):
`apt install/remove/upgrade` · `dpkg -i` · `pip/npm install` ·
`systemctl stop/restart/disable/mask` · `kill*` · `sysctl -w` (global) ·
`chmod`/`chown` · `crontab` · tulis `/etc` · `git push`/`reset --hard`/`clean -f` ·
`curl … | sh` · `sudo`.

### Anti-false-positive (penting)

Pola di-anchor ke **posisi perintah** (awal baris / setelah `;` `&` `|` / `sudo`),
dan **isi heredoc dibuang** sebelum pencocokan. Jadi:
- `rm -rf /boot` → DENY ✅
- `echo 'rm -rf /boot' > catatan.txt` → LOLOS ✅ (cuma echo)
- `cat <<'EOF' … mkfs.ext4 /dev/sda1 … EOF` → LOLOS ✅ (dokumentasi, bukan eksekusi)

Diuji: `node tests/test_guardrail_kali.mjs` → **52/52 assertion**.

## Install

```sh
sh install.sh            # salin plugin ke ~/.config/opencode/plugins/ (backup otomatis)
opencode reload
```

Atau manual:
```sh
cp plugins/kali-ops.js ~/.config/opencode/plugins/kali-ops.js
```

Plugin dimuat otomatis (auto-discovery `~/.config/opencode/plugins/*.js`).

## Test

```sh
node tests/test_guardrail_kali.mjs
```

## Struktur

```
kali-ops/
├── plugins/kali-ops.js      ← plugin (tool + guardrail + context)
├── tests/test_guardrail_kali.mjs  ← 52 assertion
├── install.sh
└── README.md
```

## Relasi

- `07-SISTEM/kernel-specialist/` → tool namespace `kernel` (kernel/dev/tuning).
- `09-MIGRASI/kali/AGENTS.md` → doktrin **Kolaborasi AI Agent <-> Sistem Kali**
  (LIHAT → USULKAN → IZIN → KERJAKAN → VERIFIKASI).
- `07-SISTEM/opencode-mesh-v2/` → mesh: mesin ini terdaftar sebagai `kali-kernel`
  (presence = sumber IP live, karena IP DHCP berubah antara sekolah & rumah).

## Changelog

- **2026-10-21** — dibuat: 8 tool, guardrail deny/ask, context injection sistem,
  52/52 assertion lulus. Anti-false-positive: anchor posisi + buang isi heredoc.
