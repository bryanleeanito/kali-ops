// kali-ops.js — plugin OpenCode V2: "co-pilot sistem" untuk mesin Kali.
//
// Tujuan: AI Agent bekerja sama dengan sistem Kali Linux — TAHU state sistem
// (bukan menebak), bisa memeriksa tool, jaringan, service, firewall, package,
// dan bisa melakukan perubahan dengan permission gate (bukan brutal).
//
// Prinsip: READ-ONLY by default. Semua operasi tulis WAJIB lewat permission
// engine (ctx.permission.assert) → user ditanya. Tidak ada yang menyentuh
// /boot, /etc/passwd, disk mentah, atau firewall tanpa persetujuan eksplisit.
//
//namespace tools: kali

import { execFile } from "node:child_process"
import { promisify } from "node:util"
import fs from "node:fs"
import os from "node:os"

const exec = promisify(execFile)

async function sh(cmd, args = [], timeout = 20_000) {
  try {
    const { stdout, stderr } = await exec(cmd, args, {
      timeout,
      maxBuffer: 8 * 1024 * 1024,
    })
    return { ok: true, out: (stdout || "").trim(), err: (stderr || "").trim() }
  } catch (e) {
    return {
      ok: false,
      out: (e?.stdout || "").trim(),
      err: (e?.stderr || String(e?.message || e)).trim(),
    }
  }
}

function firstLine(s) {
  return String(s || "").split("\n")[0].trim()
}

// ---------------------------------------------------------------------------
// TOOLS
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: "sys_status",
    description:
      "Snapshot sistem Kali: distro, kernel, uptime, CPU, RAM, disk (termasuk /boot), load, service gagal, update APT menunggu, update keamanan. Baca-saja.",
    input: { type: "object", properties: {}, additionalProperties: false },
    execute: async () => {
      const lines = []
      const rel = await sh("cat", ["/etc/os-release"])
      lines.push("distro     : " + firstLine((rel.out || "").replace("PRETTY_NAME=", "").replace(/"/g, "")))
      lines.push("kernel     : " + os.release() + " (" + os.arch() + ")")
      const up = await sh("uptime", ["-p"])
      lines.push("uptime     : " + (up.out || "-"))
      const cpu = await sh("lscpu")
      const model = (cpu.out || "").split("\n").find((l) => l.includes("Model name"))
      lines.push("cpu        : " + (model ? model.split(":").slice(1).join(":").trim() : "?") + " / " + os.cpus().length + " logical")
      const mem = await sh("free", ["-h"])
      const memLine = (mem.out || "").split("\n").find((l) => l.startsWith("Mem:"))
      lines.push("ram        : " + (memLine ? memLine.trim().split(/\s+/).slice(1, 3).join(" ") : "?"))
      const df = await sh("df", ["-h", "/", "/boot"])
      for (const l of (df.out || "").split("\n").slice(1)) lines.push("disk       : " + l.trim())
      const fail = await sh("systemctl", ["--failed", "--no-legend", "--no-pager"])
      lines.push("svc gagal  : " + (fail.out ? fail.out.split("\n").length + " unit" : "0 unit"))
      // `apt list --upgradable` = read-only, tidak butuh lock dpkg (apt-get -s bisa gagalkalau lock dipakai)
      const apt = await sh("bash", ["-lc", "apt list --upgradable 2>/dev/null | tail -n +2 | sed 's|/.*||' | head -12"], 45_000)
      const nUpg = apt.out ? apt.out.split("\n").filter((l) => l.trim()).length : 0
      lines.push("apt update : " + (apt.out ? nUpg + " paket bisa di-upgrade" + (apt.err ? " (" + apt.err.slice(0, 60) + ")" : "") : "tidak bisa dicek (" + (apt.err || "").slice(0, 60) + ")"))
      if (nUpg) lines.push("  contoh   : " + apt.out.split("\n").filter((l) => l.trim()).slice(0, 4).join(", "))
      const lastupd = await sh("bash", ["-lc", "ls -1t /var/lib/apt/periodic/ 2>/dev/null | head -3 | tr '\\n' ' '"])
      lines.push("apt cache  : " + (lastupd.out || "-"))
      lines.push("proxy env  : " + (process.env.http_proxy || process.env.HTTP_PROXY || "(tidak ada)"))
      return { content: lines.join("\n") }
    },
  },
  {
    name: "tool_check",
    description:
      "Cek apakah sebuah tool/CLI terpasang di Kali: path, versi, dan paket apt yang menyediakannya (plus saran apt kalau belum ada).",
    input: {
      type: "object",
      properties: {
        tool: { type: "string", description: "nama tool, mis. nmap / hashcat / tshark" },
        suggest: { type: "boolean", description: "cari kandidat paket apt (default true)" },
      },
      required: ["tool"],
      additionalProperties: false,
    },
    execute: async (input) => {
      const t = String(input?.tool || "").trim()
      if (!t) return { content: "wajib isi 'tool'" }
      const which = await sh("bash", ["-lc", `command -v ${JSON.stringify(t)} 2>/dev/null`])
      const out = []
      if (which.out) {
        out.push(`PATH       : ${which.out}`)
        const v = await sh("bash", ["-lc", `(${JSON.stringify(t)} --version 2>/dev/null || ${JSON.stringify(t)} -V 2>/dev/null || ${JSON.stringify(t)} version 2>/dev/null) | head -1`])
        out.push(`versi      : ${v.out || "(tidak ada output --version)"}`)
        const prov = await sh("dpkg", ["-S", which.out])
        if (prov.out) out.push(`paket      : ${prov.out.split(":")[0]}`)
      } else {
        out.push(`PATH       : TIDAK ADA (${t} belum terpasang)`)
        if (input?.suggest !== false) {
          const s = await sh("apt-cache", ["search", t], 25_000)
          const hits = (s.out || "")
            .split("\n")
            .filter((l) => l.trim())
            .slice(0, 8)
          if (hits.length) {
            out.push("kandidat paket apt:")
            hits.forEach((h) => out.push("  - " + h.trim()))
          } else {
            out.push("kandidat paket apt: tidak ada di index (coba: apt update)")
          }
        }
      }
      return { content: out.join("\n") }
    },
  },
  {
    name: "net_status",
    description:
      "Status jaringan Kali: interface + IP, route, DNS, listening port + proses owning, proxy/Tor, dan hasil tes konektivitas singkat.",
    input: {
      type: "object",
      properties: {
        test: { type: "string", description: "URL untuk tes konektivitas (default: contoh.com)" },
        deep: { type: "boolean", description: "test konektivitas (default true)" },
      },
      additionalProperties: false,
    },
    execute: async (input) => {
      const out = []
      const ip = await sh("ip", ["-br", "addr"])
      out.push("INTERFACE:\n" + (ip.out || "-"))
      const route = await sh("ip", ["route"])
      out.push("ROUTE:\n" + (route.out || "-"))
      const dns = await sh("bash", ["-lc", "cat /etc/resolv.conf 2>/dev/null | grep -v '^#' | head -5"])
      out.push("DNS:\n" + (dns.out || "-"))
      const ss = await sh("ss", ["-tulpn"])
      out.push("LISTENING:\n" + (ss.out || "-").split("\n").slice(0, 40).join("\n"))
      const tor = await sh("bash", ["-lc", "ss -tlnp 2>/dev/null | grep -E ':(9050|9051|1080|8118)\\b' || true"])
      out.push("TOR/PROXY:\n" + (tor.out || "(tidak ada listener Tor detected)"))
      if (input?.deep !== false) {
        const url = String(input?.test || "https://example.com")
        const t0 = Date.now()
        const c = await sh("curl", ["-sS", "-o", "/dev/null", "-w", "%{http_code} %{time_total}s", "--max-time", "8", url], 15_000)
        out.push(`TES KONEKTIVITAS ${url} : ${c.out || c.err} (${Date.now() - t0} ms)`)
      }
      return { content: out.join("\n\n") }
    },
  },
  {
    name: "svc_status",
    description:
      "Status systemd service: unit yang diminta (aktif, enable, log tail) + daftar unit yang gagal. Untuk cek ssh/network/display-manager/suricata.",
    input: {
      type: "object",
      properties: {
        unit: { type: "string", description: "nama unit systemd, mis. ssh, tor, NetworkManager" },
        failed: { type: "boolean", description: "tampilkan unit yang gagal (default true)" },
      },
      additionalProperties: false,
    },
    execute: async (input) => {
      const out = []
      const unit = String(input?.unit || "").trim()
      if (unit) {
        const st = await sh("systemctl", ["status", unit, "--no-pager", "-n", "15"])
        out.push("=== " + unit + " ===\n" + (st.out || st.err))
        const en = await sh("systemctl", ["is-enabled", unit])
        const ac = await sh("systemctl", ["is-active", unit])
        out.push(`state: active=${ac.out || "?"} enabled=${en.out || "?"}`)
      }
      if (input?.failed !== false) {
        const f = await sh("systemctl", ["--failed", "--no-legend", "--no-pager"])
        out.push("=== unit gagal ===\n" + (f.out || "(tidak ada)"))
      }
      return { content: out.join("\n\n") }
    },
  },
  {
    name: "fw_status",
    description:
      "Status firewall & jaringan: ufw, nftables, iptables, plus rule aktif. Membaca rule (tidak mengubah).",
    input: { type: "object", properties: {}, additionalProperties: false },
    execute: async () => {
      const out = []
      const ufw = await sh("bash", ["-lc", "ufw status verbose 2>/dev/null || echo '(ufw tidak terpasang)'"])
      out.push("UFW:\n" + ufw.out)
      const nft = await sh("bash", ["-lc", "nft list ruleset 2>/dev/null | head -40 || echo '(nft tidak terpasang / tanpa rule)'"])
      out.push("NFTABLES:\n" + nft.out)
      const ipt = await sh("bash", ["-lc", "iptables -S 2>/dev/null | head -30 || echo '(iptables tidak aktif/tidak ada)'"])
      out.push("IPTABLES:\n" + ipt.out)
      return { content: out.join("\n\n") }
    },
  },
  {
    name: "disk_usage",
    description:
      "Peta pemakaian disk: folder terbesar di path yang diminta (default /root), plusinode & quota partisi. Berguna sebelum install/besar.",
    input: {
      type: "object",
      properties: {
        path: { type: "string", description: "path yang dipindai (default /root)" },
        depth: { type: "number", description: "kedalaman du (default 1)" },
        limit: { type: "number", description: "jumlah baris (default 15)" },
      },
      additionalProperties: false,
    },
    execute: async (input) => {
      const p = String(input?.path || "/root")
      const depth = Number(input?.depth || 1)
      const limit = Number(input?.limit || 15)
      const du = await sh("du", ["-h", "--max-depth", String(depth), p], 60_000)
      const rows = (du.out || "")
        .split("\n")
        .filter((l) => l.trim())
        .sort((a, b) => {
          const pa = parseFloat(a.split(/\s+/)[0]) || 0
          const pb = parseFloat(b.split(/\s+/)[0]) || 0
          return pb - pa
        })
        .slice(0, limit)
      const df = await sh("df", ["-h"])
      const ino = await sh("df", ["-i"])
      return {
        content:
          "TOP " + limit + " di " + p + ":\n" +
          (rows.join("\n") || du.err || "-") +
          "\n\nPARTISI:\n" + (df.out || "-") +
          "\n\nINODE:\n" + (ino.out || "-"),
      }
    },
  },
  {
    name: "pkg_info",
    description:
      "Info paket apt: status terpasang, versi kandidat, ukuran, dependensi, dan apakah ada update keamanan.",
    input: {
      type: "object",
      properties: { pkg: { type: "string", description: "nama paket" } },
      required: ["pkg"],
      additionalProperties: false,
    },
    execute: async (input) => {
      const p = String(input?.pkg || "").trim()
      if (!p) return { content: "wajib isi 'pkg'" }
      const pol = await sh("apt-cache", ["policy", p], 25_000)
      const show = await sh("apt-cache", ["show", p], 25_000)
      const out = [pol.out || "-"]
      const size = (show.out || "").match(/^Size: (.+)$/m)
      const inst = (show.out || "").match(/^Installed-Size: (.+)$/m)
      if (size) out.push("ukuran unduhan : " + size[1])
      if (inst) out.push("ukuran terpasang : " + inst[1] + " KB")
      const deps = (show.out || "").match(/^Depends: (.+)$/m)
      if (deps) out.push("dependensi : " + deps[1].slice(0, 300))
      const sec = (show.out || "").match(/^Description-en: (.+)$/m)
      if (sec) out.push("deskripsi : " + sec[1].slice(0, 200))
      return { content: out.join("\n") }
    },
  },
  {
    name: "pkg_change",
    description:
      "Ubah paket apt (install/remove) — selalu DRY-RUN dulu, jalankan hanya atas persetujuan user. Output = rencana perubahan persis.",
    input: {
      type: "object",
      properties: {
        action: { type: "string", description: "install | remove | update | purge" },
        packages: { type: "array", items: { type: "string" } },
        execute: { type: "boolean", description: "true = eksekusi (butuh persetujuan user)" },
      },
      required: ["action", "packages"],
      additionalProperties: false,
    },
    execute: async (input, ctx) => {
      const action = String(input?.action || "").toLowerCase()
      const pkgs = (input?.packages || []).map(String).filter(Boolean)
      if (!["install", "remove", "update", "purge"].includes(action)) {
        return { content: "action tidak valid: install | remove | update | purge" }
      }
      if (!pkgs.length) return { content: "wajib isi 'packages'" }
      const args =
        action === "update" ? ["-s", "-o", "Debug::NoLocking=1", "upgrade"] : ["-s", "-o", "Debug::NoLocking=1", action, ...pkgs]
      const sim = await sh("apt-get", args, 60_000)
      const plan = (sim.out || "").split("\n").filter((l) => /^(Inst|Remv|Conf|E:|W:)/.test(l.trim()))
      const head =
        action === "update"
          ? "apt-get -s upgrade"
          : "apt-get -s " + action + " " + pkgs.join(" ")
      let out = ["RENCANA (dry-run): " + head, ...(plan.length ? plan : ["(tidak ada perubahan)"])]
      out.push("")
      out.push("Perkiraan: " + (plan.filter((l) => l.startsWith("Inst")).length) + " install, " + (plan.filter((l) => l.startsWith("Remv")).length) + " remove")
      if (input?.execute) {
        if (ctx?.permission && ctx.sessionID) {
          await ctx.permission.assert({
            sessionID: ctx.sessionID,
            agent: ctx.agent,
            source: { type: "tool", id: "kali_pkg_change" },
            action: "shell",
            resources: ["apt-get " + (action === "update" ? "upgrade" : action + " " + pkgs.join(" "))],
            save: ["apt-get " + action + " *"],
            metadata: { note: "ubah paket apt di sistem Kali" },
          })
        }
        const real = await sh("apt-get", ["-y", ...(action === "update" ? ["upgrade"] : [action, ...pkgs])], 600_000)
        out.push("")
        out.push("=== EKSEKUSI ===")
        out.push(real.out || real.err || "(selesai, output kosong)")
      } else {
        out.push("")
        out.push("[dry-run] tidak ada yang diubah. Panggil lagi dengan execute=true untuk eksekusi (user akan ditanya).")
      }
      return { content: out.join("\n") }
    },
  },
]

// ---------------------------------------------------------------------------
// GUARDRAIL sistem (generalisasi guardrail kernel)
// ---------------------------------------------------------------------------

const DENY = [
  { re: /\brm\s+(-[a-zA-Z]+\s+)*(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*)\s+\/(\s|$)/, why: "menghapus seluruh root filesystem" },
  { re: /\brm\s+-rf\s+\/(etc|boot|usr|bin|sbin|lib|var|home)\b/, why: "menghapus direktori sistem" },
  { re: /\brm\s+-rf\s+~\/?\s*$/, why: "menghapus home root" },
  { re: /\bmkfs(\.[a-z0-9]+)?\b/i, why: "memformat filesystem" },
  { re: /\bwipefs\b/i, why: "menghapus signature disk" },
  { re: /\bsgdisk\s+.*--zap-all/i, why: "menghapus seluruh partisi" },
  { re: /\bdd\b[^|;]*\bof=\/dev\/(?!null\b|zero\b|random\b|urandom\b|tty\b|shm\b|fd\b|stdin\b|stdout\b|stderr\b|full\b|ptmx\b|pts\/)[a-z]/i, why: "menulis langsung ke device disk", global: true },
  { re: />\s*\/dev\/(sd|nvme|vd)[a-z]/i, why: "redirect output ke device disk", global: true },
  { re: /\b(ufw|firewall-cmd)\s+(disable|reset)\b/i, why: "mematikan firewall" },
  { re: /\biptables\s+-F\b/, why: "menghapus semua rule iptables" },
  { re: /\bnft\s+flush\s+ruleset\b/i, why: "menghapus semua rule nftables" },
  { re: /\bchmod\s+-R\s+(777|a\+rwx)\s+\/(\s|$)/, why: "membuka permissions seluruh root" },
  { re: /\bchown\s+-R\s+\S+\s+\/(\s|$)/, why: "mengubah ownership seluruh root" },
  { re: /\buserdel\b|\buseradd\b|\bpasswd\s+\S+/, why: "mengubah user/akun sistem" },
  { re: />\s*\/etc\/passwd|\bsed\s+-i.*\/etc\/(passwd|shadow)\b/, why: "mengedit /etc/passwd|/etc/shadow" },
  { re: /\bhistory\s+-c\b/, why: "menghapus riwayat shell" },
  { re: /\bshred\b/, why: "menghapus data secara destruktif" },
]

const ASK = [
  { re: /\bapt(-get)?\s+(install|remove|purge|autoremove|upgrade|full-upgrade)\b/, why: "mengubah paket sistem" },
  { re: /\bdpkg\s+(-i|-r|--purge)\b/, why: "mengubah paket via dpkg" },
  { re: /\bpip3?\s+install\b/, why: "pasang paket python" },
  { re: /\bnpm\s+(i|install)\b|\bpnpm\s+(i|install)\b/, why: "pasang paket node" },
  { re: /\bsystemctl\s+(stop|restart|disable|mask|kill)\b/, why: "menghentikan/mengubah service" },
  { re: /\bservice\s+\S+\s+(stop|restart)\b/, why: "menghentikan service" },
  { re: /\bkill(all)?\s+/, why: "mematikan proses" },
  { re: /\bsysctl\s+-w\b/, why: "mengubah parameter kernel runtime (bersifat global)" },
  { re: /\bswapoff\b|\bswapon\b/, why: "mengubah swap" },
  { re: /\bchmod\b|\bchown\b/, why: "mengubah permission/ownership" },
  { re: /\bcrontab\b/, why: "mengubah jadwal cron" },
  { re: /\b(tee|dd)\b.*\/etc\//, why: "menulis ke /etc" },
  { re: /\bgit\s+(push|reset\s+--hard|clean\s+-[a-z]*f)\b/, why: "operasi git yang destruktif" },
  { re: /\bcurl\b[^|;]*\|\s*(ba)?sh\b/, why: "menjalankan skrip dari internet" },
  { re: /\bsudo\b/, why: "menjalankan perintah dengan sudo" },
]

/**
 * Normalisasi sebelum dicocokkan:
 * 1) isi heredoc dibuang (dokumentasi yang menyebut "mkfs" bukan eksekusi).
 * 2) pola di-anchor ke POSISI perintah (awal baris / setelah ; & | / sudo),
 *    supaya `echo "rm -rf /"` tidak dianggap eksekusi rm.
 */
function normalizeCommand(command) {
  const lines = String(command || "").split("\n")
  const out = []
  let inHere = false
  let term = ""
  for (const ln of lines) {
    if (!inHere) {
      const m = ln.match(/<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/)
      out.push(ln)
      if (m) {
        inHere = true
        term = m[1]
      }
    } else if (ln.trim() === term) {
      inHere = false
      out.push(ln)
    }
  }
  return out.join("\n")
}

const POS = "(?:^|[\\n;&|]\\s*|\\bsudo\\s+)"
const atPos = (re) => new RegExp(POS + "(?:" + re.source + ")", re.flags.replace("g", ""))

function guardCheck(command) {
  const cmd = normalizeCommand(command)
  for (const d of DENY) {
    const re = d.global ? d.re : atPos(d.re)
    if (re.test(cmd)) return { effect: "deny", why: d.why }
  }
  for (const a of ASK) if (atPos(a.re).test(cmd)) return { effect: "ask", why: a.why }
  return null
}

// ---------------------------------------------------------------------------
// CONTEXT snapshot sistem (disuntikkan ke system prompt)
// ---------------------------------------------------------------------------

let cached = { at: 0, text: "" }

async function buildContext() {
  const now = Date.now()
  if (now - cached.at < 60_000 && cached.text) return cached.text
  const osr = await sh("cat", ["/etc/os-release"])
  const distro = firstLine((osr.out || "").replace("PRETTY_NAME=", "").replace(/"/g, ""))
  const df = await sh("df", ["-h", "/"])
  const rootLine = (df.out || "").split("\n")[1] || ""
  const rootFree = rootLine.trim().split(/\s+/)[3] || "?"
  const mem = await sh("free", ["-h"])
  const memLine = (mem.out || "").split("\n").find((l) => l.startsWith("Mem:")) || ""
  const memTotal = memLine.trim().split(/\s+/)[1] || "?"
  const tor = await sh("bash", ["-lc", "ss -tlnp 2>/dev/null | grep -cE ':(9050|9051)\\b' || true"])
  const up = await sh("uptime", ["-p"])
  const text = [
    "<kali-system-context>",
    `Mesin: ${distro} · kernel ${os.release()} · ${os.cpus().length} logical CPU · RAM ${memTotal} · root free ${rootFree}`,
    `Uptime: ${up.out || "-"} · Tor listener: ${tor.out || "0"} (9050=socks, 9051=http) · user: ${os.userInfo().username} (uid ${os.getuid()})`,
    "Aturan: baca dulu sebelum ubah (tool kali_*), verifikasi setelah ubah, satu perubahan per iterasi,",
    "password/flag via env var saja, JANGAN simpan kredensial di file/repo, D: (NTFS) read-only.",
    "</kali-system-context>",
  ].join("\n")
  cached = { at: now, text }
  return text
}

// ---------------------------------------------------------------------------
// PLUGIN
// ---------------------------------------------------------------------------

export default {
  id: "kali-ops",
  async setup(ctx) {
    await ctx.tool.transform((editor) => {
      editor.namespace({
        name: "kali",
        description:
          "Co-pilot sistem Kali: status mesin, cek tool, jaringan, service, firewall, disk, paket apt, dan perubahan paket (dengan persetujuan). Gunakan tool ini untuk bekerja dengan sistem Kali — bukan menebak.",
      })
      for (const t of TOOLS) {
        editor.add({
          name: t.name,
          description: t.description,
          input: t.input,
          options: { namespace: "kali", codemode: true },
          execute: async (input, toolCtx) => {
            try {
              const out = await t.execute(input || {}, toolCtx || {})
              const content = typeof out === "string" ? out : out?.content
              return { content: String(content ?? "") }
            } catch (e) {
              return { content: "ERROR " + t.name + ": " + String(e?.message || e) }
            }
          },
        })
      }
    })

    // guardrail sistem
    await ctx.permission.hook("evaluate", async (event) => {
      if (event.action !== "shell") return
      for (const r of event.resources || []) {
        const hit = guardCheck(r)
        if (!hit) continue
        if (hit.effect === "deny") {
          event.effect = "deny"
          event.message =
            "DITOLAK guardrail kali-ops: " + hit.why +
            '. Perintah: "' + String(r).slice(0, 160) + '". Sistem Kali + dual-boot Windows harus utuh.'
        } else {
          event.effect = "ask"
          event.message = "Guardrail kali-ops: " + hit.why + " — pastikan user menyetujui dulu (dan backlash dicek)."
        }
        return
      }
    })

    // context sistem
    await ctx.session.hook("context", async (event) => {
      try {
        const text = await buildContext()
        if (text) event.system.push({ type: "text", text })
      } catch {}
    })
  },
}

// diekspor untuk unit test
export const __guard = { check: guardCheck, DENY, ASK }
