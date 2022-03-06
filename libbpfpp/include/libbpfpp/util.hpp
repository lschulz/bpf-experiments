#pragma once

extern "C" {
#include <signal.h>
}

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>


namespace Bpf {
namespace Util {

/// \brief Helper for dealing with process termination signals.
class InterruptSignalHandler
{
public:
    InterruptSignalHandler();

    /// \brief Evaluates to true, if the process should terminate.
    operator bool() const { return terminate; }

    /// \brief Start a new thread waiting for SIGINT or SIGTERM. SIGINT and SIGTERM will be masked
    /// on the calling thread.
    /// \remark Call in main thread before other threads are spawned.
    void launchHandler();

    /// \brief Terminate and join with the handler thread.
    void joinHandler();

    /// \brief Wait for a request to terminate the program or until the timeout has elapsed.
    /// \return True if the program should terminate, false if the timeout has elapsed.
    bool wait(std::chrono::high_resolution_clock::duration timeout) const;

private:
    sigset_t sigset;
    std::atomic<bool> terminate = false;
    mutable std::mutex mutex;
    mutable std::condition_variable cv;
    std::thread handlerThread;
};

/// \brief Print lines from `/sys/kernel/debug/tracing/trace_pipe` until \p cond indicates the
/// program should terminate.
/// \return False on error, true on normal termination.
bool tracePrint(const InterruptSignalHandler &cond);

} // namespace Util
} // namespace Bpf
