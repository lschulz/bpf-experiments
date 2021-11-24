#include "util.hpp"

extern "C" {
#include <poll.h>
#include <stdio.h>
}

#include <iostream>


namespace Bpf {
namespace Util {

////////////////////////////
// InterruptSignalHandler //
////////////////////////////

InterruptSignalHandler::InterruptSignalHandler()
{
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
}

void InterruptSignalHandler::launchHandler()
{
    // Do not receive signals in sigset on this thread or any threads spawned by it.
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

    // Start a new thread waiting for a signal to terminate (e.g, Ctrl+C).
    auto handler = [this]() {
        int signum = 0;
        sigwait(&sigset, &signum);

        terminate = true;
        cv.notify_all();

        return signum;
    };
    handlerThread = std::thread(handler);
}

void InterruptSignalHandler::joinHandler()
{
    kill(handlerThread.native_handle(), SIGTERM);
    handlerThread.join();
}

bool InterruptSignalHandler::wait(std::chrono::high_resolution_clock::duration timeout) const
{
    std::unique_lock lock(mutex);
    cv.wait_for(lock, timeout, [this] {
        return terminate == true;
    });
    return terminate;
}

////////////////
// tracePrint //
////////////////

void tracePrint(const InterruptSignalHandler &cond)
{
    static const char* TRACEFS_PIPE = "/sys/kernel/debug/tracing/trace_pipe";
    char *line = NULL;
    std::size_t lineLen = 0;

    FILE* stream = fopen(TRACEFS_PIPE, "r");
    if (!stream) return;

    struct pollfd fds = {
        .fd = fileno(stream),
        .events = POLLIN,
    };

    try {
        while (!cond.wait(std::chrono::milliseconds(100)))
        {
            while (poll(&fds, 1, 0))
            {
                std::size_t readChars = getline(&line, &lineLen, stream);
                if (readChars < 0) return;
                std::cout << line;
            }
        }
    }
    catch (...) {
        free(line);
        fclose(stream);
        throw;
    }

    free(line);
    fclose(stream);
}

} // namespace Util
} // namespace Bpf
