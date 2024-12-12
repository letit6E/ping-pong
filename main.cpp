#include <sys/file.h>

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>

enum class State { Ready, Sleep };

static pid_t other_pid = 0;
static State my_state = State::Sleep;

struct SignalEvent {
    pid_t sender_pid;
};

std::queue<SignalEvent> event_queue;
std::mutex event_mutex;
std::condition_variable event_cv;

std::optional<pid_t> read_pid_from_file(const std::string& pidfile,
                                        size_t position) {
    std::ifstream ifs(pidfile);
    if (!ifs) {
        return std::nullopt;
    }

    pid_t pid;
    while (position--) {
        ifs >> pid;

        if (ifs.fail()) {
            return std::nullopt;
        }
    }

    return pid;
}

bool write_pid_to_file(const std::string& pidfile, pid_t my_pid,
                       std::optional<pid_t> other_pid = std::nullopt) {
    std::ofstream ofs(pidfile);
    if (!ofs) {
        return false;
    }
    ofs << my_pid << "\n";
    if (other_pid) {
        ofs << *other_pid << "\n";
    }
    return true;
}

void wait_for_pid(const std::string& pidfile, pid_t my_pid) {
    int fd = open(pidfile.c_str(), O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error("Failed to open pidfile for reading");
    }

    while (true) {
        if (flock(fd, LOCK_SH) == 0) {
            auto result = read_pid_from_file(pidfile, 2);
            if (result && *result != my_pid) {
                other_pid = *result;
                flock(fd, LOCK_UN);
                close(fd);
                break;
            }
            flock(fd, LOCK_UN);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void setup_signal_handler(void (*handler)(int, siginfo_t*, void*)) {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, nullptr) == -1) {
        throw std::runtime_error(std::strerror(errno));
    }
}

void send_signal(pid_t pid) {
    if (kill(pid, SIGUSR1) == -1) {
        throw std::runtime_error(std::strerror(errno));
    }
}

void signal_handler(int signo, siginfo_t* info, void* context) {
    pid_t sender_pid = info->si_pid;

    {
        std::lock_guard<std::mutex> lock(event_mutex);
        event_queue.push({sender_pid});
    }
    event_cv.notify_one();
}

void process_event() {
    while (true) {
        SignalEvent event;
        {
            std::unique_lock<std::mutex> lock(event_mutex);
            event_cv.wait(lock, [] { return !event_queue.empty(); });
            event = event_queue.front();
            event_queue.pop();
        }

        if (my_state == State::Sleep) {
            std::cout << "Process № " << getpid() << ": signal received from "
                      << event.sender_pid << std::endl;
            my_state = State::Ready;
            std::cout << "Process № " << getpid() << ": sending signal back"
                      << std::endl;
            send_signal(other_pid);
            my_state = State::Sleep;
        } else {
            std::cout << "Process № " << getpid()
                      << ": received signal in Ready state (unexpected)"
                      << std::endl;
        }
    }
}

void process_a_logic(const std::string& pidfile, pid_t my_pid) {
    if (!write_pid_to_file(pidfile, my_pid)) {
        throw std::runtime_error("Failed to write PID to file");
    }
    wait_for_pid(pidfile, my_pid);
}

void process_b_logic(const std::string& pidfile, pid_t my_pid,
                     pid_t other_pid) {
    auto a_pid = read_pid_from_file(pidfile, 1);
    if (!a_pid || *a_pid != other_pid) {
        throw std::runtime_error("Failed to verify A's PID in pidfile");
    }
    if (!write_pid_to_file(pidfile, other_pid, my_pid)) {
        throw std::runtime_error("Failed to write PIDs to file");
    }
}

int main(int argc, char* argv[]) {
    pid_t my_pid = getpid();
    bool is_process_a = (argc == 1);

    const std::string pidfile = "agent.txt";

    try {
        setup_signal_handler(signal_handler);

        if (is_process_a) {
            std::cout << "Process № " << my_pid << ": I am A." << std::endl;
            process_a_logic(pidfile, my_pid);
            std::cout << "Process № " << my_pid
                      << ": B process id = " << other_pid << std::endl;
            std::cout << "Process № " << my_pid
                      << ": Sending initial signal to B" << std::endl;
            send_signal(other_pid);
        } else {
            if (argc < 2) {
                std::cerr << "Usage: " << argv[0] << " <A process id>"
                          << std::endl;
                return 1;
            }
            pid_t a_pid = std::atoi(argv[1]);
            other_pid = a_pid;
            std::cout << "Process № " << my_pid << ": I am B." << std::endl;
            process_b_logic(pidfile, my_pid, other_pid);
            std::cout << "Process № " << my_pid
                      << ": A process id = " << other_pid << std::endl;
        }

        std::thread event_thread(process_event);

        while (true) {
            pause();
        }

        event_thread.join();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

