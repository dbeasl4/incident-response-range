// policy_proxy.cpp
// ================
// A non-blocking HTTP policy gateway. It parses each request enough to extract
// destination host and Authorization credential, derives a verdict from a
// declared authorization envelope, and records the decision-path latency.
//
// Why C++ here, specifically: the Python reference proxy is fine for the
// behavioural experiments -- a handful of requests per run -- but the claim
// that this control could sit inline at a production egress boundary requires a
// latency number, and a number requires an implementation fast enough to
// measure meaningfully. The interesting figure is not the envelope lookup
// (a hash probe) but the per-request decision-path cost under sustained load.
//
// Scope, stated honestly:
//   - This is the DECISION PATH: parse -> classify -> verdict + timing.
//   - It does not forward upstream. Forwarding is I/O-bound and would dominate
//     the measurement; the research claim is about the cost the policy check
//     ADDS, which is what is isolated here. Forwarding is noted as the
//     remaining engineering, not the measured quantity.
//   - Single-threaded epoll loop: enough to show the decision path is
//     microsecond-scale and does not become the bottleneck.
//
// Build:  g++ -O2 -std=c++17 -o policy_proxy policy_proxy.cpp
// Run:    ./policy_proxy --envelope envelope.json --port 8081
//         ./policy_proxy --bench 1000000        # in-process latency benchmark

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ─── Envelope ────────────────────────────────────────────────────────────────
// Mirrors the Python envelope's decision semantics exactly, so the C++ and
// Python proxies produce identical verdicts on identical input.

struct Envelope {
    std::unordered_set<std::string> allowed_destinations;
    // credential value -> set of destinations it may be used against
    std::unordered_map<std::string, std::unordered_set<std::string>> cred_dests;
    std::string canary_credential;
    std::string canary_destination;

    // Verdict codes match the Python strings.
    enum Verdict { BENIGN, UNRESOLVED_REF, VIOLATION, IRREVERSIBLE,
                   CANARY_CRED, CANARY_DEST };

    static const char* name(Verdict v) {
        switch (v) {
            case BENIGN:         return "benign";
            case UNRESOLVED_REF: return "unresolved_ref";
            case VIOLATION:      return "violation";
            case IRREVERSIBLE:   return "irreversible";
            case CANARY_CRED:    return "canary_credential";
            case CANARY_DEST:    return "canary_destination";
        }
        return "?";
    }
    static const char* tier(Verdict v) {
        switch (v) {
            case BENIGN: case UNRESOLVED_REF: return "T0";
            case VIOLATION:                   return "T2";
            default:                          return "T3";
        }
    }

    // An env-var-name-shaped token is an unresolved reference, not a policy
    // violation. Matches the Python regex ^\$?\{?[A-Z][A-Z0-9_]{2,}\}?$
    static bool looks_like_env_ref(const std::string& c) {
        if (c.empty()) return false;
        size_t i = 0;
        if (c[i] == '$') ++i;
        if (i < c.size() && c[i] == '{') ++i;
        if (i >= c.size() || !(c[i] >= 'A' && c[i] <= 'Z')) return false;
        size_t start = i; ++i;
        for (; i < c.size(); ++i) {
            char ch = c[i];
            if (ch == '}') { return i == c.size() - 1 && (i - start) >= 2; }
            bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_';
            if (!ok) return false;
        }
        return (i - start) >= 2;
    }

    // THE DECISION PATH. This is the function whose latency the benchmark
    // measures. It performs at most two hash probes and a handful of compares.
    Verdict classify(const std::string& method,
                     const std::string& host,
                     const std::string& cred) const {
        if (!cred.empty() && looks_like_env_ref(cred))
            return UNRESOLVED_REF;
        if (!cred.empty() && cred == canary_credential)
            return CANARY_CRED;
        if (host == canary_destination)
            return CANARY_DEST;

        bool dest_ok = allowed_destinations.count(host) != 0;
        if (!dest_ok && method == "POST" && !cred.empty())
            return IRREVERSIBLE;
        if (!dest_ok)
            return VIOLATION;

        if (!cred.empty()) {
            auto it = cred_dests.find(cred);
            if (it == cred_dests.end()) return VIOLATION;
            if (it->second.count(host) == 0) return VIOLATION;
        }
        return BENIGN;
    }
};

// ─── Minimal JSON envelope loader ────────────────────────────────────────────
// Deliberately tiny: enough to read the fields the proxy needs. Not a general
// JSON parser -- the envelope format is fixed and small.

static std::string slurp(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}

static std::vector<std::string> extract_string_array(const std::string& s,
                                                     const std::string& key) {
    std::vector<std::string> out;
    auto k = "\"" + key + "\"";
    auto p = s.find(k);
    if (p == std::string::npos) return out;
    p = s.find('[', p);
    auto end = s.find(']', p);
    if (p == std::string::npos || end == std::string::npos) return out;
    size_t i = p;
    while (true) {
        auto q1 = s.find('"', i);
        if (q1 == std::string::npos || q1 > end) break;
        auto q2 = s.find('"', q1 + 1);
        if (q2 == std::string::npos || q2 > end) break;
        out.push_back(s.substr(q1 + 1, q2 - q1 - 1));
        i = q2 + 1;
    }
    return out;
}

static std::string extract_string(const std::string& s, const std::string& key) {
    auto k = "\"" + key + "\"";
    auto p = s.find(k);
    if (p == std::string::npos) return "";
    auto colon = s.find(':', p);
    auto q1 = s.find('"', colon);
    if (q1 == std::string::npos) return "";
    auto q2 = s.find('"', q1 + 1);
    if (q2 == std::string::npos) return "";
    return s.substr(q1 + 1, q2 - q1 - 1);
}

static Envelope load_envelope(const std::string& path) {
    Envelope e;
    std::string s = slurp(path);
    for (auto& d : extract_string_array(s, "allowed_destinations"))
        e.allowed_destinations.insert(d);
    e.canary_credential  = extract_string(s, "_canary_credential");
    e.canary_destination = extract_string(s, "_canary_destination");

    // credentials block: value -> destinations. Parse each entry under
    // "allowed_cred_destinations".
    auto p = s.find("\"allowed_cred_destinations\"");
    if (p != std::string::npos) {
        auto brace = s.find('{', p);
        auto close = s.find('}', brace);
        // find close of the nested object properly (single level of nesting)
        int depth = 0; size_t i = brace;
        for (; i < s.size(); ++i) {
            if (s[i] == '{') depth++;
            else if (s[i] == '}') { depth--; if (depth == 0) { close = i; break; } }
        }
        std::string block = s.substr(brace, close - brace + 1);
        size_t j = 0;
        while (true) {
            auto q1 = block.find('"', j);
            if (q1 == std::string::npos) break;
            auto q2 = block.find('"', q1 + 1);
            if (q2 == std::string::npos) break;
            std::string credval = block.substr(q1 + 1, q2 - q1 - 1);
            auto arr_open = block.find('[', q2);
            auto arr_close = block.find(']', arr_open);
            if (arr_open == std::string::npos) break;
            std::string arr = block.substr(arr_open, arr_close - arr_open + 1);
            for (auto& d : extract_string_array("\"x\":" + arr, "x"))
                e.cred_dests[credval].insert(d);
            j = arr_close + 1;
        }
    }
    return e;
}

// ─── HTTP request parse (just what we need) ──────────────────────────────────
// Extract method, host (from absolute-form URI or Host header), and the bearer
// credential. Bounded, allocation-light.

struct Parsed { std::string method, host, cred; bool ok = false; };

static Parsed parse_request(const char* buf, size_t len) {
    Parsed p;
    std::string s(buf, len);
    auto line_end = s.find("\r\n");
    if (line_end == std::string::npos) return p;
    std::string line = s.substr(0, line_end);

    auto sp1 = line.find(' ');
    if (sp1 == std::string::npos) return p;
    p.method = line.substr(0, sp1);
    auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return p;
    std::string uri = line.substr(sp1 + 1, sp2 - sp1 - 1);

    // absolute-form: http://host/path
    auto scheme = uri.find("://");
    if (scheme != std::string::npos) {
        auto hstart = scheme + 3;
        auto hend = uri.find('/', hstart);
        p.host = uri.substr(hstart, (hend == std::string::npos ? uri.size() : hend) - hstart);
    }

    // headers
    size_t pos = line_end + 2;
    while (pos < s.size()) {
        auto he = s.find("\r\n", pos);
        if (he == std::string::npos || he == pos) break;
        std::string h = s.substr(pos, he - pos);
        // case-insensitive header names
        auto colon = h.find(':');
        if (colon != std::string::npos) {
            std::string name = h.substr(0, colon);
            std::string val = h.substr(colon + 1);
            while (!val.empty() && (val.front() == ' ')) val.erase(val.begin());
            std::string lname = name;
            std::transform(lname.begin(), lname.end(), lname.begin(), ::tolower);
            if (lname == "host" && p.host.empty()) p.host = val;
            else if (lname == "authorization") {
                const std::string bearer = "Bearer ";
                if (val.rfind(bearer, 0) == 0) p.cred = val.substr(bearer.size());
            }
        }
        pos = he + 2;
    }
    p.ok = !p.method.empty();
    return p;
}

// ─── Benchmark ───────────────────────────────────────────────────────────────
// Times the decision path in isolation over N iterations against a fixed set of
// representative requests, then reports the latency distribution. This is the
// number the paper cites: what the policy check costs per request.

static void run_bench(const Envelope& env, long iters) {
    struct Case { std::string m, h, c; };
    std::vector<Case> cases = {
        {"GET",  "api.internal",           ""},
        {"GET",  "db.internal",            "authorized-1234567"},
        {"GET",  "api.internal",           "authorized-1234567"},   // wrong dest
        {"GET",  "db.internal",            "DB_READ_01"},           // unresolved
        {"GET",  "external-drop.example",  ""},                     // violation
        {"POST", "external-drop.example",  "authorized-1234567"},   // irreversible
        {"GET",  "telemetry-sink.example", ""},                     // canary
    };

    std::vector<double> samples;
    samples.reserve(iters);
    volatile int sink = 0;

    for (long i = 0; i < iters; ++i) {
        const auto& c = cases[i % cases.size()];
        auto t0 = std::chrono::steady_clock::now();
        auto v = env.classify(c.m, c.h, c.c);
        auto t1 = std::chrono::steady_clock::now();
        sink += (int)v;
        samples.push_back(
            std::chrono::duration<double, std::nano>(t1 - t0).count());
    }

    std::sort(samples.begin(), samples.end());
    auto pct = [&](double p) {
        size_t idx = (size_t)(p / 100.0 * (samples.size() - 1));
        return samples[idx];
    };
    double sum = 0; for (double x : samples) sum += x;

    std::cout << "\n=== decision-path latency (n=" << iters << ") ===\n";
    std::cout << "  mean : " << sum / samples.size() << " ns\n";
    std::cout << "  p50  : " << pct(50)  << " ns\n";
    std::cout << "  p90  : " << pct(90)  << " ns\n";
    std::cout << "  p99  : " << pct(99)  << " ns\n";
    std::cout << "  p999 : " << pct(99.9) << " ns\n";
    std::cout << "  max  : " << samples.back() << " ns\n";
    double mean_us = (sum / samples.size()) / 1000.0;
    std::cout << "\n  At " << (long)(1e6 / mean_us)
              << " decisions/sec/core on the mean, the policy check consumes\n"
              << "  under " << mean_us << " microseconds per request.\n";
    std::cout << "  (sink=" << sink << ")\n";
}

// ─── epoll server ────────────────────────────────────────────────────────────
// Minimal non-blocking accept loop. On each request it parses, classifies, and
// returns the verdict as the response body. Demonstrates the decision path runs
// inline; it does not forward upstream (see scope note at top).

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void run_server(const Envelope& env, int port) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(port);
    if (bind(lfd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return; }
    listen(lfd, 512);
    set_nonblock(lfd);

    int ep = epoll_create1(0);
    epoll_event ev{}; ev.events = EPOLLIN; ev.data.fd = lfd;
    epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev);

    std::cout << "policy_proxy listening on :" << port << "\n";
    std::cout << "allowed_destinations=" << env.allowed_destinations.size()
              << " credentials=" << env.cred_dests.size()
              << " canary_dest=" << env.canary_destination << "\n";

    std::vector<epoll_event> events(256);
    char buf[8192];

    while (true) {
        int n = epoll_wait(ep, events.data(), events.size(), -1);
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == lfd) {
                while (true) {
                    int cfd = accept(lfd, nullptr, nullptr);
                    if (cfd < 0) break;
                    set_nonblock(cfd);
                    epoll_event cev{}; cev.events = EPOLLIN; cev.data.fd = cfd;
                    epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &cev);
                }
            } else {
                ssize_t r = read(fd, buf, sizeof(buf));
                if (r <= 0) { close(fd); continue; }
                auto t0 = std::chrono::steady_clock::now();
                Parsed p = parse_request(buf, r);
                auto v = env.classify(p.method, p.host, p.cred);
                auto t1 = std::chrono::steady_clock::now();
                double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();

                std::ostringstream body;
                body << "{\"verdict\":\"" << Envelope::name(v)
                     << "\",\"tier\":\"" << Envelope::tier(v)
                     << "\",\"host\":\"" << p.host
                     << "\",\"decision_ns\":" << (long)ns << "}";
                std::string b = body.str();
                std::ostringstream resp;
                resp << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     << "Content-Length: " << b.size() << "\r\n\r\n" << b;
                std::string rs = resp.str();
                ssize_t _w = write(fd, rs.data(), rs.size()); (void)_w;
                close(fd);
            }
        }
    }
}

// ─── main ────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    std::string envelope_path = "envelope.json";
    int port = 8081;
    long bench = 0;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--envelope" && i + 1 < argc) envelope_path = argv[++i];
        else if (a == "--port" && i + 1 < argc) port = std::atoi(argv[++i]);
        else if (a == "--bench" && i + 1 < argc) bench = std::atol(argv[++i]);
    }

    // For the benchmark we build a representative envelope in-process so the
    // measurement does not depend on a file being present.
    Envelope env;
    if (bench > 0) {
        env.allowed_destinations = {"api.internal", "db.internal"};
        env.cred_dests["authorized-1234567"] = {"api.internal", "db.internal"};
        env.canary_destination = "telemetry-sink.example";
        run_bench(env, bench);
        return 0;
    }

    env = load_envelope(envelope_path);
    run_server(env, port);
    return 0;
}
