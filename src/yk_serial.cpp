#include <array>
#include <cstddef>
#include <format>
#include <iostream>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <ykpiv/ykpiv.h>

static constexpr unsigned long kCustomDataTag = 0x5FC106;

// default 24-byte management key (Yubico default).
static const std::array<unsigned char, 24> kDefaultMgmtKey = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08  //
};

enum class Mode {
    Write,      // -w <content>
    ReadObj,    // -r
    ReadSerial, // -s
    All,        // -a
    Unknown
};

static void printUsage(const char* progName) {
    std::println("Usage:");
    std::println("  {} -w <content>   # Write <content> to custom object 0x5FC106", progName);
    std::println("  {} -r             # Read only the custom object", progName);
    std::println("  {} -s             # Read only the YubiKey serial", progName);
    std::println("  {} -a             # Print all info (serial, version, custom object)", progName);
    std::println();
    std::println("Examples:");
    std::println("  {} -w \"Hello World!\"", progName);
    std::println("  {} -r", progName);
    std::println("  {} -s", progName);
    std::println("  {} -a", progName);
}

bool authenticate(ykpiv_state* state, std::span<const unsigned char> mgmtKey) {
    auto rc = ykpiv_authenticate(state, mgmtKey.data());
    if (rc != YKPIV_OK) {
        std::println(stderr, "error: ykpiv_authenticate: {} - {}", ykpiv_strerror_name(rc), ykpiv_strerror(rc));
        return false;
    }
    return true;
}

std::string readCustomObject(ykpiv_state* state) {
    std::vector<unsigned char> buffer(2048, 0);
    unsigned long              len = buffer.size();

    if (const auto rc = ykpiv_fetch_object(state, kCustomDataTag, buffer.data(), &len); rc == YKPIV_OK && len > 0) {
        return {reinterpret_cast<const char*>(buffer.data()), len};
    }
    return {};
}

bool writeCustomObject(ykpiv_state* state, std::string_view text) {
    std::vector<unsigned char> data(text.begin(), text.end());
    if (const auto rc = ykpiv_save_object(state, kCustomDataTag, data.data(), data.size()); rc != YKPIV_OK) {
        std::println(stderr, "Error: ykpiv_save_object: {} - {}", ykpiv_strerror_name(rc), ykpiv_strerror(rc));
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    Mode             mode = Mode::Unknown;
    std::string_view newData;
    if (std::string_view arg1 = argv[1]; arg1 == "-w") {
        if (argc < 3) {
            std::println(stderr, "Error: '-w' requires <content>.\n");
            printUsage(argv[0]);
            return 1;
        }
        mode    = Mode::Write;
        newData = argv[2]; // The text to write
    } else if (arg1 == "-r") {
        mode = Mode::ReadObj;
    } else if (arg1 == "-s") {
        mode = Mode::ReadSerial;
    } else if (arg1 == "-a") {
        mode = Mode::All;
    } else {
        std::println(stderr, "Error: Unrecognized option '{}'\n", arg1);
        printUsage(argv[0]);
        return 1;
    }

    ykpiv_state* state = nullptr;
    if (const auto rc = ykpiv_init(&state, 0); rc != YKPIV_OK) {
        std::println(stderr, "Error: ykpiv_init: {} - {}", ykpiv_strerror_name(rc), ykpiv_strerror(rc));
        return 1;
    }

    if (const auto rc = ykpiv_connect(state, nullptr); rc != YKPIV_OK) {
        std::println(stderr, "Error: ykpiv_connect: {} - {}", ykpiv_strerror_name(rc), ykpiv_strerror(rc));
        ykpiv_done(state);
        return 1;
    }

    uint32_t serial     = 0;
    auto     rc         = ykpiv_get_serial(state, &serial);
    bool     haveSerial = (rc == YKPIV_OK);

    std::string versionStr;
    if (mode == Mode::All) {
        versionStr.resize(32, '\0');
        if (auto rcVer = ykpiv_get_version(state, versionStr.data(), versionStr.size()); rcVer == YKPIV_OK) {
            versionStr.erase(versionStr.find('\0'));
        } else {
            versionStr.clear();
        }
    }

    switch (mode) {
    case Mode::Write: {
        std::println("Writing new object data: '{}'", newData);

        if (!authenticate(state, kDefaultMgmtKey)) {
            ykpiv_done(state);
            return 1;
        }
        if (!writeCustomObject(state, newData)) {
            std::println(stderr, "Error: writing custom object failed.");
            ykpiv_done(state);
            return 1;
        }
        std::println("Successfully wrote new ID. Re-reading...");

        auto readBack = readCustomObject(state);
        std::println("Object now contains: '{}'", readBack);
        break;
    }
    case Mode::ReadObj: {
        if (const auto data = readCustomObject(state); !data.empty()) {
            std::print("{}", data);
        } else {
            std::println(stderr, "No custom ID found (object empty or not present).");
        }
        break;
    }
    case Mode::ReadSerial: {
        if (!haveSerial) {
            std::println(stderr, "Error: could not read serial: {} - {}", ykpiv_strerror_name(rc), ykpiv_strerror(rc));
            break;
        }
        std::print("{}", serial);
        break;
    }
    case Mode::All: {
        if (haveSerial) {
            std::println("YubiKey Serial Number: {}", serial);
        } else {
            std::println(stderr, "Could not read serial: {} - {}", ykpiv_strerror_name(rc), ykpiv_strerror(rc));
        }
        if (!versionStr.empty()) {
            std::println("YubiKey Version: {}", versionStr);
        } else {
            std::println(stderr, "Could not retrieve version string (ignored).");
        }
        if (const auto data = readCustomObject(state); !data.empty()) {
            std::println("Custom object (0x5FC106): '{}'", data);
        } else {
            std::println("No custom object stored at 0x5FC106.");
        }
        break;
    }
    default: printUsage(argv[0]); break;
    }

    ykpiv_done(state);
    return 0;
}
