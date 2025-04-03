#ifndef YK_COMMON_HPP
#define YK_COMMON_HPP

#include <cstddef>
#include <format>
#include <fstream>
#include <optional>
#include <vector>

std::optional<std::vector<std::byte>> readFile(std::string_view filename) {
    std::ifstream file(filename.data(), std::ios::binary);
    if (!file.is_open()) {
        return std::nullopt;
    }
    file.seekg(0, std::ios::end);
    auto fileSize = file.tellg();
    if (fileSize < 0) {
        return std::nullopt;
    }
    file.seekg(0);

    std::vector<std::byte> buffer(static_cast<std::size_t>(fileSize));
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    if (!file.good() && !file.eof()) {
        return std::nullopt; // partial read / error
    }
    return buffer;
}

bool writeFile(std::string_view path, std::span<const std::byte> data) {
    std::ofstream f(path.data(), std::ios::binary);
    if (!f.is_open()) {
        return false;
    }
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return f.good();
}

#endif // YK_COMMON_HPP
