#pragma once

#include <string>


class PCAPReader {
    const std::string _fileName;
    uint64_t _packetsCount;
    uint64_t _payloadSize;
public:
    explicit PCAPReader(const std::string& fileName);

    // ���������� ������� � �����
    uint64_t packetsCount() const noexcept;

    // ����� ����� �������� �������� (��� ����� ����������)
    uint64_t payloadSize() const noexcept;
};