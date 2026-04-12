// Tail-follows a growing size-prefixed FlatBuffers stream (Event or Error), verifies each
// frame, appends one JSON line per message (same shape as event_to_json).

#include "flatbuffer_to_json.hpp"

#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/verifier.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>

namespace
{

constexpr flatbuffers::uoffset_t kMaxBodyBytes = 64U * 1024U * 1024U;

bool verifyAndWriteLine(const uint8_t* frame, size_t frame_len, FILE* out)
{
    {
        flatbuffers::Verifier verifier(frame, frame_len);
        if (owlsm::fb::VerifySizePrefixedEventBuffer(verifier))
        {
            const owlsm::fb::Event* ev = owlsm::fb::GetSizePrefixedEvent(frame);
            const std::string line = FlatbufferToJson::jsonLineFromFlatbufferEvent(ev);
            if (fwrite(line.data(), 1, line.size(), out) != line.size() || fputc('\n', out) == EOF
                || fflush(out) != 0)
            {
                std::cerr << "flatbuffer_reader: failed to write output\n";
                std::exit(1);
            }
            return true;
        }
    }
    {
        flatbuffers::Verifier verifier(frame, frame_len);
        if (verifier.VerifySizePrefixedBuffer<owlsm::fb::Error>(nullptr))
        {
            const owlsm::fb::Error* err = flatbuffers::GetSizePrefixedRoot<owlsm::fb::Error>(frame);
            const std::string line = FlatbufferToJson::jsonLineFromFlatbufferError(err);
            if (fwrite(line.data(), 1, line.size(), out) != line.size() || fputc('\n', out) == EOF
                || fflush(out) != 0)
            {
                std::cerr << "flatbuffer_reader: failed to write output\n";
                std::exit(1);
            }
            return true;
        }
    }
    return false;
}

void drainCompleteFrames(std::vector<uint8_t>& pending, FILE* out)
{
    while (pending.size() >= sizeof(flatbuffers::uoffset_t))
    {
        const flatbuffers::uoffset_t body_len =
            flatbuffers::ReadScalar<flatbuffers::uoffset_t>(pending.data());
        if (body_len > kMaxBodyBytes)
        {
            std::cerr << "flatbuffer_reader: prefixed size " << body_len << " exceeds cap\n";
            std::exit(1);
        }
        const size_t frame_len = sizeof(flatbuffers::uoffset_t) + static_cast<size_t>(body_len);
        if (pending.size() < frame_len)
        {
            break;
        }
        if (!verifyAndWriteLine(pending.data(), frame_len, out))
        {
            std::cerr << "flatbuffer_reader: verification failed for a size-prefixed message\n";
            std::exit(1);
        }
        pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(frame_len));
    }
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: flatbuffer_reader <src_path> <output_path>\n";
        return 1;
    }

    const char* src_path = argv[1];
    const char* out_path = argv[2];

    FILE* out = std::fopen(out_path, "ab");
    if (!out)
    {
        std::perror("flatbuffer_reader: fopen output");
        return 1;
    }

    std::vector<uint8_t> pending;
    pending.reserve(65536);

    uint64_t read_offset = 0;

    while (true)
    {
        std::ifstream in(src_path, std::ios::binary | std::ios::ate);
        if (!in)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        const std::streampos end_pos = in.tellg();
        if (end_pos < 0)
        {
            in.close();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        const uint64_t file_size = static_cast<uint64_t>(end_pos);
        if (file_size < read_offset)
        {
            pending.clear();
            read_offset = 0;
        }

        if (file_size > read_offset)
        {
            in.seekg(static_cast<std::streamoff>(read_offset), std::ios::beg);
            const std::streamsize to_read = static_cast<std::streamsize>(file_size - read_offset);
            std::vector<uint8_t> chunk(static_cast<size_t>(to_read));
            if (!in.read(reinterpret_cast<char*>(chunk.data()), to_read))
            {
                in.close();
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }
            read_offset = file_size;
            pending.insert(pending.end(), chunk.begin(), chunk.end());
            drainCompleteFrames(pending, out);
        }

        in.close();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}
