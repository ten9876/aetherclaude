// Foundry Validator — libFuzzer harness for the Antares AdifParser finding.
//
// Instead of a fixed corpus (adif_validate.cpp), this lets libFuzzer *generate*
// inputs and drive the REAL AetherSDR::AdifParser under ASan+UBSan. Seeded with
// one valid ADIF and an ADIF token dictionary, the fuzzer discovers the
// crafted field length that trips the signed-overflow on its own — no
// hand-authored crash input required. A sanitizer trip => libFuzzer saves the
// reproducing input as a crash-<hash> artifact and exits non-zero.
//
// Build: <llvm>/clang++ -fsanitize=fuzzer,address,undefined ... (Apple clang
// ships no fuzzer runtime; see bin/fuzz-finding.sh).

#include "core/AdifParser.h"

#include <QString>
#include <QVector>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace AetherSDR;

// AdifParser's public entry (parseFile) reads a path; parse() is private. So we
// stage each fuzz input into one reusable temp file and run the real path.
static std::string g_path;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    const char* tmp = std::getenv("TMPDIR");
    g_path = std::string(tmp ? tmp : "/tmp") + "/adif_fuzz_input.adi";
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::FILE* f = std::fopen(g_path.c_str(), "wb");
    if (!f) return 0;
    if (size) std::fwrite(data, 1, size, f);
    std::fclose(f);

    const QVector<QsoRecord> records =
        AdifParser::parseFile(QString::fromStdString(g_path));
    (void)records;   // exercise the parse; result is irrelevant to the oracle
    return 0;
}
