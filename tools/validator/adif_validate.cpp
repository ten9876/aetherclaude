// Foundry Validator — testbed harness for an Antares Detector finding.
//
// Compiles the REAL AetherSDR::AdifParser translation unit under
// AddressSanitizer + UndefinedBehaviorSanitizer and drives it with a crafted
// ADIF file. The sanitizer is the oracle:
//   * a sanitizer trip (SIGABRT + "runtime error"/"AddressSanitizer") inside
//     the localized file  => the vulnerability is CONFIRMED,
//   * a clean parse of every malicious input                       => UNCONFIRMED
//     (the Detector's candidate does not reproduce as a memory-safety bug).
//
// This is the "Detector -> Validator" link: an Antares candidate (file + CWE)
// is turned into ground truth by executing the real code, not by re-reading it.
//
// Usage: adif_validate <file.adi>     (exit 0 = clean; sanitizer aborts on trip)

#include "core/AdifParser.h"

#include <QByteArray>
#include <QString>
#include <QVector>

#include <cstdio>

using namespace AetherSDR;

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <file.adi>\n", argv[0]);
        return 2;
    }
    // parseFile() opens the file and runs the exact production parse path
    // (QString::fromUtf8 -> record split -> extractField), the code Antares
    // localized. No CtyDatParser is set, so the DXCC-resolution branch (the
    // only m_ctyParser deref) stays null-guarded and unlinked.
    const QVector<QsoRecord> records =
        AdifParser::parseFile(QString::fromLocal8Bit(argv[1]));

    // Reached only if no sanitizer tripped. Touch the results so the parse
    // can't be optimized away.
    std::fprintf(stderr, "[harness] clean parse: %d record(s)\n",
                 static_cast<int>(records.size()));
    return 0;
}
