// NIST CAVP "FIPS 186-4 ECDSA" SigVer known-answer vectors.
//
// Source: csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/
// documents/dss/186-4ecdsatestvectors.zip, file SigVer.rsp, sections [<curve>,<hash>].
// Each record below is one CAVP record: Msg / Qx / Qy / R / S / Result, copied verbatim
// except that Qx and Qy are left-padded with a leading zero nibble -- CAVP prints binary-curve
// coordinates at ceil(m/4) hex digits (41 for the 163-bit curves), which is an odd digit count,
// while a SEC1 point needs whole bytes.
//
// Why these exist: every other per-curve test in this directory signs a message and then
// verifies its own output, which cannot detect a wrong wire format. These vectors are an
// external oracle. The non-byte-aligned binary curves are the point of the exercise -- their
// subgroup order n is 163, 233, 281 and 282 bits, so FIPS 186-4 6.4 digest truncation has to
// keep the leftmost n *bits* of the digest, not the leftmost whole bytes. Keeping whole bytes
// instead makes every one of the Result = P vectors below fail (verified independently), which
// is exactly the defect that shipped undetected.
//
// Transcription was cross-checked by re-verifying all of these from scratch in Python -- an
// independent GF(2^m)/GF(p) ECDSA verifier, with the curve constants themselves self-checked by
// confirming G is on the curve and n*G is the point at infinity -- and confirming the verdict
// matched CAVP's own Result column for all 28 records.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    /* Decodes an even-length hex literal into raw bytes. */
    std::vector<uint8_t> fromHex(const char* hex) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') { return c - '0'; }
            if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
            if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
            return -1;
        };

        std::vector<uint8_t> out;
        for (const char* p = hex; *p && *(p + 1); p += 2) {
            out.push_back(uint8_t((nibble(p[0]) << 4) | nibble(p[1])));
        }
        return out;
    }

    /* Computes a digest over msg with one of the library's own built-in hashers. */
    std::vector<uint8_t> digestOf(EHashers alg, const std::vector<uint8_t>& msg) {
        IHasherPtr hasher;
        REQUIRE(IHasher::create(alg, hasher) == ERET_OK);
        REQUIRE(hasher);

        hasher->push(SReadOnlyByteSpan(msg.data(), msg.size()));

        std::vector<uint8_t> out(hasher->byteWidth());
        SByteSpan outSpan(out.data(), out.size());
        REQUIRE(hasher->finish(outSpan));
        return out;
    }

    // --> Every encoder below is hand-built rather than reached through asn1::CDer, so that a
    // --> vector's expected input never depends on the same encoder under test elsewhere.
    /* Appends a DER definite-length field: short form below 128, minimal long form above. */
    void appendDerLength(std::vector<uint8_t>& out, size_t len) {
        if (len < 0x80) {
            out.push_back(uint8_t(len));
            return;
        }

        uint8_t bytes[sizeof(size_t)];
        size_t count = 0;
        for (size_t v = len; v; v >>= 8) {
            bytes[count++] = uint8_t(v & 0xFF);
        }

        out.push_back(uint8_t(0x80 | count));
        while (count) {
            out.push_back(bytes[--count]);
        }
    }

    /* Appends a minimally-encoded DER INTEGER holding a non-negative big-endian magnitude. */
    void appendDerInteger(std::vector<uint8_t>& out, const std::vector<uint8_t>& magnitude) {
        REQUIRE_FALSE(magnitude.empty());

        size_t at = 0;
        while (at + 1 < magnitude.size() && magnitude[at] == 0x00) {
            ++at;
        }

        std::vector<uint8_t> body;
        if (magnitude[at] & 0x80) {
            body.push_back(0x00); // --> keep the value non-negative under DER's sign convention.
        }
        body.insert(body.end(), magnitude.begin() + at, magnitude.end());

        out.push_back(0x02);
        appendDerLength(out, body.size());
        out.insert(out.end(), body.begin(), body.end());
    }

    /* Wraps already-encoded content in a DER SEQUENCE. */
    std::vector<uint8_t> derSequence(const std::vector<uint8_t>& inner) {
        std::vector<uint8_t> der;
        der.push_back(0x30);
        appendDerLength(der, inner.size());
        der.insert(der.end(), inner.begin(), inner.end());
        return der;
    }

    /* Builds Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } from a vector's raw r/s hex. */
    std::vector<uint8_t> derSignature(const char* rHex, const char* sHex) {
        std::vector<uint8_t> inner;
        appendDerInteger(inner, fromHex(rHex));
        appendDerInteger(inner, fromHex(sHex));
        return derSequence(inner);
    }
}

namespace {
    /* One CAVP 186-4 ECDSA SigVer record. */
    struct SigVerVector {
        EAsymmetrics algorithm;
        EHashers hashAlg;
        const char* label;      // --> CAVP section and verdict, surfaced by INFO on failure.
        const char* qx;
        const char* qy;
        const char* r;
        const char* s;
        const char* msg;
        bool shouldVerify;      // --> CAVP's "Result = P" (true) or "Result = F ..." (false).
    };

    const SigVerVector VECTORS[] = {
        {
            EASYM_K163, EHASH_SHA256,
            "K-163/SHA-256 Result = F (3 - S changed)",
            "076c3013015e54a355f44f119dc69ff79a6220ea24",
            "043312e3dd36371e6e6028d29654c5050829532643",
            "0123cd916b9d0e681d2589b4f69dd158fc763b3cbd",
            "034eddf7c7b19a5fd1b90f421de1094f1afd5932fc",
            "36c6b824012460b73d9a1cce453eae5505d952d34f28e2490a8f082e5d6f445f"
            "8aec031e15edda57c0b364b248cdf84b2043c4845e2e81ae09486ebebfade285"
            "0628d36e04f52077b2cd0746914aa8b7216df1e9a9342f59b4ed2157fe7a8121"
            "87defa456a3d64c47e42d6bdb9844616a1b3a15bbdfb8828622e39ca0aab7610",
            false
        },
        {
            EASYM_K163, EHASH_SHA256,
            "K-163/SHA-256 Result = F (4 - Q changed)",
            "009e59b792cbf290b1a5558eb2bff0d050cdc94e55",
            "023e83acee2ce8cadfba7d558b09bb60b8df01bf6d",
            "023f53c4eeb57843ff82f3d087081f7c858de51c34",
            "03afaf8b91edd1900e57dae40afe1414a78e8c0a1a",
            "480b24b8d46a7b023516b37b302df8c5f113a13844cc146f3f4a78e102a1a1d4"
            "75554224efb2577ccc073e64ea2288ce31ab230a0faae0ad0819d2d007b7b460"
            "7018f5a486274162c30b0a0a581ae798cbbe46eb38b78a8096b70e20e844ef74"
            "de37466c2f9d7e30c9397e692ddcc78373b28b25b945e91a6cdbe218ce94b5f6",
            false
        },
        {
            EASYM_K163, EHASH_SHA256,
            "K-163/SHA-256 Result = F (2 - R changed)",
            "033fef189d89620780b3b7d093ae2ed9075c4339bc",
            "049b4a6acb23f0e8ef899982d6cc7438521761a07a",
            "022466c273a29100b1916d0f2968e8434df20839db",
            "01920f30c82972b8de69589bb231fd793cd52f154a",
            "e1ffa02b8359a049765196823c140a82defec326ddaff88fd9e47189e8734c08"
            "6de84b8335b6a655a26a4a6185f8aee426e458e22c4d3caf3127f64ae9a2ad21"
            "81c7dd3b9dd9adc29c2624ccc32e0ea441f6524b915f03d736f4be65b268d5bf"
            "3c409937c0ad6087d951701c7867d2585a2b9c3d4fb149041e1ef12f534d61f8",
            false
        },
        {
            EASYM_K163, EHASH_SHA256,
            "K-163/SHA-256 Result = P (0 )",
            "02dfcc77d88454d56f6554964046c9ab3063b5d2b1",
            "050662c61f46ab6697d5aa1b9811f88a1671715f3a",
            "0143a9219f6f5f50f16c0bfe1573cdb3d5e903c491",
            "0222dc0a774dd4a81599ef8ef0d6fae11513031f85",
            "2a4d77289ed9184fe22833aa6716073cec9278dc373b558d857241335ccbd617"
            "eb1d6db7a9682bd132f2ed8a27b44f5f2d0d5f41f7dfc86bcd5e02607d2c3e23"
            "056b8b4acc430fa91cdfe9ff5bd8bed0c64b6197752e759746086fbcf6f5997b"
            "baae221ea66008721c66abe55f9f0e6109372911f2223483132cc938ddb66c36",
            true
        },
        {
            EASYM_B163, EHASH_SHA256,
            "B-163/SHA-256 Result = P (0 )",
            "028c5c9d46450ea9c267f8510ef0c37702b93210a9",
            "05fa5f4acb8c345e228477db5f51b2860aa4f1aaf9",
            "017df984f390f689ae4556217f12da4c282ab70f58",
            "02ef66dab9a2753d66e818d9a0afbc81cd21ec5677",
            "d71e28f1d38eea0326154d78109b907e59d8fc679ffb730819ae144f8c04ab21"
            "e35f937a5568f1b9b657857ab9d21cb63466b769fcdc06ef3961116f6c09a81d"
            "56586a08ec7572d87da579b0fa743196b5724f5f883ae4e7747c6dcbdfb33273"
            "4d2229e842951d79beeb5bffdc72941d6d0c474db4ceccefd2d215028143f85d",
            true
        },
        {
            EASYM_B163, EHASH_SHA256,
            "B-163/SHA-256 Result = F (3 - S changed)",
            "04c50a24fa97a9da834582b87afdf1e2ab468c16a3",
            "06ed3f30ce8ac92fc9bcff8e8cde607771121da9b6",
            "00ae9a37a8ec2997bb94a770eed842e128c0dd7370",
            "008638b7294cf664b3f380887330f853a8eb9242fb",
            "99dc739aa0e8af7604247b23e0d07d6a98f22cbce297d9845e78371e2bfb96cb"
            "47e483aefb55178e5f64c4ff9f8b110eea3e60a50656233b55793b6017e864f2"
            "610e343410f9ce56aade90aa9901e40b76c03db277620faa83e029df1a6562b5"
            "24f5b170cd5873cbb9c9049277a00baf82d00639dd9ababe3fe632674fd68270",
            false
        },
        {
            EASYM_B163, EHASH_SHA256,
            "B-163/SHA-256 Result = F (4 - Q changed)",
            "00560aafbd210bba079c91d8baaa32cb567f99a611",
            "05d888f7201729477b6a19e711d030e092fdf28189",
            "028e4f9aae1cf5269fd2e735a019d89a6cc9290d0f",
            "02fb89046189838cc3c5bf1a06a467cbb99a95f37c",
            "609660735332c3e556c46e433ea7ee4640392899b9dcc13596bdd9c934ef8daf"
            "eb7e4ce343f75b8fc64f197202e097abc3435e63b367944129154078d6397c54"
            "b71bea92db386db36f435e7e59dff76d3611ed1badf9d1f851aca456802d97ce"
            "b318a71dc4ea174dcd1e5edf88afebde118a29b2ae25314d10f0ac0b720aecce",
            false
        },
        {
            EASYM_B163, EHASH_SHA256,
            "B-163/SHA-256 Result = F (1 - Message changed)",
            "03b29bbd06235d89dbce629e0bd3c86c5dd32fe93e",
            "06e1283667175d1eead7441c56970ebc9d0f414af0",
            "023ec9f6e3050f90b0d8612d3730d085769901ab05",
            "03209a58469ad4830c33e5e2471ca5e07150f02025",
            "0af238aa403fc1f854f3ab403005ab3137a40e6a53bbbbf978f4ff24db4a69ff"
            "0f2be2457e6cf745632f79de671f0d293577c44327f08255f0eb5d1e46048c89"
            "4d0094be8cf283477a2824bd83045d7bc675be25492180d8da4d2b113d1c7301"
            "67bebba8dfb14d332befdd069a55ae4f9e2d19468f08b56a2e0e72126adfbff9",
            false
        },
        {
            EASYM_K163, EHASH_SHA512,
            "K-163/SHA-512 Result = F (3 - S changed)",
            "013b710e91e2faec1d2e34a4a0a32d944531dfe2c6",
            "06d2f8ddca633ca0c52c3438bdf99c18d35e66de06",
            "0254412da587080f5e911461e96256ee1477f9efe1",
            "02f8e1cee60a2c4d6f75f8765bf20c882cdaed654b",
            "410589d6dc79e3a1ca51c9fb84a3f1cc4c4a0d74e8d539b10e1d03aa8d0a9304"
            "ac388e7ec378cea99e93c411c79ceae8990dfcde8383fcb1dbf8612a49af0936"
            "507df3603f25fb866363e472c91a50df4b00a43803531777ecc0fed8c6be0e1b"
            "403d1647e4165f2dfe58d6deab4b9f01ad1ff429c458d9991fe3c94219d98076",
            false
        },
        {
            EASYM_K163, EHASH_SHA512,
            "K-163/SHA-512 Result = F (4 - Q changed)",
            "00af0f24629c1fc5f0e968ff923757c4857430df4c",
            "07dbb6e661caae47a78e50ef97d65eea9cfc37ad7a",
            "0315141e67772d3658b76777998f457e1fc8d53f69",
            "035a129f92d1996f4ae04df5f092de41c41490b205",
            "b87af93bb05463cbb6d61c4c696290f8ab40771f4a9dcc7052dc7b031eb57c68"
            "e33e933426d89624c4eb8a604438a8ef7e094357a54b80c9bc70bbcac3609a93"
            "0c456edaf366b7fa1e70d0d7f15a2462178548277d11b74e5e9188e220edb6ad"
            "46cc9ca3e6019323d8806f2bd6af6b2ccea5f491f4642c69e651c218a584b9ec",
            false
        },
        {
            EASYM_K163, EHASH_SHA512,
            "K-163/SHA-512 Result = F (1 - Message changed)",
            "027b272f13549466a930e59cf28039b6275fbecbc4",
            "03cb630a44f888a520dbeb35e29879ea445306fdcc",
            "036682aa4d99d8d90629456812eda01eb1afc5c30d",
            "002f83faa2e844a8005ae32e6ecc9202984133261b",
            "014855603ca35d201fef46ed17161d7110d133457877e862e66f0e9e0e10773e"
            "217089dfd728924ec5849c1801b5a85c4623fd8e357fcf6c778e5614e6817ccf"
            "435640bf6d400b3694e7255c3c855872ca3bc79f3bf38c805cdaa20e1e0cfbc4"
            "37c891a2687c4254462c02f20d2a5b8110daa86e5bfeeb0acf262773c2ef2c29",
            false
        },
        {
            EASYM_K163, EHASH_SHA512,
            "K-163/SHA-512 Result = P (0 )",
            "00bc9eb8daa9d1bbc80ea479ef923d96fb5b29f50a",
            "01d60172e81f2b9e967c1f96c9688a7a8b32a8ac96",
            "029817562328d26f02658dc85fec2bfc223fc32e6d",
            "00539afab0e94a8d7d6882060bf207957676ff45ed",
            "00c724ef48283d768b1ec0d2de238c5787a1abfad0c75dda1d070ad361dd0082"
            "7a2c55ce626c505a3fd984f8bd1590af9546048f9251440139a44fd14b2b5b79"
            "75b2f1cf1041ea9ad76685f39f02af4f6b7a1a88dcc47764f5bbf0a7813603d7"
            "496a913287773654226956f80be2bbfcce486e4f606f3b0f747c45a314eae681",
            true
        },
        {
            EASYM_B233, EHASH_SHA256,
            "B-233/SHA-256 Result = P (0 )",
            "0151cd1573ea0e5de917effa185747517598db76ef15ee32e22a3630dc96",
            "01ddf0918097dbed1897af3f96ce389183d77ba368d4f63e196410e3e4b6",
            "008dd34c080b4be097a378fc6274c776ebf61021f3dfe8740b94e17da7b6",
            "00404dba4f3ad89e02ffdcc9e30f751b0e4dda8b633becd75d99d04209c7",
            "14dca9cce04604ca01214fdbeb87389559350957b14dbb175a35c705a8969664"
            "a2138d72d99a973bfc85d95408086140588f1e7eef8fcd70e37983d1ea1e7987"
            "b2defcba6f13e50c6db72819207d05448e2f5a49d0f136acfa5d440331b4dab0"
            "967da7dbc9a77ca5ea1c6577af97218235b302b7e1f8fb07c8f601795556da32",
            true
        },
        {
            EASYM_B233, EHASH_SHA256,
            "B-233/SHA-256 Result = F (3 - S changed)",
            "00e1ccad4fd82ed18668766b88cc42ceb350325dd874566821fe6d0b9dbf",
            "0079f26e92b27ecf34b36c6d39156253564301e22d491b861eb150b8507e",
            "0070eafed083b96a9b454c500667d4706fc1936beb04d8660f3d04cdf0dd",
            "00c2b4934d736345f9de221511eac69eeb6ba878883740d8f0b4a21daf2b",
            "31747f44907160d70a8a9343c41929f52b62d1b804a58026db905b865ce28bf3"
            "7eaa6824870d2d43163b502d718364d3e73363b66b1d4cba22972825aca4a637"
            "5ee5aa2300dfe29f9eb746a463b755ff06bef80338e1315fcf6aa484f8f21ac7"
            "1f806ec6565fbeee68a59832709e7fb0af31feb0b96da991283f8fcde78b1285",
            false
        },
        {
            EASYM_B233, EHASH_SHA256,
            "B-233/SHA-256 Result = F (2 - R changed)",
            "01edd7e3e4462d17cf7fb101214f788951ac84be5fd7e7a9b0270ff7c746",
            "01e0bdb080806c8f5af778790a9fff487c507e49b371835c41c2dca2b8b7",
            "00ec94ad40d68e0229869473d5cb2c385be359bfb0030ae2162ee4a7abe9",
            "00787dc167c8ae5a0708d98aa89c546448b93f0c4419ab52b9260991d0d2",
            "b0dd49bac9e30a869d828fa00d7669f3b593606d035033b6c5da9a3609dc356b"
            "d93b119961e9bdef51874652d836b18bd2517569b387b61921ff27ca491f72dd"
            "5940b4e2bc2f558d22ea7ff2a2be982d9e92e6715a0e078fd7907fd94a161f49"
            "357a3bfea2b61431ba146883a9146d15cc00199a78f896bdc87685592ffc9f90",
            false
        },
        {
            EASYM_B233, EHASH_SHA256,
            "B-233/SHA-256 Result = F (4 - Q changed)",
            "0155831e6a962f9321fea3c8bcd8ab06559cea3db4b88f702e5980b1fc3a",
            "00d4fbefe427565cc8424a33ddb0cd773c2c30e276400e93759875bfae6f",
            "0011e76e35c036c23a7c9ae16d20d366eeb08bead606c6c49a8b62156e2a",
            "0099b96b5f5730cdc90294ddd9da65356bcb1800f1149a78495cfffbc78e",
            "7831d59ba11e3df8e09d957f94b731f14fa57bde7426dc19a55fb23bcc6c2a89"
            "659e7171b4ca92f9263d76d6489c74e91abcc9dde7ea8822d3746cc912b061b5"
            "290e8eb85629535c0f66b5a94cc8de4b23b2f60d7a0dab91e557f308b18accba"
            "ff9d9d365cf65a9c8f81d05ce5073c7deec19439792dfeb08d808afe850bebae",
            false
        },
        {
            EASYM_K283, EHASH_SHA384,
            "K-283/SHA-384 Result = F (1 - Message changed)",
            "030557ec31f7abb062a4af5207707a7ecd810341514668afea2818b5cd12daed"
            "0714594a",
            "071a7a1b4e88ed37ddccd6d7c660d57211ac403d53f6119dbd56d914fd8eba3e"
            "caa57b87",
            "00e6d687b3712a2a850aa771c408167f978c7e8cef500e12dd889da81d2c6288"
            "526cb82c",
            "00fa0119781a0961eb7b23ef184bbe6863c47d8361619df2972ea3cf41e3d5f7"
            "b2cf41c0",
            "d1a75368b6b83238b66a1dda85ab85ac264b28862dc3f8439f0b9c7314b71276"
            "27fc4b9e60c6eeb94c85ead7035379e47290683747af74b05398ba44a1bc3f9d"
            "1375e4bea1fe5721e104969afc0ca08033fff862174b8ccd59271ef20da0234a"
            "245d4e151f98ae1ae3c1db7a638575a4567170e1e342800ddcb56dbef95c43e2",
            false
        },
        {
            EASYM_K283, EHASH_SHA384,
            "K-283/SHA-384 Result = P (0 )",
            "01829e6a31eae6aa373a69b1102a8a4a2abe7be65d06e37dcfde686349c29fe0"
            "046130ad",
            "0214724fb16beaa7b421546c9fdd03591cd48e0c5b6d36252a3490ae699aa6c6"
            "1e9715b7",
            "009c6fa3bb3e9e684545af7d4f0833660acdc9fb464b9122c36cefc03a374114"
            "bc38b3cc",
            "01390899d78b97f7ecef9f33a82fcc25605df0b6d16b31787b29d8a1e5fb4449"
            "35db427e",
            "78cab3cae32427d516eb3b14828bf8e4fdd8469a258bda29999f73bac5c5440d"
            "fd3440c7ea31910f0384194448cd19c310f897fc8562168ec0bc526c4db5872f"
            "9ad7fda930928eb83039c867fb14eb3207a5438ad01cf39bd58081a06fb10c51"
            "568d5eb4d02a6e04f09539c8051321fae3f167fb95b9a8a70ebe44df897880a7",
            true
        },
        {
            EASYM_K283, EHASH_SHA384,
            "K-283/SHA-384 Result = F (4 - Q changed)",
            "040378e0cdbd410c8b21d604230979a605ace72244a14011ae54629eb13fcb0d"
            "7d92f93e",
            "03c112322dfdca3c9c7e0323ab6433aed8ca06e17dc34fec3f5ccd3db883825e"
            "5672b9ce",
            "01df22e4ec6d4e9d5ee2b868f09e438ba935c21a4de1d749e975d319212ddc95"
            "201fb255",
            "01b146c9bf6908810761dd98a308b2228538c3ef72e2f47410c843dcbde23ea4"
            "11b80aca",
            "148c6168897394b736c5995137e9e96e507a8904f155c2031a9c5bff8fe8cb82"
            "79d77088c99cbd40c607266a87221594f42104f92c81dcb465834bb44558af09"
            "cc16f565e714c8962fbc06cce3c350a626deb11509c61cb25284a4d7de6bfea1"
            "ef759d451b5df045f9279a8b7e694a628873ac03fcf61e4bf502a763c1b9184e",
            false
        },
        {
            EASYM_K283, EHASH_SHA384,
            "K-283/SHA-384 Result = F (2 - R changed)",
            "00e8e125d91e223c6cbcf6b33c7763bea02fd3e3a2c9821c58e009ffca8995e6"
            "ff2dc76f",
            "02cd0a3bd7b643d2c3fa7d5fb3cf78a33bac95909a9df677fd1237a269c6e887"
            "6d1c5ed1",
            "00346f7c261442232b1245f5a9297c55a63ce5dc07c89dd49a7057680797f554"
            "f87a9056",
            "00400e3f16ac6436152443970981fb23ea9b445f3d7de5ba9f861ff5bbec34c7"
            "c0b7cafe",
            "98fefe886b57e112e1002fdaf9e3e4fd8eb9a6ede3f11799eb55a4b00c3f0539"
            "6c9c9e2aa1ec17570c67578faa1d54acba2bc7d6d4bb6af3b8c2ecdd9ba76c41"
            "ea59b7f486bd631a0321a1cdc625ed2bfa4c847ecf6f02f72054122faaff13e6"
            "9d33347bc2c3ca06ea0fffef30cb2aaff086594a4804453745146250e41536a3",
            false
        },
        {
            EASYM_B283, EHASH_SHA384,
            "B-283/SHA-384 Result = F (1 - Message changed)",
            "001c1035bdab52d8e73c00778e20e4c010d9d6aca680256608bae0ef2fc59cc4"
            "44a2902b",
            "05f50d87cffe65e11e340c6b3a7a1d36dcd78ec00acc697116413fbb35e3d23d"
            "3ebed1f3",
            "03e3c1a2b40487faa8e07a020920e703df486ebd1a5b5efeb4c7b697ff2deeff"
            "5fd5628c",
            "0055dc20bf694448c1045bfe423da1ad0bbff7dabe3afc7117eccc7028e1799c"
            "0204f81c",
            "0cad10ce8aedccbd65c5ad1f91eba1914f3f527fc7cc142d7d82ea460df87bf2"
            "74135d84cdb139838d010d51519a42808f8bbef6eda9187753d6f935860d25cc"
            "627435bfa14a928fe1a439a379c079c6887ba3b884044308b3e11831011f6194"
            "e83d7d7b1e8e94403090ef42dcaa002aa335cc4363f65af7992e9082f5711c14",
            false
        },
        {
            EASYM_B283, EHASH_SHA384,
            "B-283/SHA-384 Result = F (2 - R changed)",
            "07d4f2e5b2bed6336654d02a219bd0c7a34a3990f490d8dddfdcc20fe27e55ec"
            "f296aa20",
            "020aed46e1650f52b18784bf847af5ba180ff6b83f9048e11f8b18bb59bdf088"
            "2158fa22",
            "00bac571e4de7481df0236aaaa6b83d5590497436a691eafa7d59ecc687d1dfb"
            "14c7bf50",
            "017255b13f74db2cb67dbc5617d8cfd9b877afa6d8bcfc675cabf097f928a7bd"
            "96740200",
            "e6ff1637c6bfe72475a086fe48ba77b970b566c4cdbeb74284018d00f2800319"
            "1cb6a8c49b7fa12c945e3e00d5b858ffcae96f8ebfe057a5e0587cdd1b623420"
            "554fec383b654e5b41b5ea9f1573949bfb0c0f436aa3352de4653ec71614f78f"
            "c5bcc6430c4bb732bbf11e44be86fdb4c45bc562a5045e26cf13fb381540f4e0",
            false
        },
        {
            EASYM_B283, EHASH_SHA384,
            "B-283/SHA-384 Result = P (0 )",
            "058549012fb02ceacef63c75a4f23e6d2de749d83ed936da49a8c455478c5062"
            "bdb800f9",
            "03385ca738df7e56ba2e35167aa0bdaddcb7221370a6eaa1196885e11f7b4626"
            "b970eb4a",
            "00db0d340b59af49ff78d09088148055f15df0e4aec1b23409b97c3870dd9276"
            "894ca9a6",
            "0022b746ee1c71ffe777853500041ab5534bd230ebdee9b2a370b55a44efb57c"
            "9b916ae2",
            "09cba889bf8594fcd57b4e10a8be0ba2628a9b904bfdc38d41617e30298ad447"
            "e4b20a14b37334ec791ce251300edda4b4d73a22d74f2634f298938575546868"
            "5ff1ecde957ca804ade3598eced217cba28e978399c2cc34462cbce78c7f53ff"
            "aea3bd4f30b592c06f658f9a587a701851328858403c9e817922425f411bf870",
            true
        },
        {
            EASYM_B283, EHASH_SHA384,
            "B-283/SHA-384 Result = F (4 - Q changed)",
            "03c74781d9c78f1229e5e1501f2ed9ad8658241f63fbf2b7dfac0999a370a5db"
            "b704eb3d",
            "05bfc96ba37e54773a12099e5ed633015d3a5723c44159870fee6befb4fc8f8f"
            "513a5e9c",
            "035b51f0b2da1a9e143ce4f1d4441e43743fb2fa6b77c00a77415a54951c6cbe"
            "4da01871",
            "015fb4871ed50614b24975fc1fc815f8d8a271161b8696544a58d0a3f39f157e"
            "7945aca5",
            "bfc3f7bb6c58122f3d5ca2ddedc12933c2953f97024213eea1d1251a58220d83"
            "45b86c9793d62997a2d8b8b43c10aafff78af5e769d9e05a9155a84d90bccc00"
            "174af89bc9c93cd54b9994ed7c59e43c62bd581b097550c2f67300e45ff39a68"
            "0e9eb0d76ed0c5e2b177fdb587f4770bc6f33b3d6b618b99672b8939dbeeb1cb",
            false
        },
        {
            EASYM_P256, EHASH_SHA256,
            "P-256/SHA-256 Result = F (3 - S changed)",
            "87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555",
            "e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9",
            "d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0",
            "a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6",
            "e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d"
            "9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19"
            "fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c"
            "24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0",
            false
        },
        {
            EASYM_P256, EHASH_SHA256,
            "P-256/SHA-256 Result = F (2 - R changed)",
            "5cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7d2",
            "ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a85",
            "dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693",
            "d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c",
            "069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d6"
            "83877f95ecc6d6c81623d8fac4e900ed0019964094e7de91f1481989ae187300"
            "4565789cbf5dc56c62aedc63f62f3b894c9c6f7788c8ecaadc9bd0e81ad91b2b"
            "3569ea12260e93924fdddd3972af5273198f5efda0746219475017557616170e",
            false
        },
        {
            EASYM_P256, EHASH_SHA256,
            "P-256/SHA-256 Result = F (4 - Q changed)",
            "2ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244cb",
            "5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a64",
            "9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda8",
            "9467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc",
            "df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d"
            "8d746429a393ba88840d661615e07def615a342abedfa4ce912e562af7149598"
            "96858af817317a840dcff85a057bb91a3c2bf90105500362754a6dd321cdd861"
            "28cfc5f04667b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de",
            false
        },
        {
            EASYM_P256, EHASH_SHA256,
            "P-256/SHA-256 Result = P (0 )",
            "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c",
            "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927",
            "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f",
            "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c",
            "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45f"
            "d75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217"
            "ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce4"
            "70a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3",
            true
        },
    };
}

TEST_CASE("ECDSA: CAVP 186-4 SigVer known-answer vectors verify as published") {
    for (const SigVerVector& v : VECTORS) {
        INFO("vector: " << v.label);

        IAsymmetricPtr alg = IAsymmetric::builtIn(v.algorithm);
        REQUIRE(alg);

        // SEC1 uncompressed point: 0x04 || X || Y, each coordinate at the field byte width.
        std::vector<uint8_t> qx = fromHex(v.qx);
        std::vector<uint8_t> qy = fromHex(v.qy);
        REQUIRE(qx.size() == qy.size());

        std::vector<uint8_t> point;
        point.push_back(0x04);
        point.insert(point.end(), qx.begin(), qx.end());
        point.insert(point.end(), qy.begin(), qy.end());

        IPublicKeyPtr pub = alg->createPublicKey(SReadOnlyByteSpan(point.data(), point.size()));
        REQUIRE(pub); // --> every Q in these vectors is a valid on-curve point, including the
                      // --> "Q changed" negative cases, which swap in a different *valid* key.

        IAsymmetricContextPtr ctx = alg->createContext();
        REQUIRE(ctx);
        ctx->keyPair(pub, nullptr);

        std::vector<uint8_t> digest = digestOf(v.hashAlg, fromHex(v.msg));
        std::vector<uint8_t> sig = derSignature(v.r, v.s);

        ERetCode got = ctx->verify(
            SReadOnlyByteSpan(digest.data(), digest.size()),
            SReadOnlyByteSpan(sig.data(), sig.size()));

        if (v.shouldVerify) {
            CHECK(got == ERET_OK);
        } else {
            CHECK(got != ERET_OK);
        }
    }
}
