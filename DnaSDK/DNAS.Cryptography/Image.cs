using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Hashes the exact DNAS image ranges consumed by the PS2 when deriving the
/// first server reply's DES challenge key. Offsets are relative to the image
/// buffer beginning at EE 0x005498DC, not to an ELF/ISO file header.
/// </summary>
/// <summary>
/// Image-independent first-reply challenge supported by the original PS2 client.
/// Challenge A bytes 0..3 are SHA-1 input lengths; when all are zero, all
/// three effective SHA-1 operations hash the empty sequence, regardless of
/// the image or the offsets in A[4..7]. The resulting DES key is thus
/// calculable by any server without possession of a game-specific image.
/// This preserves the DES ciphertext/response check, but it does NOT prove
/// possession or validity of the client's DNAS image.
/// </summary>

public static class Image
{
    public const int RequiredPrefixLength = 0x1A7;
    public const int ImageLength = 0x10000;
    public const int SignedRegionLength = 0xFCC0;
    public const int SignatureOffset = 0xFCC0;
    public const int SignatureLength = 0x80;
    public const int UnknownTailOffset = 0xFD40;
    public const int UnknownTailLength = 0x2C0;
    public const int RecordedDiscDataOffset = 0xFC80;
    public const int RecordedDiscDataLength = 0x40;

    // Recovered from the original module's 162-byte ASN.1 SPKI at EE
    // 0x005608E0. The first 48 DER bytes were DES-ECB encrypted in the
    // module; their original decrypt key is 0B AB 79 94 DA C2 40 23.
    // This key authenticates the 64 KiB DNAS image signature. It is NOT
    // The signing authority for image verification is separate from the per-title S1 ticket public key.
    public static readonly byte[] ImageSignatureModulus128 = Convert.FromHexString(
        "C5C20818AFF3ECABEF1EBA6644D9EFEB8DD3815150FF1F2CDB5EB11B7AD90F" +
        "48F251A5DEE3DD5ED2E3A12DE4FD98C9710AE246FF410D2CC8A5966BD5AECD7" +
        "3F1E54093A44205C6E70200089192E0D84BED10891739CCCA1A7EBF93EF4B45B" +
        "095258E5CBC88B3547CA9901DDCE6C0CF914B5BF4F616C3B089B6322239DBF2CBAD");

    /// <summary>
    /// Genuine signature verification used by the recovered DNAS module:
    /// RSA-1024, e=65537, PKCS#1 v1.5 type-1 padding and a raw 20-byte
    /// SHA-1 digest of image[0..0xFCBF]. No fixture equality, private key,
    /// captured signature lookup or per-game special case is involved.
    /// The last 0x2C0 image bytes are outside this particular signature.
    /// </summary>
    public static bool VerifySignature(byte[] image)
    {
        if (image == null || image.Length != ImageLength) throw new ArgumentException("Expected exactly 65536 image bytes.", nameof(image));
        ReadOnlySpan<byte> signature = image.AsSpan(SignatureOffset, SignatureLength);
        if (new BigInteger(signature, isUnsigned: true, isBigEndian: true) >= new BigInteger(ImageSignatureModulus128, isUnsigned: true, isBigEndian: true)) return false;
        byte[] block = RSA.PublicOperation(signature.ToArray(), ImageSignatureModulus128);
        if (block[0] != 0 || block[1] != 1 || block[107] != 0) return false;
        for (int i = 2; i < 107; i++) if (block[i] != 0xFF) return false;
        byte[] digest = ComputeSignedRegionSha1(image);
        return CryptographicOperations.FixedTimeEquals(block.AsSpan(108, 20), digest);
    }

    /// <summary>SHA-1 over the exact 0xFCC0-byte image region hashed by the recorded PS2 code.</summary>
    public static byte[] ComputeSignedRegionSha1(byte[] image)
    {
        if (image == null || image.Length != ImageLength) throw new ArgumentException("Expected exactly 65536 image bytes.", nameof(image));
        return SHA1.HashData(image.AsSpan(0, SignedRegionLength));
    }

    /// <summary>
    /// Validate the signed image before deriving a trusted per-title key for
    /// the original first-response challenge. A server can cache this eight-byte
    /// result for this step; other DNAS checks still need independent validation.
    /// </summary>
    public static byte[] DeriveVerifiedFirstReplyKey(byte[] image)
    {
        if (!VerifySignature(image)) throw new CryptographicException("The DNAS image is not signed by the original image authority.");
        return DeriveFirstReplyKey(image);
    }

    /// <summary>Validate the original signed image, then derive the DES key for the actual S1 Challenge A.</summary>
    public static byte[] DeriveVerifiedFirstReplyKey(byte[] image, byte[] challenge8A)
    {
        if (!VerifySignature(image)) throw new CryptographicException("The DNAS image is not signed by the original image authority.");
        return DeriveFirstReplyKey(image, challenge8A);
    }

    /// <summary>Returns the 128-byte record immediately following the SHA-1-covered image region.</summary>
    public static byte[] GetSignatureRecord(byte[] image)
    {
        if (image == null || image.Length != ImageLength) throw new ArgumentException("Expected exactly 65536 image bytes.", nameof(image));
        return image.AsSpan(SignatureOffset, SignatureLength).ToArray();
    }


    /// <summary>
    /// Generates the exact 16-byte DES ciphertext the PS2 will decrypt in the
    /// first server response. The server must know the appropriate per-title
    /// image/key and choose a 16-byte expected client result; this does not
    /// implement the unknown original server-side choice of that result.
    /// </summary>
    public static byte[] EncryptFirstReplyChallenge(byte[] dnasImage, byte[] expectedClient16)
    {
        Guard.Size(expectedClient16, 16, nameof(expectedClient16));
        return DES.Encrypt(expectedClient16, DeriveFirstReplyKey(dnasImage));
    }

    /// <summary>Encrypt an arbitrary 16-byte plaintext with the key selected by the actual S1 Challenge A.</summary>
    public static byte[] EncryptFirstReplyChallenge(byte[] dnasImage, byte[] expectedClient16, byte[] challenge8A)
    {
        Guard.Size(expectedClient16, 16, nameof(expectedClient16));
        return DES.Encrypt(expectedClient16, DeriveFirstReplyKey(dnasImage, challenge8A));
    }

    /// <summary>
    /// Original retail S1 Challenge A key producer: 0x00531CA4..0x00531CBC calls
    /// 0x005323B8. A[4..7] indexes the signed disc DNAS image, A[0..3] are
    /// corresponding SHA-1 source lengths. Four SHA-1 calculations execute;
    /// the first digest is overwritten. The last three SHA-1 digests are XORed
    /// before the 20-to-8-byte native fold at 0x00532598..0x005325E8.
    /// Confirmed byte-exact against original and two mutated retail C2 requests.
    /// </summary>
    public static byte[] DeriveFirstReplyKey(byte[] dnasImage, byte[] challenge8A)
    {
        Guard.Size(challenge8A, 8, nameof(challenge8A));
        int requiredPrefix = Math.Max(challenge8A[5] + challenge8A[1], Math.Max(challenge8A[6] + challenge8A[2], challenge8A[7] + challenge8A[3]));
        if (dnasImage == null || dnasImage.Length < requiredPrefix) throw new ArgumentException("The supplied image prefix does not cover the Challenge A-selected SHA-1 ranges.", nameof(dnasImage));
        byte[] accumulated = SHA1.HashData(dnasImage.AsSpan(challenge8A[5], challenge8A[1]));
        byte[] third = SHA1.HashData(dnasImage.AsSpan(challenge8A[6], challenge8A[2]));
        byte[] fourth = SHA1.HashData(dnasImage.AsSpan(challenge8A[7], challenge8A[3]));
        for (int i = 0; i < 20; i++) accumulated[i] ^= (byte)(third[i] ^ fourth[i]);
        byte[] key8 = new byte[8];
        for (int i = 0; i < 8; i++) key8[i] = (byte)(accumulated[i] ^ accumulated[i + 8] ^ (i < 4 ? accumulated[i + 16] : 0));
        return key8;
    }

    /// <summary>
    /// Historical fixed-A regression: this exact 8-byte key applies only when
    /// Challenge A == 5A06EDAF7E46BAE6. For arbitrary live S1 challenges use
    /// DeriveFirstReplyKey(image, challenge8A), which is the native algorithm.
    /// </summary>
    public static byte[] DeriveFirstReplyKey(byte[] dnasImage)
    {
        if (dnasImage == null || dnasImage.Length < RequiredPrefixLength) throw new ArgumentException("Expected the original DNAS image bytes beginning at image offset zero.", nameof(dnasImage));
        byte[] digest175 = SHA1.HashData(dnasImage.AsSpan(0x0E6, 0x0AF));
        byte[] digest6 = SHA1.HashData(dnasImage.AsSpan(0x046, 0x006));
        byte[] digest237 = SHA1.HashData(dnasImage.AsSpan(0x0BA, 0x0ED));
        for (int i = 0; i < 20; i++) digest6[i] ^= digest237[i];
        return DES.FoldChallengeKey(digest175, digest6);
    }
}
