using System;

namespace DNAS;

/// <summary>Client-side image verification. Server authentication never loads a client module.</summary>
public static class NativeClientReadiness
{
    public static bool VerifyImage(byte[] image) => image != null && image.Length == Image.ImageLength && Image.VerifySignature(image);

    public static uint Initialize(byte[] image)
    {
        if (!VerifyImage(image)) throw new System.Security.Cryptography.CryptographicException("DNAS image signature verification failed.");
        return 1;
    }
}
