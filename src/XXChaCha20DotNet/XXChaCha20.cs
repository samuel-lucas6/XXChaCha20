using System.Security.Cryptography;
using Geralt;

namespace XXChaCha20DotNet;

public static class XXChaCha20
{
    public const int KeySize = ChaCha20.KeySize;
    public const int NonceSize = HChaCha20.NonceSize + ChaCha20.NonceSize;
    public const int BlockSize = ChaCha20.BlockSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize];
        HChaCha20.DeriveKey(subkey, key, nonce[..HChaCha20.NonceSize]);

        ChaCha20.Encrypt(ciphertext, plaintext, nonce[HChaCha20.NonceSize..], subkey, counter);
        CryptographicOperations.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0)
    {
        Encrypt(plaintext, ciphertext, nonce, key, counter);
    }
}
