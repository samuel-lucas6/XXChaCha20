/*
    XXChaCha20: ChaCha20 with a 224-bit nonce.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Security.Cryptography;
using Geralt;

namespace XXChaCha20DotNet;

public static class XXChaCha20
{
    public const int KeySize = ChaCha20.KeySize;
    public const int NonceSize = HChaCha20.NonceSize + ChaCha20.NonceSize;
    
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        if (nonce.Length != NonceSize) {
            throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long.");
        }
        Span<byte> subKey = stackalloc byte[ChaCha20.KeySize];
        HChaCha20.DeriveKey(subKey, key, nonce[..HChaCha20.NonceSize]);
        ChaCha20.Encrypt(ciphertext, plaintext, nonce[HChaCha20.NonceSize..], subKey);
        CryptographicOperations.ZeroMemory(subKey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        Encrypt(plaintext, ciphertext, nonce, key);
    }
}