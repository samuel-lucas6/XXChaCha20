using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using XXChaCha20DotNet;

namespace XXChaCha20DotNetTests;

[TestClass]
public class XXChaCha20Tests
{
    [TestMethod]
    public void ThoroughTest()
    {
        Span<byte> plaintext = Encoding.UTF8.GetBytes("The people who can destroy a thing, they control it.");
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> nonce = stackalloc byte[XXChaCha20.NonceSize];
        Span<byte> key = stackalloc byte[XXChaCha20.KeySize];
        
        XXChaCha20.Encrypt(ciphertext, plaintext, nonce, key);
        Assert.IsFalse(ciphertext.SequenceEqual(plaintext));
        
        Span<byte> decrypted = stackalloc byte[ciphertext.Length];
        XXChaCha20.Decrypt(decrypted, ciphertext, nonce, key);
        Assert.IsTrue(decrypted.SequenceEqual(plaintext));
    }
}