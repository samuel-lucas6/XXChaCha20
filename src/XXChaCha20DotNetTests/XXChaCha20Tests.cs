using Microsoft.VisualStudio.TestTools.UnitTesting;
using XXChaCha20DotNet;

namespace XXChaCha20DotNetTests;

[TestClass]
public class XXChaCha20Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "5856752a377aff121d13e3383a5c143a72d1aecfd05c0d243a888e40ad6065f04ab28a56af9970caec794bb9c019a21cb5775ae8f9bced3d867b4a48a14f1ddeda51c3e893d2a9c9a8f2f08114860eebfb0f98ad7b56c871429fe0c5cd89c768bd7e43ac4eb0d4e3362feb8307d305d67333439137194b873d2a643771faaba882d14314ae9daed7bfc9e9f265e6b0b6806d6bf231bf6981104c6df5b8b9cb4f7cad2a8d6ac2975c2fe904e21dc4f850cc82b544b424107a7548c561861ec99709eab909d6d5e5c7dbac8645509080a995f41d951dd69995a137ead48359fd0ae1429c918dd5138f52a3a0e14e0606e58893ccbd5bede2594bb79c8b4bab5047323387d0eb3da6ddc74af6c99d9d5e6a65e50bc41b859ee8bbb8f685afa3d7f081776c32e5ea399e32df132599c2c636",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f505152535455565758596061",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (uint)0
        ];
        yield return
        [
            "ea56c1e4d7c8a3c1edb6b7964ac901eaea418ca076059e79449de2c780c6c935bd565bff48e39fec3b37f0d746d44dc73b250aaa21504595742864077de4a2e9889e5750eb9fa3d6edc9a6f73cb2f1b48b2277e978a1729f1c0266bcb7b38c007c8831c3649cdb582ae114f21dd6ff4dc2d18856b8775f743c4e8d4a9a4cc19a12b9a317d685eccccde8d54c4c88cca09ebb1c9350cb9395e47ef59d8b50bc18b24795968f9c5f9d5cb0ada5190f05ebc3c0b4f551f1bb5e56b587cb12e154482c2182d5a23da6ddc74ae3cd8c94412f68ab41c51e90dbeefaa9eacba3a2dfe0d2786b36e9e260c918ca156c8acccf6e428c268ac1d8dc86d8b15bc6c47474bcb4e2fd125e158df03a6fbd054b35dd0c15c0020a5b0df9c0ddf9332ab7081a31440f06bf62658ea7a683d7fefb1038a3",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f505152535455565758596061",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (uint)1
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [XXChaCha20.BlockSize + 1, XXChaCha20.BlockSize, XXChaCha20.NonceSize, XXChaCha20.KeySize, (uint)0];
        yield return [XXChaCha20.BlockSize - 1, XXChaCha20.BlockSize, XXChaCha20.NonceSize, XXChaCha20.KeySize, (uint)0];
        yield return [XXChaCha20.BlockSize, XXChaCha20.BlockSize, XXChaCha20.NonceSize + 1, XXChaCha20.KeySize, (uint)0];
        yield return [XXChaCha20.BlockSize, XXChaCha20.BlockSize, XXChaCha20.NonceSize - 1, XXChaCha20.KeySize, (uint)0];
        yield return [XXChaCha20.BlockSize, XXChaCha20.BlockSize, XXChaCha20.NonceSize, XXChaCha20.KeySize + 1, (uint)0];
        yield return [XXChaCha20.BlockSize, XXChaCha20.BlockSize, XXChaCha20.NonceSize, XXChaCha20.KeySize - 1, (uint)0];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, XXChaCha20.KeySize);
        Assert.AreEqual(28, XXChaCha20.NonceSize);
        Assert.AreEqual(64, XXChaCha20.BlockSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, uint counter)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        XXChaCha20.Encrypt(c, p, n, k, counter);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, uint counter)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XXChaCha20.Encrypt(c, p, n, k, counter));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, uint counter)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        XXChaCha20.Decrypt(p, c, n, k, counter);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, uint counter)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => XXChaCha20.Decrypt(p, c, n, k, counter));
    }
}
