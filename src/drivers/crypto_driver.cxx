#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Returns (p, q, g) DH parameters. This function should:
 * 1) Initialize a `CryptoPP::AutoSeededRandomPool` object
 *    and a `CryptoPP::PrimeAndGenerator` object.
 * 2) Generate a prime p, sub-prime q, and generator g
 *    using `CryptoPP::PrimeAndGenerator::Generate(...)`
 *    with a `delta` of 1, a `pbits` of 512, and a `qbits` of 511.
 * 3) Store and return the parameters in a `DHParams_Message` object.
 * @return `DHParams_Message` object that stores Diffie-Hellman parameters
 */
DHParams_Message CryptoDriver::DH_generate_params()
{
    CryptoPP::AutoSeededRandomPool asrp = CryptoPP::AutoSeededRandomPool();
    CryptoPP::PrimeAndGenerator gen = CryptoPP::PrimeAndGenerator(1, asrp, 512, 511);
    DHParams_Message msg = DHParams_Message();
    msg.p = gen.Prime();
    msg.q = gen.SubPrime();
    msg.g = gen.Generator();
    return msg;
}

/**
 * @brief Generate DH keypair. This function should
 * 1) Create a DH object and `SecByteBlock`s for the private and public keys.
 * Use `DH_obj.PrivateKeyLength()` and `PublicKeyLength()` to get key sizes.
 * 2) Generate a DH keypair using the `GenerateKeyPair(...)` method.
 * @param DH_params Diffie-Hellman parameters
 * @return Tuple containing DH object, private value, public value.
 */
std::tuple<DH, SecByteBlock, SecByteBlock>
CryptoDriver::DH_initialize(const DHParams_Message &DH_params)
{
    DH dh = DH(DH_params.p, DH_params.q, DH_params.g);
    SecByteBlock privKey = SecByteBlock(dh.PrivateKeyLength());
    SecByteBlock pubKey = SecByteBlock(dh.PublicKeyLength());
    CryptoPP::AutoSeededRandomPool asrp;
    dh.GenerateKeyPair(asrp, privKey, pubKey);
    return {dh, privKey, pubKey};
}

/**
 * @brief Generates a shared secret. This function should
 * 1) Allocate space in a `SecByteBlock` of size `DH_obj.AgreedValueLength()`.
 * 2) Run `DH_obj.Agree(...)` to store the shared key in the allocated space.
 * 3) Throw a `std::runtime_error` if failed to agree.
 * @param DH_obj Diffie-Hellman object
 * @param DH_private_value user's private value for Diffie-Hellman
 * @param DH_other_public_value other user's public value for Diffie-Hellman
 * @return Diffie-Hellman shared key
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value)
{
    SecByteBlock shared = SecByteBlock(DH_obj.AgreedValueLength());
    if (DH_obj.Agree(
            shared,
            DH_private_value,
            DH_other_public_value,
            true))
    {
        return shared;
    }
    throw std::runtime_error("DH_generate_shared_key - Could not Agree");
}

/**
 * @brief Generates CHAIN key using HKDR with a salt.
 * @param Old_CHAIN_key The current chain key
 * @return CHAIN key
 */
SecByteBlock CryptoDriver::CHAIN_generate_key(const SecByteBlock &ROOT_key)
{
    std::string chain_salt_str("roots000");
    SecByteBlock chain_salt((const unsigned char *)(chain_salt_str.data()),
                            chain_salt_str.size());
    SecByteBlock key(ROOT_key.size());
    HKDF<SHA256> hkdf;
    assert(hkdf.DeriveKey(key, key.size(),
                          ROOT_key, ROOT_key.size(),
                          chain_salt, chain_salt.size(),
                          nullptr, 0) > 0);
    return key;
}

SecByteBlock CryptoDriver::CHAIN_update_key(const SecByteBlock &Old_CHAIN_key)
{
    std::string chain_salt_str("chain000");
    SecByteBlock chain_salt((const unsigned char *)(chain_salt_str.data()),
                            chain_salt_str.size());
    SecByteBlock key(Old_CHAIN_key.size());
    HKDF<SHA256> hkdf;
    assert(hkdf.DeriveKey(key, key.size(),
                          Old_CHAIN_key, Old_CHAIN_key.size(),
                          chain_salt, chain_salt.size(),
                          nullptr, 0) > 0);
    return key;
}

SecByteBlock CryptoDriver::ROOT_update_key(const SecByteBlock &Old_ROOT_key, const SecByteBlock &DH_shared)
{
    SecByteBlock key(Old_ROOT_key.size());
    HKDF<SHA256> hkdf;
    assert(hkdf.DeriveKey(key, key.size(),
                          Old_ROOT_key, Old_ROOT_key.size(),
                          DH_shared, DH_shared.size(),
                          nullptr, 0) > 0);
    return key;
}

SecByteBlock CryptoDriver::HEADER_update_key(const SecByteBlock &ROOT_key)
{
    std::string header_salt_str("header00");
    SecByteBlock header_salt((const unsigned char *)(header_salt_str.data()),
                            header_salt_str.size());
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    HKDF<SHA256> hkdf;
    assert(hkdf.DeriveKey(key, key.size(),
                          ROOT_key, ROOT_key.size(),
                          header_salt, header_salt.size(),
                          nullptr, 0) > 0);
    return key;
}
/**
 * @brief Updates Chain key using HKDR with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `AES::DEFAULT_KEYLENGTH`.
 * 2) Use a `HKDF<SHA256>` to derive and return a key for AES using the provided
 * salt. See the `DeriveKey` function.
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key Diffie-Hellman shared key
 * @return AES key
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &CHAIN_key)
{
    std::string aes_salt_str("salt0000");
    SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                          aes_salt_str.size());
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    HKDF<SHA256> hkdf;
    assert(hkdf.DeriveKey(key, key.size(),
                          CHAIN_key, CHAIN_key.size(),
                          aes_salt, aes_salt.size(),
                          nullptr, 0) > 0);
    return key;
}

/**
 * @brief Encrypts the given plaintext. This function should:
 * 1) Initialize `CBC_Mode<AES>::Encryption` using GetNextIV and SetKeyWithIV.
 * 1.5) IV should be of size AES::BLOCKSIZE
 * 2) Run the plaintext through a `StreamTransformationFilter` using
 * `AES_encryptor`.
 * 3) Return ciphertext and iv used in encryption or throw a
 * `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param plaintext text to encrypt
 * @return Pair of ciphertext and iv
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext)
{
    try
    {
        CBC_Mode<AES>::Encryption c;
        CryptoPP::AutoSeededRandomPool asrp;
        SecByteBlock iv(AES::BLOCKSIZE);
        c.GetNextIV(asrp, iv);
        c.SetKeyWithIV(key, key.size(), iv);
        std::string ciphertext;
        StringSource _(
            plaintext,
            true,
            new StreamTransformationFilter(
                c,
                new StringSink(ciphertext)));
        return {ciphertext, iv};
    }
    catch (CryptoPP::Exception &e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << "This function was likely called with an incorrect shared key."
                  << std::endl;
        throw std::runtime_error("CryptoDriver AES encryption failed.");
    }
}

/**
 * @brief Decrypts the given ciphertext, encoded as a hex string. This function
 * should:
 * 1) Initialize `CBC_Mode<AES>::Decryption` using SetKeyWithIV on the key and
 * iv. 2) Run the decoded ciphertext through a `StreamTransformationFilter`
 * using `AES_decryptor`.
 * 3) Return the plaintext or throw a `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param iv iv used in encryption
 * @param ciphertext text to decrypt
 * @return decrypted message
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext)
{
    try
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        std::string plaintext;
        StringSource _(
            ciphertext,
            true,
            new StreamTransformationFilter(
                d,
                new StringSink(plaintext)));
        return plaintext;
    }
    catch (CryptoPP::Exception &e)
    {
      /*
        // This is expected to fail in the attempted decryptions of out-of-order headers so we
        // silence the warning
        std::cerr << e.what() << std::endl;
        std::cerr << "This function was likely called with an incorrect shared key."
                  << std::endl;
      */
        throw std::runtime_error("CryptoDriver AES decryption failed.");
    }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `SHA256::BLOCKSIZE` for the shared key.
 * 2) Use a `HKDF<SHA256>` to derive and return a key for HMAC using the
 * provided salt. See the `DeriveKey` function.
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key shared key from Diffie-Hellman
 * @return HMAC key
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key)
{
    std::string hmac_salt_str("salt0001");
    SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                           hmac_salt_str.size());
    SecByteBlock key(SHA256::BLOCKSIZE);
    HKDF<SHA256> hkdf;
    assert(hkdf.DeriveKey(key, key.size(),
                          DH_shared_key, DH_shared_key.size(),
                          hmac_salt, hmac_salt.size(),
                          nullptr, 0) > 0);
    return key;
}

/**
 * @brief Given a ciphertext, generates an HMAC. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the ciphertext through a `HashFilter` to generate an HMAC.
 * 3) Throw `std::runtime_error`upon failure.
 * @param key HMAC key
 * @param ciphertext message to tag
 * @return HMAC (Hashed Message Authentication Code)
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext)
{
    try
    {
        HMAC<SHA256> hmac(key, key.size());
        std::string mac;
        StringSource _(
            ciphertext,
            true,
            new HashFilter(
                hmac,
                new StringSink(mac)));
        return mac;
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << e.what() << std::endl;
        throw std::runtime_error("CryptoDriver HMAC generation failed.");
    }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the message through a `HashVerificationFilter` to verify the HMAC.
 * 3) Throw `std::runtime_error`upon failure.
 * @param key HMAC key
 * @param ciphertext message to verify
 * @param mac associated MAC
 * @return true if MAC is valid, else false
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac)
{
    const int flags = HashVerificationFilter::THROW_EXCEPTION |
                      HashVerificationFilter::HASH_AT_END;
    try
    {
        HMAC<SHA256> hmac(key, key.size());
        StringSource _(
            ciphertext + mac,
            true,
            new HashVerificationFilter(
                hmac,
                nullptr,
                flags));
    }
    catch (const CryptoPP::Exception &e)
    {
        std::cerr << e.what() << std::endl;
        throw std::runtime_error("CryptoDriver HMAC verification failed.");
    }
    return true;
}
