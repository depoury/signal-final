#pragma once

#include <iostream>
#include <mutex>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

struct Client_Ratchet_State {
public:
    Client_Ratchet_State() {
      this->Ns = CryptoPP::Integer::Zero();
      this->Nr = CryptoPP::Integer::Zero();
      this->PN = CryptoPP::Integer::Zero();
      this->MKSKIPPED = {};
    }
    SecByteBlock RK;
    SecByteBlock CKs;
    SecByteBlock CKr;
    CryptoPP::Integer Ns;
    CryptoPP::Integer Nr;
    CryptoPP::Integer PN;
    std::map<CryptoPP::Integer, std::vector<std::tuple<SecByteBlock, SecByteBlock, SecByteBlock>>> MKSKIPPED;
};

class Client
{
public:
    Client(std::shared_ptr<NetworkDriver> network_driver,
           std::shared_ptr<CryptoDriver> crypto_driver);
    void prepare_keys(CryptoPP::DH DH_obj,
                      CryptoPP::SecByteBlock DH_private_value,
                      CryptoPP::SecByteBlock DH_other_public_value,
                      bool send);
    Message_Message send(std::string plaintext);
    std::pair<std::string, bool> receive(const Message_Message &ciphertext);
    void run(std::string command);
    void HandleKeyExchange(std::string command);

private:
    void ReceiveThread();
    void SendThread();

    // wrapper
    void SerializeSend(Serializable *msg);
    Client_Ratchet_State state;

    std::mutex mtx;

    std::shared_ptr<CLIDriver> cli_driver;
    std::shared_ptr<CryptoDriver> crypto_driver;
    std::shared_ptr<NetworkDriver> network_driver;
    SecByteBlock HMAC_key;

    // DH Ratchet Fields
    DHParams_Message DH_params;
    bool DH_switched;
    SecByteBlock DH_current_private_value;
    SecByteBlock DH_current_public_value;
    SecByteBlock DH_last_other_public_value;
};
