#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

std::vector<Message_Message> hold_up = {};

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.q
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver)
{
    // Make shared variables.
    this->cli_driver = std::make_shared<CLIDriver>();
    this->crypto_driver = crypto_driver;
    this->network_driver = network_driver;
    this->message_id = CryptoPP::Integer::Zero(); // We are not allowed to use this right?
    this->pn = CryptoPP::Integer::Zero();  // number in prev sending chain
    this->n = CryptoPP::Integer::Zero();  // number in current sending chain
    this->recv_n = CryptoPP::Integer::Zero(); // number of current receiving chain
    this->saved_keys = {};
}

void Client::UpdateAESKey(bool send)
{
    if (send) {
        this->Send_AES_key = this->crypto_driver->AES_generate_key(this->state.send_CHAIN_key);
        this->state.send_CHAIN_key = this->crypto_driver->CHAIN_update_key(this->state.send_CHAIN_key, 
                                                                             this->state.ROOT_key);
        this->message_id++;
        this->n++; // update sending chain length
    } else {
        this->Recv_AES_key = this->crypto_driver->AES_generate_key(this->state.recv_CHAIN_key);
        this->state.recv_CHAIN_key = this->crypto_driver->CHAIN_update_key(this->state.recv_CHAIN_key, 
                                                                             this->state.ROOT_key);
        this->recv_n++; // update receiving chain length
    }
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call DH_generate_shared_key
 * 2) Use the resulting key in AES_generate_key and HMAC_generate_key
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value,
                          bool send)
{
    SecByteBlock s = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
    this->state.ROOT_key = this->crypto_driver->ROOT_update_key(this->state.ROOT_key, s);
    if (send)
        this->state.send_CHAIN_key = this->crypto_driver->CHAIN_generate_key(this->state.ROOT_key);
    else 
        this->state.recv_CHAIN_key = this->crypto_driver->CHAIN_generate_key(this->state.ROOT_key);
    this->HMAC_key = this->crypto_driver->HMAC_generate_key(s);
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext)
{
    // Grab the lock to avoid race conditions between the receive and send threads
    // Lock will automatically release at the end of the function.
    std::unique_lock<std::mutex> lck(this->mtx);
    if (!this->DH_switched)
    {
        this->DH_switched = true;
        this->pn = this->n;
        this->n = CryptoPP::Integer::Zero();
        std::tuple<DH, SecByteBlock, SecByteBlock> DH_Tuple = this->crypto_driver->DH_initialize(this->DH_params);
        this->DH_current_private_value = std::get<1>(DH_Tuple);
        this->DH_current_public_value = std::get<2>(DH_Tuple);
        this->prepare_keys(
            std::get<0>(DH_Tuple),
            this->DH_current_private_value,
            this->DH_last_other_public_value, true);
    }
    this->UpdateAESKey(true); // update send key
    std::pair<std::string, SecByteBlock> aes = this->crypto_driver->AES_encrypt(
        this->Send_AES_key,
        std::move(plaintext));
    Message_Message msg;
    msg.iv = aes.second;
    msg.public_value = this->DH_current_public_value;
    msg.uuid = this->message_id;
    msg.number = this->n-1; // we always add 1 to n in UpdateAESKey, but the actual number should start from 0?
    msg.previous_chain_length = this->pn;
    msg.ciphertext = aes.first;
    msg.mac = this->crypto_driver->HMAC_generate(
        this->HMAC_key,
        concat_msg_fields(
            msg.iv,
            this->DH_current_public_value,
            msg.ciphertext));
    return msg;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(const Message_Message &ciphertext)
{
    std::unique_lock<std::mutex> lck(this->mtx);
    this->DH_switched = false;
    this->cli_driver->print_info("Received msg: " + std::to_string(ciphertext.uuid.ConvertToLong()));

    // if DH ratchet key changed, need to update receive CHAIN key
    if (ciphertext.public_value != this->DH_last_other_public_value && ciphertext.public_value != this->DH_prev_other_public_value)
    {   
        // check if there are missed messages
        if (this->recv_n < ciphertext.previous_chain_length)
            this->cli_driver->print_info("Missed message in prev recv chain");
        for (CryptoPP::Integer i = this->recv_n; i < ciphertext.previous_chain_length; i++)
        {   // save keys in the previous unfinished chain if any
            this->UpdateAESKey(false);
            this->saved_keys.emplace(
                std::make_pair(byteblock_to_integer(this->DH_last_other_public_value), i),
                std::tie(
                    this->Recv_AES_key,
                    this->HMAC_key));
        }
        this->DH_prev_other_public_value = this->DH_last_other_public_value;
        this->DH_last_other_public_value = ciphertext.public_value;
        this->prepare_keys(
            DH(
                this->DH_params.p,
                this->DH_params.q,
                this->DH_params.g),
            this->DH_current_private_value,
            this->DH_last_other_public_value, false);
        // this->pn = this->n;
        this->recv_n = CryptoPP::Integer::Zero();
    }
    SecByteBlock AES_key_to_use;
    SecByteBlock HMAC_key_to_use;
    SecByteBlock DH_key_to_use = ciphertext.public_value;
    
    if (ciphertext.public_value == this->DH_prev_other_public_value)
    {
        // This must be an out-of-order message
        // What if multiple rounds of DH change message are lost?
        auto saved = std::make_pair(byteblock_to_integer(ciphertext.public_value), ciphertext.number);
        std::tie(
            AES_key_to_use,
            HMAC_key_to_use) = this->saved_keys[saved];
        this->saved_keys.erase(saved);    
    }
    else
    {
        this->UpdateAESKey(false);
        if (this->recv_n < ciphertext.number) 
            this->cli_driver->print_info("Trying to catch up number");
        while (this->recv_n < ciphertext.number)
        {
            this->saved_keys.emplace(
                std::make_pair(byteblock_to_integer(this->DH_last_other_public_value), this->recv_n),
                std::tie(
                    this->Recv_AES_key,
                    this->HMAC_key));
            this->UpdateAESKey(false);
        }
        AES_key_to_use = this->Recv_AES_key;
        HMAC_key_to_use = this->HMAC_key;
    }

    bool verified = true;
    try {
        this->crypto_driver->HMAC_verify(
            HMAC_key_to_use,
            concat_msg_fields(
                ciphertext.iv,
                DH_key_to_use,
                ciphertext.ciphertext),
            ciphertext.mac);
    } catch (std::runtime_error &e) {
        this->cli_driver->print_info("HMAC verified failed");
        verified = false;
    }

    return {
        this->crypto_driver->AES_decrypt(
            AES_key_to_use,
            ciphertext.iv,
            ciphertext.ciphertext),
        verified};
}

/**
 * Run the client.
 */
void Client::run(std::string command)
{
    // Initialize cli_driver.
    this->cli_driver->init();

    // Run key exchange.
    this->HandleKeyExchange(command);

    // Start msgListener thread.
    boost::thread msgListener =
        boost::thread(boost::bind(&Client::ReceiveThread, this));
    msgListener.detach();

    // Start sending thread.
    this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`
 * `command` can be either "listen" or "connect"; the listener should read()
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command)
{
    // synchronize DH params
    if (std::equal(command.begin(), command.end(), "listen"))
    {
        this->DH_switched = false;
        std::vector<unsigned char> msg = this->network_driver->read();
        if (get_message_type(msg) != MessageType::DHParams_Message)
            throw std::runtime_error("HandleKeyExchange - Listener Expected a DHParams_Message");

        this->DH_params.deserialize(msg);
    }
    else if (std::equal(command.begin(), command.end(), "connect"))
    {
        this->DH_switched = true;
        this->DH_params = this->crypto_driver->DH_generate_params();
        this->SerializeSend(&this->DH_params);
    }
    else
    {
        throw std::runtime_error("HandleKeyExchange - Invalid Command");
    }
    // DH exchange
    std::tuple<DH, SecByteBlock, SecByteBlock> DH_Tuple = this->crypto_driver->DH_initialize(this->DH_params);
    this->DH_current_private_value = std::get<1>(DH_Tuple);
    this->DH_current_public_value = std::get<2>(DH_Tuple);

    PublicValue_Message pub_key_msg;
    pub_key_msg.public_value = this->DH_current_public_value;
    this->SerializeSend(&pub_key_msg);

    std::vector<unsigned char> their_pub_key_msg = this->network_driver->read();
    if (get_message_type(their_pub_key_msg) != MessageType::PublicValue)
        throw std::runtime_error("HandleKeyExchange - Listener Expected a PublicValue");
    PublicValue_Message their_pub_key;
    their_pub_key.deserialize(their_pub_key_msg);
    this->DH_last_other_public_value = their_pub_key.public_value;

    // Handle RK generation
    auto [rk_dh, rk_private, rk_public] = this->crypto_driver->DH_initialize(this->DH_params);
    PublicValue_Message rk_pub_key_msg;
    rk_pub_key_msg.public_value = rk_public;
    this->SerializeSend(&rk_pub_key_msg);

    PublicValue_Message their_rk_pub_key;
    std::vector<unsigned char> their_rk_pub_key_msg = this->network_driver->read();
    if (get_message_type(their_rk_pub_key_msg) != MessageType::PublicValue)
        throw std::runtime_error("HandleKeyExchangeRK - Listener Expected a PublicValue");
    their_rk_pub_key.deserialize(their_rk_pub_key_msg);
        
    this->state.ROOT_key = this->crypto_driver->DH_generate_shared_key(rk_dh, rk_private, their_rk_pub_key.public_value);
    
    // Generate initial keys
    this->prepare_keys(
        std::get<0>(DH_Tuple),
        this->DH_current_private_value,
        this->DH_last_other_public_value, true);
    this->state.recv_CHAIN_key = this->crypto_driver->CHAIN_generate_key(this->state.ROOT_key);
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread()
{
    while (true)
    {
        // Try reading data from the other user.
        std::vector<unsigned char> data;
        try
        {
            data = this->network_driver->read();
        }
        catch (std::runtime_error &_)
        {
            // Exit cleanly.
            this->cli_driver->print_left("Received EOF; closing connection");
            this->network_driver->disconnect();
            return;
        }

        // Deserialize, decrypt, and verify message.
        Message_Message msg;
        msg.deserialize(data);
        auto decrypted_data = this->receive(msg);
        if (!decrypted_data.second)
        {
            this->cli_driver->print_left("Received invalid HMAC; the following "
                                         "message may have been tampered with.");
            throw std::runtime_error("Received invalid MAC!");
        }
        this->cli_driver->print_left(std::get<0>(decrypted_data));
    }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread()
{
    std::string plaintext;
    while (true)
    {
        // Read from STDIN.
        std::getline(std::cin, plaintext);
        if (std::cin.eof())
        {
            this->cli_driver->print_left("Received EOF; closing connection");
            this->network_driver->disconnect();
            return;
        }

        // Encrypt and send message.
        if (plaintext != "")
        {
            Message_Message msg = this->send(plaintext);
            if (plaintext.find("TEST") != std::string::npos)
            {
                hold_up.push_back(msg);
                this->cli_driver->print_info("FAILED msg: " + std::to_string(msg.uuid.ConvertToLong()));
            }
            else
            {
                std::vector<unsigned char> data;
                msg.serialize(data);
                this->cli_driver->print_info("SEND msg: " + std::to_string(msg.uuid.ConvertToLong()));
                this->network_driver->send(data);
            }
        }
        else if (!hold_up.empty())
        {
            Message_Message msg = hold_up.back();
            hold_up.pop_back();
            std::vector<unsigned char> data;
            msg.serialize(data);
            this->cli_driver->print_info("RESEND msg: " + std::to_string(msg.uuid.ConvertToLong()));
            this->network_driver->send(data);
        }
        this->cli_driver->print_right(plaintext);
    }
}



void Client::SerializeSend(Serializable* msg)
{
    std::vector<unsigned char> data;
    msg->serialize(data);
    this->network_driver->send(data);
}