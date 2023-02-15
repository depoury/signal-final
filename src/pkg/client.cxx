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

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.q
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call DH_generate_shared_key
 * 2) Use the resulting key in AES_generate_key and HMAC_generate_key
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  SecByteBlock s = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
  this->AES_key = this->crypto_driver->AES_generate_key(s);
  this->HMAC_key = this->crypto_driver->HMAC_generate_key(s);
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  if (!this->DH_switched) {
    this->DH_switched = true;
    std::tuple<DH, SecByteBlock, SecByteBlock> DH_Tuple = this->crypto_driver->DH_initialize(this->DH_params);
    this->DH_current_private_value = std::get<1>(DH_Tuple);
    this->DH_current_public_value = std::get<2>(DH_Tuple);
    this->prepare_keys(
        std::get<0>(DH_Tuple),
        this->DH_current_private_value,
        this->DH_last_other_public_value
        );
  }
  std::pair<std::string, SecByteBlock> aes = this->crypto_driver->AES_encrypt(
      this->AES_key,
      std::move(plaintext)
      );
  Message_Message msg;
  msg.iv = aes.second;
  msg.public_value = this->DH_current_public_value;
  msg.ciphertext = aes.first;
  msg.mac = this->crypto_driver->HMAC_generate(
      this->HMAC_key,
      msg.ciphertext
      );
  return msg;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message ciphertext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  if (this->DH_switched) {
    this->DH_switched = false;
  }
  if (ciphertext.public_value != this->DH_last_other_public_value) {
    this->DH_last_other_public_value = ciphertext.public_value;
    std::tuple<DH, SecByteBlock, SecByteBlock> DH_Tuple = this->crypto_driver->DH_initialize(this->DH_params);
    this->DH_current_private_value = std::get<1>(DH_Tuple);
    this->DH_current_public_value = std::get<2>(DH_Tuple);
    this->prepare_keys(
        std::get<0>(DH_Tuple),
        this->DH_current_private_value,
        this->DH_last_other_public_value
    );
  }

  std::pair<std::string, bool> ret;

  if (!this->crypto_driver->HMAC_verify(
      this->HMAC_key,
      ciphertext.ciphertext,
      ciphertext.mac
      )) {
    ret.first = "";
    ret.second = false;
    return ret;
  }
  ret.first = this->crypto_driver->AES_decrypt(
      this->AES_key,
      ciphertext.iv,
      ciphertext.ciphertext
      );
  ret.second = true;
  return ret;
}

/**
 * Run the client.
 */
void Client::run(std::string command) {
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
void Client::HandleKeyExchange(std::string command) {
  if (std::equal(command.begin(), command.end(), "listen")) {
    this->DH_switched = false;
    std::vector<unsigned char> msg = this->network_driver->read();
    if (get_message_type(msg) != MessageType::DHParams_Message) {
      throw std::runtime_error("HandleKeyExchange - Listener Expected a DHParams_Message");
    }
    this->DH_params.deserialize(msg);
  } else if (std::equal(command.begin(), command.end(), "connect")) {
    this->DH_switched = true;
    this->DH_params = this->crypto_driver->DH_generate_params();
    std::vector<unsigned char> msg;
    this->DH_params.serialize(msg);
    this->network_driver->send(msg);
  } else {
    throw std::runtime_error("HandleKeyExchange - Invalid Command");
  }
  //std::cout << "Initialising DH" << std::endl;
  std::tuple<DH, SecByteBlock, SecByteBlock> DH_Tuple = this->crypto_driver->DH_initialize(this->DH_params);
  //std::cout << "DH Initialised" << std::endl;
  this->DH_current_private_value = std::get<1>(DH_Tuple);
  this->DH_current_public_value = std::get<2>(DH_Tuple);

  std::vector<unsigned char> my_pub_key;
  PublicValue_Message pub_key_msg;
  pub_key_msg.public_value = this->DH_current_public_value;
  pub_key_msg.serialize(my_pub_key);
  this->network_driver->send(my_pub_key);

  std::vector<unsigned char> their_pub_key_msg = this->network_driver->read();
  if (get_message_type(their_pub_key_msg) != MessageType::PublicValue) {
    throw std::runtime_error("HandleKeyExchange - Listener Expected a PublicValue");
  }
  PublicValue_Message their_pub_key;
  their_pub_key.deserialize(their_pub_key_msg);
  this->DH_last_other_public_value = their_pub_key.public_value;

  std::cout << "Made it here!" << std::endl;

  this->prepare_keys(
      std::get<0>(DH_Tuple),
      this->DH_current_private_value,
      this->DH_last_other_public_value
      );
  std::cout << "Key exchange complete!" << std::endl;
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
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
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}
