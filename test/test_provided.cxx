#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <string>
#include "doctest/doctest.h"
#include "../include/drivers/crypto_driver.hpp"
#include "../include/drivers/network_driver.hpp"
#include "../include/pkg/client.hpp"
#include "../include-shared/colors.hpp"
#include "../include-shared/util.hpp"

TEST_CASE("DH Key Exchange")
{ 
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();

    // Create client then run network, crypto, and cli.
    Client Alice = Client(network_driver, crypto_driver);
    Client Bob = Client(network_driver, crypto_driver);

    DHParams_Message DH_params = crypto_driver->DH_generate_params();
    auto [dh_obj, alice_prv, alice_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [dh_obj2, bob_prv, bob_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh, alice_rk_prv, alice_rk_pub] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh2, bob_rk_prv, bob_rk_pub] = crypto_driver->DH_initialize(DH_params);

    Alice.EvalKeyExchange("listen", DH_params, dh_obj, rk_dh, alice_prv, alice_ppk, alice_rk_prv, alice_rk_pub,
                          bob_ppk, bob_rk_pub);
    Bob.EvalKeyExchange("connect", DH_params, dh_obj2, rk_dh2, bob_prv, bob_ppk, bob_rk_prv, bob_rk_pub,
                        alice_ppk, alice_rk_pub);

    CHECK(byteblock_to_integer(Alice.state.RK) == byteblock_to_integer(Bob.state.RK));
}


TEST_CASE("Normal message listener first")
{ 
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();

    // Create client then run network, crypto, and cli.
    Client Alice = Client(network_driver, crypto_driver);
    Client Bob = Client(network_driver, crypto_driver);

    DHParams_Message DH_params = crypto_driver->DH_generate_params();
    auto [dh_obj, alice_prv, alice_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [dh_obj2, bob_prv, bob_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh, alice_rk_prv, alice_rk_pub] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh2, bob_rk_prv, bob_rk_pub] = crypto_driver->DH_initialize(DH_params);

    Alice.EvalKeyExchange("listen", DH_params, dh_obj, rk_dh, alice_prv, alice_ppk, alice_rk_prv, alice_rk_pub,
                          bob_ppk, bob_rk_pub);
    Bob.EvalKeyExchange("connect", DH_params, dh_obj2, rk_dh2, bob_prv, bob_ppk, bob_rk_prv, bob_rk_pub,
                        alice_ppk, alice_rk_pub);

    std::pair<std::string, bool> tmp;
    std::string Alice_msg1 = "Hello";
    tmp = Bob.receive(Alice.send(Alice_msg1));
    CHECK(Alice_msg1.compare(tmp.first)==0);
    CHECK(tmp.second);

    std::string Alice_msg2 = "Hello again";
    tmp = Bob.receive(Alice.send(Alice_msg2));
    CHECK(Alice_msg2.compare(tmp.first)==0);
    CHECK(tmp.second);
    
    std::string Bob_msg1 = "Hello back";
    tmp = Alice.receive(Bob.send(Bob_msg1));
    CHECK(Bob_msg1.compare(tmp.first)==0);
    CHECK(tmp.second);
    
    std::string Bob_msg2 = "How are you";
    tmp = Alice.receive(Bob.send(Bob_msg2));
    CHECK(Bob_msg2.compare(tmp.first)==0);
    CHECK(tmp.second);
    
    std::string Alice_msg3 = "Good";
    tmp = Bob.receive(Alice.send(Alice_msg3));
    CHECK(Alice_msg3.compare(tmp.first)==0);
    CHECK(tmp.second);

}



TEST_CASE("Normal message connecter first")
{ 
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();

    // Create client then run network, crypto, and cli.
    Client Alice = Client(network_driver, crypto_driver);
    Client Bob = Client(network_driver, crypto_driver);

    DHParams_Message DH_params = crypto_driver->DH_generate_params();
    auto [dh_obj, alice_prv, alice_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [dh_obj2, bob_prv, bob_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh, alice_rk_prv, alice_rk_pub] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh2, bob_rk_prv, bob_rk_pub] = crypto_driver->DH_initialize(DH_params);

    Alice.EvalKeyExchange("listen", DH_params, dh_obj, rk_dh, alice_prv, alice_ppk, alice_rk_prv, alice_rk_pub,
                          bob_ppk, bob_rk_pub);
    Bob.EvalKeyExchange("connect", DH_params, dh_obj2, rk_dh2, bob_prv, bob_ppk, bob_rk_prv, bob_rk_pub,
                        alice_ppk, alice_rk_pub);

    std::pair<std::string, bool> tmp;
    std::string Bob_msg1 = "Hello";
    tmp = Alice.receive(Bob.send(Bob_msg1));
    CHECK(Bob_msg1.compare(tmp.first)==0);
    CHECK(tmp.second);
    
    std::string Bob_msg2 = "Hello again";
    tmp = Alice.receive(Bob.send(Bob_msg2));
    CHECK(Bob_msg2.compare(tmp.first)==0);
    CHECK(tmp.second);

    std::string Alice_msg1 = "Hello back";
    tmp = Bob.receive(Alice.send(Alice_msg1));
    CHECK(Alice_msg1.compare(tmp.first)==0);
    CHECK(tmp.second);

    std::string Alice_msg2 = "How are you";
    tmp = Bob.receive(Alice.send(Alice_msg2));
    CHECK(Alice_msg2.compare(tmp.first)==0);
    CHECK(tmp.second);
    
    std::string Bob_msg3 = "Good";
    tmp = Alice.receive(Bob.send(Bob_msg3));
    CHECK(Bob_msg3.compare(tmp.first)==0);
    CHECK(tmp.second);

}