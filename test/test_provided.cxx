#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <string>
#include "doctest/doctest.h"
#include "../include/drivers/crypto_driver.hpp"
#include "../include/drivers/network_driver.hpp"
#include "../include/pkg/client.hpp"
#include "../include-shared/colors.hpp"
#include "../include-shared/util.hpp"

TEST_CASE("DH Root Key Exchange")
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
    
    std::string Bob_msg2 = "Hello again";
    tmp = Alice.receive(Bob.send(Bob_msg2));
    CHECK(Bob_msg2.compare(tmp.first)==0);

    std::string Alice_msg1 = "Hello back";
    tmp = Bob.receive(Alice.send(Alice_msg1));
    CHECK(Alice_msg1.compare(tmp.first)==0);

    std::string Alice_msg2 = "How are you";
    tmp = Bob.receive(Alice.send(Alice_msg2));
    CHECK(Alice_msg2.compare(tmp.first)==0);
    
    std::string Bob_msg3 = "Good";
    tmp = Alice.receive(Bob.send(Bob_msg3));
    CHECK(Bob_msg3.compare(tmp.first)==0);
}

TEST_CASE("Missed listener side")
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

    std::string Alice_msg1 = "Missed 1";
    Message_Message miss1 = Alice.send(Alice_msg1);
    std::string Alice_msg2 = "Missed 2";
    Message_Message miss2 = Alice.send(Alice_msg2);

    std::string Alice_msg3 = "Normal 1";
    tmp = Bob.receive(Alice.send(Alice_msg3));
    CHECK(Alice_msg3.compare(tmp.first)==0);

    tmp = Bob.receive(miss2);
    CHECK(Alice_msg2.compare(tmp.first)==0);

    tmp = Bob.receive(miss1);
    CHECK(Alice_msg1.compare(tmp.first)==0);
}


TEST_CASE("Missed connecter side")
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
    std::string Bob_msg1 = "Missed 1";
    Message_Message miss1 = Bob.send(Bob_msg1);
    std::string Bob_msg2 = "Missed 2";
    Message_Message miss2 = Bob.send(Bob_msg2);

    std::string Bob_msg3 = "Normal 1";
    tmp = Alice.receive(Bob.send(Bob_msg3));
    CHECK(Bob_msg3.compare(tmp.first)==0);

    tmp = Alice.receive(miss2);
    CHECK(Bob_msg2.compare(tmp.first)==0);
    tmp = Alice.receive(miss1);
    CHECK(Bob_msg1.compare(tmp.first)==0);
}



TEST_CASE("Missed both sides")
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

    std::string Alice_msg1 = "Normal 1";
    tmp = Bob.receive(Alice.send(Alice_msg1));
    CHECK(Alice_msg1.compare(tmp.first)==0);

    std::string Alice_msg2 = "Missed 2";
    Message_Message alice_miss_2 = Alice.send(Alice_msg2);

    std::string Alice_msg3 = "Normal 3";
    tmp = Bob.receive(Alice.send(Alice_msg3));
    CHECK(Alice_msg3.compare(tmp.first)==0);

    std::string Bob_msg1 = "Missed 1";
    Message_Message bob_miss_1 = Bob.send(Bob_msg1);

    std::string Bob_msg2 = "Normal 2";
    tmp = Alice.receive(Bob.send(Bob_msg2));
    CHECK(Bob_msg2.compare(tmp.first)==0);

    std::string Bob_msg3 = "Missed 3";
    Message_Message bob_miss_3 = Bob.send(Bob_msg3);

    std::string Alice_msg4 = "Normal 4";
    tmp = Bob.receive(Alice.send(Alice_msg4));
    CHECK(Alice_msg4.compare(tmp.first)==0);

    std::string Alice_msg5 = "Missed 5";
    Message_Message alice_miss_5 = Alice.send(Alice_msg5);

    std::string Bob_msg4 = "Normal 4";
    tmp = Alice.receive(Bob.send(Bob_msg4));
    CHECK(Bob_msg4.compare(tmp.first)==0);

    std::string Bob_msg5 = "Missed 5";
    Message_Message bob_miss_5 = Bob.send(Bob_msg5);

    std::string Bob_msg6 = "Normal 6";
    tmp = Alice.receive(Bob.send(Bob_msg6));
    CHECK(Bob_msg6.compare(tmp.first)==0);

    tmp = Bob.receive(alice_miss_2);
    CHECK(Alice_msg2.compare(tmp.first)==0);
    tmp = Bob.receive(alice_miss_5);
    CHECK(Alice_msg5.compare(tmp.first)==0);
    tmp = Alice.receive(bob_miss_1);
    CHECK(Bob_msg1.compare(tmp.first)==0);
    tmp = Alice.receive(bob_miss_3);
    CHECK(Bob_msg3.compare(tmp.first)==0);
    tmp = Alice.receive(bob_miss_5);
    CHECK(Bob_msg5.compare(tmp.first)==0);
}



TEST_CASE("Basic header security")
{ 
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();

    // Create client then run network, crypto, and cli.
    Client Alice = Client(network_driver, crypto_driver);
    Client Bob = Client(network_driver, crypto_driver);
    Client Charlie = Client(network_driver, crypto_driver);

    DHParams_Message DH_params = crypto_driver->DH_generate_params();
    auto [dh_obj, alice_prv, alice_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [dh_obj2, bob_prv, bob_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh, alice_rk_prv, alice_rk_pub] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh2, bob_rk_prv, bob_rk_pub] = crypto_driver->DH_initialize(DH_params);

    auto [dh_obj3, charlie_prv, charlie_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh3, charlie_rk_prv, charlie_rk_pub] = crypto_driver->DH_initialize(DH_params);

    Alice.EvalKeyExchange("listen", DH_params, dh_obj, rk_dh, alice_prv, alice_ppk, alice_rk_prv, alice_rk_pub,
                          bob_ppk, bob_rk_pub);
    Bob.EvalKeyExchange("connect", DH_params, dh_obj2, rk_dh2, bob_prv, bob_ppk, bob_rk_prv, bob_rk_pub,
                        alice_ppk, alice_rk_pub);
    Charlie.EvalKeyExchange("connect", DH_params, dh_obj3, rk_dh3, charlie_prv, charlie_ppk, charlie_rk_prv, charlie_rk_pub,
                        alice_ppk, alice_rk_pub);

    std::pair<std::string, bool> tmp;

    std::string Alice_msg1 = "Normal 1";
    tmp = Bob.receive(Alice.send(Alice_msg1));
    CHECK(Alice_msg1.compare(tmp.first)==0);

    std::string Alice_msg2 = "Normal 2";
    tmp = Bob.receive(Alice.send(Alice_msg2));
    CHECK(Alice_msg2.compare(tmp.first)==0);

    std::string Bob_msg1= "Normal 1";
    tmp = Alice.receive(Bob.send(Bob_msg1));
    CHECK(Bob_msg1.compare(tmp.first)==0);

    std::string Bob_msg2 = "Normal 2";
    tmp = Alice.receive(Bob.send(Bob_msg2));
    CHECK(Bob_msg2.compare(tmp.first)==0);

    std::string Charlie_msg1 = "Attack 1";
    tmp = Alice.receive(Charlie.send(Charlie_msg1));
    CHECK(tmp.second==false);
}


TEST_CASE("Basic DH security")
{ 
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();

    // Create client then run network, crypto, and cli.
    Client Alice = Client(network_driver, crypto_driver);
    Client Bob = Client(network_driver, crypto_driver);
    Client Charlie = Client(network_driver, crypto_driver);

    DHParams_Message DH_params = crypto_driver->DH_generate_params();
    auto [dh_obj, alice_prv, alice_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [dh_obj2, bob_prv, bob_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh, alice_rk_prv, alice_rk_pub] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh2, bob_rk_prv, bob_rk_pub] = crypto_driver->DH_initialize(DH_params);

    auto [dh_obj3, charlie_prv, charlie_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh3, charlie_rk_prv, charlie_rk_pub] = crypto_driver->DH_initialize(DH_params);

    Alice.EvalKeyExchange("listen", DH_params, dh_obj, rk_dh, alice_prv, alice_ppk, alice_rk_prv, alice_rk_pub,
                          bob_ppk, bob_rk_pub);
    Bob.EvalKeyExchange("connect", DH_params, dh_obj2, rk_dh2, bob_prv, bob_ppk, bob_rk_prv, bob_rk_pub,
                        alice_ppk, alice_rk_pub);
    Charlie.EvalKeyExchange("connect", DH_params, dh_obj3, rk_dh3, charlie_prv, charlie_ppk, alice_rk_prv, alice_rk_pub,
                        bob_ppk, bob_rk_pub);

    std::pair<std::string, bool> tmp;

    std::string Bob_msg1= "Normal 1";
    tmp = Alice.receive(Bob.send(Bob_msg1));
    CHECK(Bob_msg1.compare(tmp.first)==0);

    std::string Bob_msg2 = "Miss 2";
    Message_Message bob_miss_2 = Bob.send(Bob_msg2);

    std::string Alice_msg1 = "Normal 1";
    tmp = Bob.receive(Alice.send(Alice_msg1));
    CHECK(Alice_msg1.compare(tmp.first)==0);

    std::string Alice_msg2 = "Normal 2";
    tmp = Bob.receive(Alice.send(Alice_msg2));
    CHECK(Alice_msg2.compare(tmp.first)==0);

    std::string Bob_msg3 = "Normal 3";
    tmp = Alice.receive(Bob.send(Bob_msg3));
    CHECK(Bob_msg3.compare(tmp.first)==0);

    Message_Message Charlie_attack1 = Charlie.send("Attack 1");
    Message_Message Charlie_attack2 = Charlie.send("Attack 2");

    tmp = Alice.receive(Charlie_attack1);
    CHECK(tmp.second==false);

    tmp = Alice.receive(Charlie_attack2);
    CHECK(tmp.second==false);
}