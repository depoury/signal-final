#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <iostream>

#include "../include/drivers/crypto_driver.hpp"
#include "../include/drivers/network_driver.hpp"
#include "../include/pkg/client.hpp"
#include "../include-shared/colors.hpp"
/*
 * Usage: ./signal <accept|connect> [address] [port]
 * Ex: ./signal accept localhost 3000
 *     ./signal connect localhost 3000
 */
int main(int argc, char *argv[])
{
    // Connect to network driver.
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();

    // Create client then run network, crypto, and cli.
    Client Alice = Client(network_driver, crypto_driver);
    Client Bob = Client(network_driver, crypto_driver);

    DHParams_Message DH_params = crypto_driver->DH_generate_params();
    auto [dh_obj,  alice_prv, alice_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [dh_obj2, bob_prv, bob_ppk] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh,  alice_rk_prv, alice_rk_pub] = crypto_driver->DH_initialize(DH_params);
    auto [rk_dh2, bob_rk_prv, bob_rk_pub] = crypto_driver->DH_initialize(DH_params);

    Alice.EvalKeyExchange("listen", DH_params, dh_obj, rk_dh.
                          alice_prv, alice_ppk, alice_rk_prv, alice_rk_pub,
                          bob_ppk, bob_rk_pub);
    Bob.EvalKeyExchange("connect", DH_params, dh_obj2, rk_dh2.
                          bob_prv, bob_ppk, bob_rk_prv, bob_rk_pub,
                          alice_ppk, alice_rk_pub);

    if (Alice.state.RK == Bob.state.RK) std::cout << GREEN << "DH success" << RESET << std::endl;
    else std::cout << RED << "DH error" << RESET << std::endl;

    return 0;
}
