#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/pkg/client.hpp"

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

    return 0;
}
