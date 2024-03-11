Get the wallet of your dream with the Vanity Address Generator for Ethereum.


Virtual Machine:

apt-get update
apt-get install -y libsecp256k1-dev libssl-dev g++
git clone https://github.com/djanssan/vanity-address-generator.git
cd vanity-address-generator/
g++ -o myscript vanity_w_speed.cpp -lsecp256k1 -lcrypto -lssl -std=c++11 -pthread
./myscript




On Mac:

g++ -std=c++11 -o vanity_address_generator vanity_w_speed.cpp -I/opt/homebrew/Cellar/secp256k1/0.4.1/include -L/opt/homebrew/Cellar/secp256k1/0.4.1/lib -lsecp256k1 -I/opt/homebrew/include -L/opt/homebrew/lib -lcrypto -pthread
