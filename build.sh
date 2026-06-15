cd external/libbpf/src
make
sudo make install

cd ../../xdp-tools
make
sudo make install

cd ../..
mkdir build
cd build
cmake ..
make