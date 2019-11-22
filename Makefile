OPENSSL_DIR := /mnt/ssd/msopiha/repo/BMW/openssl-1.1.1d
INCLUDES = -I$(OPENSSL_DIR)/include
all:
	g++ -std=c++11 -Wall $(INCLUDES) main.cpp -o app -L. $(OPENSSL_DIR)/libcrypto.a -ldl -lpthread
