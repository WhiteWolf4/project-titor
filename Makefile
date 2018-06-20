#
# Makefile to compile Project Titor
#

SRC_DIR := src
OBJ_DIR := obj
SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_FILES))
CPPFLAGS=-Iinclude/
LDLIBS=$(shell pkg-config  --cflags --libs libcrypto++)


titor: $(OBJ_FILES)
	g++ -Wall -Wextra -g3 -std=c++11 $(CPPFLAGS) -o $@ titor.cpp $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp object
	g++ -Wall -Wextra -g3 -std=c++11 $(CPPFLAGS) -c $< -o $@ $(LDLIBS)

object:
	mkdir -p obj

clean:
	rm -rf obj
	rm -f titor
