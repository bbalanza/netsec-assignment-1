.PHONY = build link clean install

SOURCE_NAME= attack
COMPILER_FLAGS= 
LIBRARY_FLAGS= -lnet -lpcap 

all: ${SOURCE_NAME}.c install build link clean

install:
	@echo "Installing dependencies..."
	@sudo apt -qq install -y libpcap-dev libnet1-dev

build: 
	@echo "Compiling..."
	@gcc -c ${COMPILER_FLAGS} -g ${SOURCE_NAME}.c -o ${SOURCE_NAME}.o

link: build
	@echo "Linking..."
	@gcc ${SOURCE_NAME}.o -g -o ${SOURCE_NAME} ${LIBRARY_FLAGS}
	@sudo chmod 755 ${SOURCE_NAME}

clean: link
	@echo "Cleaning temporary files..."
	@rm ${SOURCE_NAME}.o
