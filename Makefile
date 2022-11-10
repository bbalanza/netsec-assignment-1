.PHONY = build link clean

SOURCE_NAME= attack
COMPILER_FLAGS=  
LIBRARY_FLAGS= -lnet

all: build link clean

build: ${SOURCE_NAME}.c
	@echo "Compiling..."
	@gcc -c ${COMPILER_FLAGS} ${SOURCE_NAME}.c -o ${SOURCE_NAME}.o

link: build
	@echo "Linking..."
	@gcc ${SOURCE_NAME}.o -o ${SOURCE_NAME}_out ${LIBRARY_FLAGS}

clean: link
	@echo "Cleaning temporary files..."
	@rm ${SOURCE_NAME}.o