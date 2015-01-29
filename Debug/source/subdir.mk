################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../source/baseCryptoRandomStream.cpp \
../source/baseHash.cpp \
../source/baseRipemd.cpp \
../source/baseRipemd128X.cpp \
../source/baseRipemd160X.cpp \
../source/baseSha32.cpp \
../source/defaultCryptoRandomStream.cpp \
../source/hashSuite.cpp \
../source/ripemd128.cpp \
../source/ripemd160.cpp \
../source/ripemd256.cpp \
../source/ripemd320.cpp \
../source/sha1.cpp \
../source/sha224.cpp \
../source/sha256.cpp \
../source/sha384.cpp \
../source/sha512.cpp 

OBJS += \
./source/baseCryptoRandomStream.o \
./source/baseHash.o \
./source/baseRipemd.o \
./source/baseRipemd128X.o \
./source/baseRipemd160X.o \
./source/baseSha32.o \
./source/defaultCryptoRandomStream.o \
./source/hashSuite.o \
./source/ripemd128.o \
./source/ripemd160.o \
./source/ripemd256.o \
./source/ripemd320.o \
./source/sha1.o \
./source/sha224.o \
./source/sha256.o \
./source/sha384.o \
./source/sha512.o 

CPP_DEPS += \
./source/baseCryptoRandomStream.d \
./source/baseHash.d \
./source/baseRipemd.d \
./source/baseRipemd128X.d \
./source/baseRipemd160X.d \
./source/baseSha32.d \
./source/defaultCryptoRandomStream.d \
./source/hashSuite.d \
./source/ripemd128.d \
./source/ripemd160.d \
./source/ripemd256.d \
./source/ripemd320.d \
./source/sha1.d \
./source/sha224.d \
./source/sha256.d \
./source/sha384.d \
./source/sha512.d 


# Each subdirectory must supply rules for building sources it contributes
source/%.o: ../source/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -I"/home/DiceLock-Work/Development-Work/CPP/HashDigester-x/HashDigester-x/header" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


