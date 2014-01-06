################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../dshellHook.c \
../itimer.c \
../priority.c \
../rlimit.c \
../utils.c 

OBJS += \
./dshellHook.o \
./itimer.o \
./priority.o \
./rlimit.o \
./utils.o 

C_DEPS += \
./dshellHook.d \
./itimer.d \
./priority.d \
./rlimit.d \
./utils.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


