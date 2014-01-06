################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../autogensrc/saveFunc.c 

OBJS += \
./autogensrc/saveFunc.o 

C_DEPS += \
./autogensrc/saveFunc.d 


# Each subdirectory must supply rules for building sources it contributes
autogensrc/%.o: ../autogensrc/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


