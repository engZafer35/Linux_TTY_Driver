
RM := rm -rf

all: test_basic

%: %.c
	gcc -o $@ $^ -I .. -Wall

test_basic: test_basic.c
	gcc -o $@ $^ -I .. -Wall

# Other Targets
clean:
	-@echo "Make Clean"
	-@echo ' '
	-$(RM) test_basic

.PHONY: all clean dependents post-build
