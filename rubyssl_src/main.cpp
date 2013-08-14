#include <iostream>

int main(int argc, char *argv[])
{
    std::cerr << "test" << std::endl;
    return 0;
}

extern "C" {
    int c_test(int i) {
        std::cerr << "i:" << i << std::endl;
	i+= 5;
	return ++i;
    }
}


