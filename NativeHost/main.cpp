#include <iostream>

int main()
{
    std::cout << "[Host] Enter \"q\" to exit." << std::endl;
    while (std::cin.get() != 'q') {}
    return 0;
}
