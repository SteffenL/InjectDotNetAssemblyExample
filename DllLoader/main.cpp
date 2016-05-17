#include "Application.h"

#include <iostream>

int main()
{
    try {
        return Application().Run();
    }
    catch (std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        throw;
    }
}
