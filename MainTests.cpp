#include <iostream>
#define CATCH_CONFIG_RUNNER
#include "Catch.hpp"

int main(int argc, char* const argv[]) {
	std::cout << "Welcome to PolyHook -By- Stevemk14ebr" << std::endl;
	int result = Catch::Session().run(argc, argv);

	getchar();
	return result;
}

//Project layout type unit tests should go here, or console output things
//TEST_CASE("","")
//{
//    std::cout << "Welcome to PolyHook -By- Stevemk14ebr" << std::endl;
//}

