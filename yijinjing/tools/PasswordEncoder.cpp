/**
 * Password encoding protection.
 * @Author cjiang (changhao.jiang@taurus.ai)
 * @since   Jan, 2018
 *  this file should not be open-sourced !!!
 */

#include <boost/program_options.hpp>
#include <string>
#include <iostream>
#include "PasswordUtil.hpp"

using namespace boost::program_options;

int main(int argc, char *argv[])
{
    options_description desc{"Options"};
    desc.add_options()
            ("help,h", "Help screen")
            ("password,p", value<std::string>(), "password");

    variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);
    if (vm.count("help"))
    {
        std::cout << desc << '\n';
        return 0;
    }
    if (! vm.count("password"))
    {
        std::cout << "please specify password!!!" << std::endl;
        return 0;
    }
    std::string password = vm["password"].as<std::string>();
    std::cout << "password: " << password << std::endl;

    printEncode(password);
}