#include "main.hxx"
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

void print_help_msg(std::ostream& os = std::cout) {
    os << "Usage:\n"
       << "  respack <function> <path> [flags]\n"
       << "----------------------------------------\n"
       << "Functions:\n"
       << "  -p, --pack         Pack directory to .rvlt\n"
       << "  -u, --unpack       Unpack .rvlt archive\n"
       << "  -gk, --genkey      Generate a new random key\n"
       << "  -pgk, --packgenkey Pack and encrypt directory with a newly generated key\n"
       << "----------------------------------------\n"
       << "Flags:\n"
       << "  --key=<key>        Base64URL key to encrypt/decrypt\n"
       << "  -o, --output=<out> Custom output path for archive/folder\n"
       << "  -h, --help         Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help_msg(std::cerr);
        return 1;
    }

    std::string action = argv[1];

    if (action == "-h" || action == "--help") {
        print_help_msg(std::cout);
        return 0;
    }

    if (action == "-gk" || action == "--genkey") {
        std::vector<uint8_t> key = respack::gen_key();
        std::cout << respack::key_to_string(key) << "\n";
        return 0;
    }

    if (argc < 3) {
        std::cerr << "Error: Missing required path argument.\n\n";
        print_help_msg(std::cerr);
        return 1;
    }

    std::string target_path = argv[2];
    if (target_path.ends_with('/') || target_path.ends_with('\\'))
        target_path.pop_back();
    std::string key_str;
    std::string custom_output;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--key=", 0) == 0) {
            key_str = arg.substr(6);
        } else if (arg.rfind("--output=", 0) == 0) {
            custom_output = arg.substr(9);
        } else if (arg == "-o" && i + 1 < argc) {
            custom_output = argv[++i];
        }
    }

    respack::res result;

    if (action == "-p" || action == "--pack") {
        std::string out_pkg = custom_output.empty() ? (target_path + ".rvlt") : custom_output;

        if (!key_str.empty()) {
            std::vector<uint8_t> key = respack::key_from_string(key_str);
            result = respack::pack(target_path, out_pkg, key);
        } else {
            result = respack::pack(target_path, out_pkg);
        }

    } else if (action == "-pgk" || action == "--packgenkey") {
        std::string out_pkg = custom_output.empty() ? (target_path + ".rvlt") : custom_output;

        std::vector<uint8_t> key = respack::gen_key();
        std::string generated_key_str = respack::key_to_string(key);

        result = respack::pack(target_path, out_pkg, key);
        if (result) {
            std::cout << "Generated Key: " << generated_key_str << "\n";
        }

    } else if (action == "-u" || action == "--unpack") {
        std::string out_dir = custom_output;
        if (out_dir.empty()) {
            fs::path p(target_path);
            out_dir = p.stem().string();
        }

        if (!key_str.empty()) {
            std::vector<uint8_t> key = respack::key_from_string(key_str);
            result = respack::unpack(target_path, out_dir, key);
        } else {
            result = respack::unpack(target_path, out_dir);
        }

    } else {
        std::cerr << "Error: Unknown function '" << action << "'\n\n";
        print_help_msg(std::cerr);
        return 1;
    }

    if (!result) {
        std::cerr << "Error: " << result.message << "\n";
        return 1;
    }

    std::cout << "Success: " << result.message << "\n";
    return 0;
}