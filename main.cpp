#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>

#pragma comment(lib, "advapi32")

const std::string DB_FILE = "users.db";
const std::string ACL_FILE = "acl.db";
const std::vector<std::string> OBJECTS = {
    "object1.txt", "object2.txt", "object3.txt", "object4.txt", "object5.txt",
    "object6.txt", "object7.txt", "object8.txt", "object9.txt", "object10.txt"
};

using AccessControlList = std::map<std::string, std::map<std::string, std::string>>;

std::vector<BYTE> hashPassword(const std::string& login, const std::string& password) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::vector<BYTE> hashVal;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return hashVal;

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return hashVal;
    }

    std::string combined = login + password;
    CryptHashData(hHash, (BYTE*)combined.c_str(), combined.size(), 0);

    DWORD hashLen = 0;
    DWORD lenLen = sizeof(DWORD);
    CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashLen, &lenLen, 0);
    hashVal.resize(hashLen);
    CryptGetHashParam(hHash, HP_HASHVAL, hashVal.data(), &hashLen, 0);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return hashVal;
}

void saveUsersToFile(const std::map<std::string, std::vector<BYTE>>& users) {
    std::ofstream file(DB_FILE, std::ios::binary);
    size_t count = users.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& [login, hash] : users) {
        size_t loginLen = login.size(), hashLen = hash.size();
        file.write(reinterpret_cast<const char*>(&loginLen), sizeof(loginLen));
        file.write(login.c_str(), loginLen);
        file.write(reinterpret_cast<const char*>(&hashLen), sizeof(hashLen));
        file.write(reinterpret_cast<const char*>(hash.data()), hashLen);
    }
}

std::map<std::string, std::vector<BYTE>> loadUsersFromFile() {
    std::map<std::string, std::vector<BYTE>> users;
    std::ifstream file(DB_FILE, std::ios::binary);
    if (!file.is_open()) return users;

    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    for (size_t i = 0; i < count; ++i) {
        size_t loginLen, hashLen;
        file.read(reinterpret_cast<char*>(&loginLen), sizeof(loginLen));
        std::string login(loginLen, ' ');
        file.read(&login[0], loginLen);
        file.read(reinterpret_cast<char*>(&hashLen), sizeof(hashLen));
        std::vector<BYTE> hash(hashLen);
        file.read(reinterpret_cast<char*>(hash.data()), hashLen);
        users[login] = hash;
    }

    return users;
}

void saveACL(const AccessControlList& acl) {
    std::ofstream file(ACL_FILE);
    for (const auto& [object, users] : acl) {
        for (const auto& [user, rights] : users) {
            file << object << ' ' << user << ' ' << rights << '\n';
        }
    }
}

AccessControlList loadACL() {
    AccessControlList acl;
    std::ifstream file(ACL_FILE);
    std::string object, user, rights;
    while (file >> object >> user >> rights) {
        acl[object][user] = rights;
    }
    return acl;
}

bool hasRight(const std::string& rights, char right) {
    return rights.find(right) != std::string::npos;
}

void listObjects() {
    std::cout << "Available objects:\n";
    for (const auto& obj : OBJECTS) std::cout << " - " << obj << "\n";
}

void interactWithObject(const std::string& login, AccessControlList& acl) {
    listObjects();
    std::string obj, action;
    std::cout << "Enter object name: ";
    std::getline(std::cin, obj);

    if (std::find(OBJECTS.begin(), OBJECTS.end(), obj) == OBJECTS.end()) {
        std::cout << "No such object.\n";
        return;
    }

    if (acl[obj].find(login) == acl[obj].end()) {
        std::cout << "You have no access to this object.\n";
        return;
    }

    std::cout << "Enter action (read/write/grant): ";
    std::getline(std::cin, action);

    if (action == "read") {
        if (hasRight(acl[obj][login], 'r')) {
            std::ifstream f(obj);
            std::string line;
            std::cout << "Contents of " << obj << ":\n";
            while (std::getline(f, line)) std::cout << line << '\n';
        } else {
            std::cout << "Access denied.\n";
        }
    } else if (action == "write") {
        if (hasRight(acl[obj][login], 'w')) {
            std::ofstream f(obj, std::ios::app);
            std::string text;
            std::cout << "Enter text to append: ";
            std::getline(std::cin, text);
            f << login << ": " << text << "\n";
        } else {
            std::cout << "Access denied.\n";
        }
    } else if (action == "grant") {
        if (hasRight(acl[obj][login], 'o')) {
            std::string otherUser, newRights;
            std::cout << "Grant rights to (username): ";
            std::getline(std::cin, otherUser);
            std::cout << "Enter rights (r/w/o): ";
            std::getline(std::cin, newRights);
            acl[obj][otherUser] = newRights;
            std::cout << "Rights granted.\n";
        } else {
            std::cout << "Access denied.\n";
        }
    } else {
        std::cout << "Unknown action.\n";
    }
}

int main() {
    auto users = loadUsersFromFile();
    auto acl = loadACL();
    std::string login, password;

    std::cout << "[User Login / Registration]\n";
    std::cout << "Login: ";
    std::getline(std::cin, login);

    if (users.find(login) == users.end()) {
        std::cout << "User not found. Registering new user.\nEnter password: ";
        std::getline(std::cin, password);
        users[login] = hashPassword(login, password);
        saveUsersToFile(users);

        if (login == "admin") {
            for (const auto& obj : OBJECTS) {
                acl[obj][login] = "rwo";
            }
            std::cout << "Admin has been granted full access to all objects.\n";
        } else {
            std::cout << "No access granted to this user. Please wait for the admin to assign rights.\n";
        }

        saveACL(acl);
        std::cout << "Registration successful!\n";
    } else {
        int attempts = 0;
        while (attempts < 3) {
            std::cout << "Enter password: ";
            std::getline(std::cin, password);
            auto inputHash = hashPassword(login, password);
            if (inputHash == users[login]) {
                std::cout << "Access granted!\n";
                interactWithObject(login, acl);
                saveACL(acl);
                return 0;
            } else {
                std::cout << "Incorrect password.\n";
                attempts++;
            }
        }
        std::cout << "Access denied. Too many attempts.\n";
    }

    return 1;
}
