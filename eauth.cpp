#include "eauth.h"
#include <cpr/cpr.h>
#include "skCrypter.h"
#include <openssl/sha.h>
#include "rapidjson/document.h"

// Required configuration
std::string ACCOUNT_KEY; // Your account key goes here;
std::string APPLICATION_KEY; // Your application key goes here
std::string APPLICATION_ID; // Your application ID goes here;
std::string APPLICATION_VERSION; // Your application version goes here;

// Advanced configuration
const auto invalid_account_key_message = skCrypt("Invalid account key!");
const auto invalid_application_key_message = skCrypt("Invalid application key!");
const auto invalid_request_message = skCrypt("Invalid request!");
const auto outdated_version_message = skCrypt("Outdated version, please upgrade!");
const auto busy_sessions_message = skCrypt("Please try again later!");
const auto unavailable_session_message = skCrypt("Invalid session. Please re-launch the app!");
const auto used_session_message = skCrypt("Why did the computer go to therapy? Because it had a case of 'Request Repeatitis' and couldn't stop asking for the same thing over and over again!");
const auto overcrowded_session_message = skCrypt("Session limit exceeded. Please re-launch the app!");
const auto unauthorized_session_message = skCrypt("Unauthorized session.");
const auto expired_session_message = skCrypt("Your session has timed out. Please re-launch the app!");
const auto invalid_user_message = skCrypt("Incorrect login credentials!");
const auto invalid_file_message = skCrypt("Incorrect file credentials!");
const auto banned_user_message = skCrypt("Access denied!");
const auto invalid_path_message = skCrypt("Oops, the bytes of the file could not be written. Please check the path of the file!");
const auto incorrect_hwid_message = skCrypt("Hardware ID mismatch. Please try again with the correct device!");
const auto expired_user_message = skCrypt("Your subscription has ended. Please renew to continue using our service!");
const auto used_name_message = skCrypt("Username already taken. Please choose a different username!");
const auto invalid_key_message = skCrypt("Invalid key. Please enter a valid key!");
const auto upgrade_your_eauth_message = skCrypt("Upgrade your Eauth plan to exceed the limits!");
const bool consoleTitleWithAppName = true; // Change your console title to the app name

// Dynamic configuration (this refers to configuration settings that can be changed during runtime)
bool init = false;
bool login = false;
bool signup = false;

std::string session_id = std::string(skCrypt(""));
std::string app_status = std::string(skCrypt(""));
std::string app_name = std::string(skCrypt(""));
std::string logged_message = std::string(skCrypt(""));
std::string registered_message = std::string(skCrypt(""));
std::string error_message = std::string(skCrypt(""));

std::string rank = std::string(skCrypt(""));
std::string register_date = std::string(skCrypt(""));
std::string expire_date = std::string(skCrypt(""));
std::string hwid = std::string(skCrypt(""));
std::string user_hwid = std::string(skCrypt(""));

std::string file_to_download = std::string(skCrypt(""));

// Function takes an input string and calculates its SHA-512 hash using the OpenSSL library
std::string sha512(const std::string& input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

// Base64
char lookupTable[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                       'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                       'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                       'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                       'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                       'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                       'w', 'x', 'y', 'z', '0', '1', '2', '3',
                       '4', '5', '6', '7', '8', '9', '+', '/' };

char base64Decode(char c) {
    if (c == '=') {
        return 0;
    }
    else {
        for (int x = 0; x < 64; x++) {
            if (lookupTable[x] == c) {
                return (char)x;
            }
        }
        return 0;
    }
}

std::string base64Decode(const std::string& data) {
    int length, length2, length3;
    int blockCount;
    int paddingCount = 0;
    int dataLength = data.length();
    length = dataLength;
    blockCount = length / 4;
    length2 = blockCount * 3;

    for (int x = 0; x < 2; x++) {
        if (data[length - x - 1] == '=') {
            paddingCount++;
        }
    }

    char* buffer = new char[length];
    char* buffer2 = new char[length2];

    for (int x = 0; x < length; x++) {
        buffer[x] = base64Decode(data[x]);
    }

    for (int x = 0; x < blockCount; x++) {
        char b1 = buffer[x * 4 + 0];
        char b2 = buffer[x * 4 + 1];
        char b3 = buffer[x * 4 + 2];
        char b4 = buffer[x * 4 + 3];

        char c1 = (b1 << 2) | (b2 >> 4);
        char c2 = (b2 << 4) | (b3 >> 2);
        char c3 = (b3 << 6) | b4;

        buffer2[x * 3 + 0] = c1;
        buffer2[x * 3 + 1] = c2;
        buffer2[x * 3 + 2] = c3;
    }

    length3 = length2 - paddingCount;

    std::string result(buffer2, buffer2 + length3);

    delete[] buffer;
    delete[] buffer2;

    return result;
}

// Generate header token
std::string generateAuthToken(const std::string& message, const std::string& app_id) {
    // Get the current timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::string timestampStr = std::to_string(timestamp);

    // Remove the last 5 digits from the timestamp
    timestampStr = timestampStr.substr(0, timestampStr.length() - 2);

    // Concatenate the timestamp, message, and app_id
    std::string auth_token = timestampStr + message + app_id;

    return sha512(auth_token);
}

// Send post request to Eauth
std::string runRequest(auto params) {
    auto r = cpr::Post(cpr::Url{ std::string(skCrypt("https://eauth.us.to/api/1.1/")) },
        cpr::Body{ params },
        cpr::Header{ {std::string(skCrypt("Content-Type")), std::string(skCrypt("application/x-www-form-urlencoded"))}, {std::string(skCrypt("User-Agent")), std::string(skCrypt("e_a_u_t_h"))} });

    std::string json = r.text;
    rapidjson::Document doc;
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();

    if (message == std::string(skCrypt("init_success")) || message == std::string(skCrypt("login_success")) || message == std::string(skCrypt("register_success")) || message == std::string(skCrypt("var_grab_success"))) {
        if (generateAuthToken(r.text, APPLICATION_ID) != r.header[std::string(skCrypt("Authorization"))]) {
            exit(1);
        }
    }
    
    return r.text; // JSON response
}

// Get HWID
std::string getHWID() {
    char volumeName[MAX_PATH + 1] = { 0 };
    char fileSystemName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;

    if (GetVolumeInformationA("C:\\", volumeName, ARRAYSIZE(volumeName), &serialNumber, &maxComponentLen, &fileSystemFlags, fileSystemName, ARRAYSIZE(fileSystemName))) {
        return std::to_string(serialNumber);
    }
    else {
        exit(1);
    }
}

// Report error
void raiseError(auto error) {
    error_message = error;
}

// Initialization request
bool initRequest(std::string account_key, std::string application_key, std::string application_id, std::string application_version) {
    if (init) {
        return init;
    }

    ACCOUNT_KEY = account_key;
    APPLICATION_KEY = application_key;
    APPLICATION_ID = application_id;
    APPLICATION_VERSION = application_version;

    std::string init_data = std::string(skCrypt("sort=init&appkey="))+APPLICATION_KEY+ std::string(skCrypt("&acckey="))+ACCOUNT_KEY+ std::string(skCrypt("&version=")) + APPLICATION_VERSION + std::string(skCrypt("&hwid=")) +getHWID();
    std::string json = runRequest(init_data);
    rapidjson::Document doc;
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();
    if (message == std::string(skCrypt("init_success"))) {
        init = true;
        session_id = doc["session_id"].GetString();
        app_status = doc["app_status"].GetString();
        app_name = doc["app_name"].GetString();
        if (consoleTitleWithAppName)
            SetConsoleTitle(app_name.c_str());
        logged_message = doc["logged_message"].GetString();
        registered_message = doc["registered_message"].GetString();
    }
    else if (message == std::string(skCrypt("invalid_account_key"))) {
        raiseError(invalid_account_key_message);
    }
    else if (message == std::string(skCrypt("invalid_application_key"))) {
        raiseError(invalid_application_key_message);
    }
    else if (message == std::string(skCrypt("invalid_request"))) {
        raiseError(invalid_request_message);
    }
    else if (message == std::string(skCrypt("version_outdated"))) {
        std::string download_link = doc["download_link"].GetString();
        if (download_link != "") {
            // Open download link in web browser
            ShellExecute(NULL, "open", download_link.c_str(), NULL, NULL, SW_SHOWNORMAL);
        }
        raiseError(outdated_version_message);
    }
    else if (message == std::string(skCrypt("maximum_sessions_reached"))) {
        raiseError(busy_sessions_message);
    }
    else if (message == std::string(skCrypt("user_is_banned"))) {
        raiseError(banned_user_message);
    }
    else if (message == std::string(skCrypt("init_paused"))) {
        raiseError(doc["paused_message"].GetString());
    }

    return init;
}

// Login request
bool loginRequest(std::string username, std::string password, std::string key) {
    if (login) {
        return login;
    }

    if (key.length() > 0) {
        username = password = key;
        std::string register_data = std::string(skCrypt("sort=register&sessionid=")) + session_id + std::string(skCrypt("&username=")) + username + std::string(skCrypt("&password=")) + password + std::string(skCrypt("&key=")) + key + std::string(skCrypt("&hwid=")) + getHWID();
        std::string json = runRequest(register_data);
        rapidjson::Document doc;
        doc.Parse(json.c_str());

        std::string message = doc["message"].GetString();

        if (message == std::string(skCrypt("register_success")) || message == std::string(skCrypt("name_already_used"))) {
            login = true;
        }
        else {
            raiseError(invalid_key_message);
        }
    }
    std::string login_data = std::string(skCrypt("sort=login&sessionid=")) + session_id + std::string(skCrypt("&username=")) + username + std::string(skCrypt("&password=")) + password + std::string(skCrypt("&hwid=")) +getHWID();
    std::string json = runRequest(login_data);
    rapidjson::Document doc;
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();
    if (message == std::string(skCrypt("login_success"))) {
        login = true;
        rank = doc["rank"].GetString();
        register_date = doc["register_date"].GetString();
        expire_date = doc["expire_date"].GetString();
        std::string word = "later";
        std::stringstream ss(expire_date);
        std::string token;
        expire_date = "";
        while (ss >> token) {
            if (token != word) {
                expire_date += token + " ";
            }
        }
        expire_date.pop_back(); // remove the last word

        hwid = doc["hwid"].GetString();
    }
    else if (message == std::string(skCrypt("invalid_account_key"))) {
        raiseError(invalid_account_key_message);
    }
    else if (message == std::string(skCrypt("invalid_application_key"))) {
        raiseError(invalid_application_key_message);
    }
    else if (message == std::string(skCrypt("invalid_request"))) {
        raiseError(invalid_request_message);
    }
    else if (message == std::string(skCrypt("session_unavailable"))) {
        raiseError(unavailable_session_message);
    }
    else if (message == std::string(skCrypt("session_already_used"))) {
        raiseError(used_session_message);
    }
    else if (message == std::string(skCrypt("session_overcrowded"))) {
        raiseError(overcrowded_session_message);
    }
    else if (message == std::string(skCrypt("session_expired"))) {
        raiseError(expired_session_message);
    }
    else if (message == std::string(skCrypt("account_unavailable"))) {
        raiseError(invalid_user_message);
    }
    else if (message == std::string(skCrypt("user_is_banned"))) {
        raiseError(banned_user_message);
    }
    else if (message == std::string(skCrypt("hwid_incorrect"))) {
        raiseError(incorrect_hwid_message);
    }
    else if (message == std::string(skCrypt("subscription_expired"))) {
        raiseError(expired_session_message);
    }

    return login;
}

// Register request
bool registerRequest(std::string username, std::string password, std::string key) {
    if (signup) {
        return signup;
    }
    
    std::string register_data = std::string(skCrypt("sort=register&sessionid=")) + session_id + std::string(skCrypt("&username=")) + username + std::string(skCrypt("&password=")) + password + std::string(skCrypt("&key=")) + key + std::string(skCrypt("&hwid=")) + getHWID();
    std::string json = runRequest(register_data);
    rapidjson::Document doc;
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();
    if (message == std::string(skCrypt("register_success"))) {
        signup = true;
    }
    else if (message == std::string(skCrypt("invalid_account_key"))) {
        raiseError(invalid_account_key_message);
    }
    else if (message == std::string(skCrypt("invalid_request"))) {
        raiseError(invalid_request_message);
    }
    else if (message == std::string(skCrypt("session_unavailable"))) {
        raiseError(unavailable_session_message);
    }
    else if (message == std::string(skCrypt("session_already_used"))) {
        raiseError(used_session_message);
    }
    else if (message == std::string(skCrypt("session_overcrowded"))) {
        raiseError(overcrowded_session_message);
    }
    else if (message == std::string(skCrypt("session_expired"))) {
        raiseError(expired_session_message);
    }
    else if (message == std::string(skCrypt("account_unavailable"))) {
        raiseError(invalid_user_message);
    }
    else if (message == std::string(skCrypt("name_already_used"))) {
        raiseError(used_name_message);
    }
    else if (message == std::string(skCrypt("key_unavailable"))) {
        raiseError(invalid_key_message);
    }
    else if (message == std::string(skCrypt("user_is_banned"))) {
        raiseError(banned_user_message);
    }
    else if (message == std::string(skCrypt("maximum_users_reached"))) {
        raiseError(upgrade_your_eauth_message);
    }

    return signup;
}

// Download request
bool downloadRequest(std::string fileid) {
    std::string file_data = std::string(skCrypt("sort=download&sessionid=")) + session_id + std::string(skCrypt("&fileid=")) + fileid;
    std::string json = runRequest(file_data);
    rapidjson::Document doc;
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();
    if (message == std::string(skCrypt("download_success"))) {
        file_to_download = doc["bytes"].GetString();
        return true;
    }
    else if (message == std::string(skCrypt("invalid_account_key"))) {
        raiseError(invalid_account_key_message);
        return false;
    }
    else if (message == std::string(skCrypt("invalid_request"))) {
        raiseError(invalid_request_message);
        return false;
    }
    else if (message == std::string(skCrypt("session_unavailable"))) {
        raiseError(unavailable_session_message);
        return false;
    }
    else if (message == std::string(skCrypt("session_unauthorized"))) {
        raiseError(unauthorized_session_message);
        return false;
    }
    else if (message == std::string(skCrypt("session_expired"))) {
        raiseError(expired_session_message);
        return false;
    }
    else if (message == std::string(skCrypt("invalid_file"))) {
        raiseError(invalid_file_message);
        return false;
    }
}

// Write file
bool writeBytesToFile(std::string fileid, const std::string& filename, const std::string& path) {
    std::filesystem::create_directories(path); // Create the directory path if it doesn't exist
    
    if (!downloadRequest(fileid)) {
        return false;
    }

    std::string bytes = base64Decode(file_to_download);

    std::ofstream file(path + "/" + filename, std::ios::binary);
    if (file.is_open()) {
        file.write(bytes.data(), bytes.size());
        file.close();
        return true;
    }
    else {
        raiseError(invalid_path_message);
        return false;
    }
}
