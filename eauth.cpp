#define CURL_STATICLIB
#include "eauth.h"
#include "skCrypter.h"
#include "sha/sha512.hpp"
#include "rapidjson/document.h"
#include <__msvc_chrono.hpp>
#include <filesystem>
#include <iostream>
#include <fstream>
#include "curl/curl.h"

#pragma comment(lib, "libcurl_a.lib")

#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wldap32.lib" )
#pragma comment(lib, "crypt32.lib" )

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
std::string hash(const std::string input) {
    return hmac_hash::sha512(input);
}

// Generate header token
std::string generateAuthToken(const std::string& message, const std::string& app_id) {
    // Get the current timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::string timestampStr = std::to_string(timestamp);

    // Remove the last 2 digits from the timestamp
    timestampStr = timestampStr.substr(0, timestampStr.length() - 6);

    // Concatenate the timestamp, message, and app_id
    std::string auth_token = timestampStr + message + app_id;

    return hash(auth_token);
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Send post request to Eauth
std::string runRequest(auto params) {

    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::string headerData;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://eauth.us.to/api/1.1/"); // Replace with your URL
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str()); // Replace with your POST data
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "e_a_u_t_h"); // Set user agent
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headerData);
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded"); // Set content type
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "cURL error: " << curl_easy_strerror(res) << std::endl;
            exit(1);
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    std::string json = readBuffer;
    rapidjson::Document doc;
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();

    if (message == std::string(skCrypt("init_success")) || message == std::string(skCrypt("login_success")) || message == std::string(skCrypt("register_success")) || message == std::string(skCrypt("var_grab_success"))) {
        // Find the start of the "Key" field
        size_t start = headerData.find("Key: ");
        if (start == std::string::npos) {
            exit(1);
        }

        // Find the end of the "Key" field value
        size_t end = headerData.find("\n", start);
        if (end == std::string::npos) {
            exit(1);
        }
        if (generateAuthToken(json, APPLICATION_ID) != headerData.substr(start + 5, end - start - 6)) {
            exit(1);
        }
    }

    return json; // JSON response
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

    std::string init_data = std::string(skCrypt("sort=init&appkey=")) + APPLICATION_KEY + std::string(skCrypt("&acckey=")) + ACCOUNT_KEY + std::string(skCrypt("&version=")) + APPLICATION_VERSION + std::string(skCrypt("&hwid=")) + getHWID();
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
    std::string login_data = std::string(skCrypt("sort=login&sessionid=")) + session_id + std::string(skCrypt("&username=")) + username + std::string(skCrypt("&password=")) + password + std::string(skCrypt("&hwid=")) + getHWID();
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
        file_to_download = doc["link"].GetString();
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

// Callback function to write data into a string
static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* data = static_cast<std::string*>(userdata);
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

// Write file
bool writeBytesToFile(std::string fileid, const std::string& filename, const std::string& path) {
    std::filesystem::create_directories(path); // Create the directory path if it doesn't exist

    if (!downloadRequest(fileid)) {
        return false;
    }

    std::string savePath = path + "/" + filename;

    CURL* curl;
    CURLcode res;
    std::string data;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, file_to_download.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            error_message = curl_easy_strerror(res);
        }

        curl_easy_cleanup(curl);
    }

    std::ofstream file(savePath, std::ios::binary);

    if (file.is_open()) {
        file.write(data.data(), data.size());
        file.close();
    }
    else {
        std::cerr << "Unable to open file for writing: " << savePath << std::endl;
        return false;
    }

    return true;
}

// Ban the user HWID and IP
void banUser() {
    // Get the current timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::string timestampStr = std::to_string(timestamp);

    // Remove the last 2 digits from the timestamp
    timestampStr = timestampStr.substr(0, timestampStr.length() - 6);

    // Concatenate the timestamp, message, and app_id
    std::string signature = hash(timestampStr + "ban_user" + getHWID());

    // Actual request
    std::string data = std::string(skCrypt("sort=command&sessionid=")) + session_id + std::string(skCrypt("&command=ban_user&signature=")) + signature + std::string(skCrypt("&hwid=")) + getHWID();
    std::string quote = runRequest(data);

    exit(1);
}