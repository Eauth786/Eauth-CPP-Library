#define EAUTH_H
#include <string>

bool initRequest(std::string account_key, std::string application_key, std::string application_id, std::string application_version);
extern std::string error_message;
extern std::string logged_message;
extern std::string registered_message;
extern std::string app_name;
extern std::string rank;
extern std::string register_date;
extern std::string expire_date;
extern std::string hwid;
bool writeBytesToFile(std::string fileid, const std::string& filename, const std::string& path);
bool loginRequest(std::string username, std::string password, std::string key);
bool registerRequest(std::string username, std::string password, std::string key);
