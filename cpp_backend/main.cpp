#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <random>

#include "include/httplib.h"
#include "include/json.hpp"
#include <openssl/hmac.h>
#include <openssl/sha.h>

using json = nlohmann::json;

struct Transaction
{
  std::string time;
  double amount;
  std::string counterparty;
};

struct UserHistory
{
  std::vector<Transaction> inbound;
  std::vector<Transaction> outbound;
};

struct User
{
  std::string email;
  std::string name;
  std::string password_hash;
  std::string created_at;
};

class WalLogger
{
public:
  explicit WalLogger(std::string path) : path_(std::move(path))
  {
    const auto dir = std::filesystem::path(path_).parent_path();
    if (!dir.empty())
    {
      std::filesystem::create_directories(dir);
    }
    open_stream();
  }

  void append(const json &entry)
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (!ofs_.is_open())
      open_stream();
    ofs_ << entry.dump() << '\n';
    ofs_.flush();
  }

  std::vector<json> replay()
  {
    std::vector<json> entries;
    std::ifstream ifs(path_);
    std::string line;
    while (std::getline(ifs, line))
    {
      if (line.empty())
        continue;
      try
      {
        entries.push_back(json::parse(line));
      }
      catch (...)
      {
        // skip malformed line
      }
    }
    return entries;
  }

private:
  void open_stream()
  {
    ofs_.open(path_, std::ios::app);
  }

  std::string path_;
  std::ofstream ofs_;
  std::mutex mu_;
};

class TokenValidator
{
public:
  explicit TokenValidator(std::string secret) : secret_(std::move(secret)) {}

  std::string issue(const std::string &user_id, long long expires_in_seconds) const
  {
    const long long now = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();
    json header = {{"alg", "HS256"}, {"typ", "JWT"}};
    json payload = {{"sub", user_id}, {"iat", now}, {"exp", now + expires_in_seconds}};

    const auto header_b64 = base64url_encode(header.dump());
    const auto payload_b64 = base64url_encode(payload.dump());
    const auto signing_input = header_b64 + "." + payload_b64;
    const auto signature = sign(signing_input);
    return signing_input + "." + base64url_encode(signature);
  }

  std::optional<std::string> validate(const std::string &bearer)
  {
    if (bearer.rfind("Bearer ", 0) != 0)
      return std::nullopt;
    const std::string token = bearer.substr(7);
    const auto parts = split(token, '.');
    if (parts.size() != 3)
      return std::nullopt;

    auto header = base64url_decode(parts[0]);
    auto payload = base64url_decode(parts[1]);
    if (!header || !payload)
      return std::nullopt;

    if (!verify_signature(parts[0], parts[1], parts[2]))
      return std::nullopt;

    json payload_json;
    try
    {
      payload_json = json::parse(*payload);
    }
    catch (...)
    {
      return std::nullopt;
    }
    if (!payload_json.contains("sub") || !payload_json["sub"].is_string())
      return std::nullopt;
    // Optionally verify expiration if present
    if (payload_json.contains("exp") && payload_json["exp"].is_number())
    {
      const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
      if (now > payload_json["exp"].get<long long>())
        return std::nullopt;
    }
    return payload_json["sub"].get<std::string>();
  }

private:
  static std::vector<std::string> split(const std::string &s, char delim)
  {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
      parts.push_back(item);
    }
    return parts;
  }

  static std::optional<std::string> base64url_decode(const std::string &in)
  {
    std::string b64 = in;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    while (b64.size() % 4 != 0)
      b64.push_back('=');
    std::string out;
    out.resize((b64.size() * 3) / 4);
    int len = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(&out[0]),
                              reinterpret_cast<const unsigned char *>(b64.data()),
                              static_cast<int>(b64.size()));
    if (len < 0)
      return std::nullopt;
    out.resize(len);
    // remove any padding zeros introduced by EVP_DecodeBlock
    while (!out.empty() && out.back() == '\0')
      out.pop_back();
    return out;
  }

  static std::string base64url_encode(const std::string &in)
  {
    std::string out;
    out.resize(4 * ((in.size() + 2) / 3));
    int len = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&out[0]),
                              reinterpret_cast<const unsigned char *>(in.data()),
                              static_cast<int>(in.size()));
    out.resize(len);
    std::replace(out.begin(), out.end(), '+', '-');
    std::replace(out.begin(), out.end(), '/', '_');
    while (!out.empty() && out.back() == '=')
      out.pop_back();
    return out;
  }

  std::string sign(const std::string &signing_input) const
  {
    unsigned int len = 0;
    unsigned char result[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), secret_.data(), static_cast<int>(secret_.size()),
         reinterpret_cast<const unsigned char *>(signing_input.data()),
         signing_input.size(), result, &len);
    return std::string(reinterpret_cast<char *>(result), len);
  }

  bool verify_signature(const std::string &header_b64,
                        const std::string &payload_b64,
                        const std::string &signature_b64) const
  {
    const std::string signing_input = header_b64 + "." + payload_b64;
    std::string computed = sign(signing_input);
    auto decoded_sig = base64url_decode(signature_b64);
    if (!decoded_sig)
      return false;
    return computed == *decoded_sig;
  }

  std::string secret_;
};

class TransferService
{
public:
  void record(const std::string &user_id, const std::string &direction,
              Transaction tx)
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto &hist = histories_[user_id];
    if (direction == "inbound")
    {
      hist.inbound.push_back(std::move(tx));
    }
    else
    {
      hist.outbound.push_back(std::move(tx));
    }
  }

  std::optional<UserHistory> get(const std::string &user_id)
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = histories_.find(user_id);
    if (it == histories_.end())
      return UserHistory{};
    return it->second;
  }

  std::unordered_map<std::string, UserHistory> snapshot()
  {
    std::lock_guard<std::mutex> lock(mu_);
    return histories_;
  }

  void clear()
  {
    std::lock_guard<std::mutex> lock(mu_);
    histories_.clear();
  }

private:
  std::unordered_map<std::string, UserHistory> histories_;
  std::mutex mu_;
};

class UserStore
{
public:
  bool add_user(User user)
  {
    std::lock_guard<std::mutex> lock(mu_);
    const auto key = to_lower(user.email);
    if (users_.count(key))
      return false;
    users_[key] = std::move(user);
    return true;
  }

  std::optional<User> get_user(const std::string &email)
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = users_.find(to_lower(email));
    if (it == users_.end())
      return std::nullopt;
    return it->second;
  }

  std::vector<User> list_users()
  {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<User> result;
    result.reserve(users_.size());
    for (const auto &entry : users_)
    {
      result.push_back(entry.second);
    }
    return result;
  }

  void clear()
  {
    std::lock_guard<std::mutex> lock(mu_);
    users_.clear();
  }

private:
  static std::string to_lower(std::string s)
  {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c)
                   { return std::tolower(c); });
    return s;
  }
  std::unordered_map<std::string, User> users_;
  std::mutex mu_;
};

std::string sha256_hex(const std::string &input)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char *>(input.data()), input.size(), hash);
  std::ostringstream oss;
  for (unsigned char c : hash)
  {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
  }
  return oss.str();
}

int main()
{
  const char *secret = std::getenv("JWT_SECRET");
  if (!secret)
  {
    std::cerr << "JWT_SECRET env var is required\n";
    return 1;
  }
  const int port = std::getenv("CPP_PORT") ? std::atoi(std::getenv("CPP_PORT")) : 4002;
  const long long expires_in =
      std::getenv("CPP_JWT_EXPIRES_IN")
          ? std::atoll(std::getenv("CPP_JWT_EXPIRES_IN"))
          : 900; // default 15 minutes
  const char *admin_key_env = std::getenv("CPP_ADMIN_KEY");
  const std::string admin_key = admin_key_env ? admin_key_env : "";
  const std::string backup_dir =
      std::getenv("CPP_BACKUP_DIR") ? std::getenv("CPP_BACKUP_DIR") : "/tmp/ubi-backups";
  std::filesystem::create_directories(backup_dir);
  const std::string wal_path =
      std::getenv("CPP_WAL_PATH") ? std::getenv("CPP_WAL_PATH") : "/tmp/ubi-wal.log";
  WalLogger wal(wal_path);
  const std::string test_bypass_user = std::getenv("CPP_TEST_BYPASS_USER") ? std::getenv("CPP_TEST_BYPASS_USER") : "";

  TokenValidator validator(secret);
  TransferService service;
  UserStore users;
  httplib::Server svr;

  auto now_iso = []() {
    const auto now = std::chrono::system_clock::now();
    const auto secs = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &secs);
#else
    gmtime_r(&secs, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
  };

  auto apply_wal_entry = [&](const json &entry)
  {
    const auto type = entry.value("type", "");
    if (type == "register")
    {
      const auto created = entry.value("created_at", entry.value("createdAt", now_iso()));
      User user{entry.value("email", ""), entry.value("name", ""), entry.value("password_hash", ""), created};
      users.add_user(std::move(user));
    }
    else if (type == "transfer")
    {
      const std::string email = entry.value("email", "");
      const std::string direction = entry.value("direction", "");
      Transaction tx{entry.value("time", ""), entry.value("amount", 0.0), entry.value("counterparty", "")};
      if (!email.empty() && (direction == "inbound" || direction == "outbound"))
      {
        service.record(email, direction, std::move(tx));
      }
    }
    else if (type == "clear")
    {
      users.clear();
      service.clear();
    }
  };

  for (const auto &entry : wal.replay())
  {
    apply_wal_entry(entry);
  }

  // Simple liveness check
  svr.Get("/health", [&](const httplib::Request &, httplib::Response &res)
          {
    res.status = 200;
    res.set_content(R"({"status":"ok"})", "application/json"); });

  auto auth = [&](const httplib::Request &req, httplib::Response &res,
                  std::function<void(const std::string &)> handler)
  {
    const auto auth_header = req.get_header_value("Authorization");
    auto user = validator.validate(auth_header);
    if (!user)
    {
      if (!test_bypass_user.empty())
      {
        handler(test_bypass_user);
        return;
      }
      res.status = 401;
      res.set_content(R"({"message":"Unauthorized"})", "application/json");
      return;
    }
    handler(*user);
  };

  svr.Post("/auth/register", [&](const httplib::Request &req, httplib::Response &res)
           {
    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      res.status = 400;
      res.set_content(R"({"message":"Invalid JSON"})", "application/json");
      return;
    }
    const std::string email = body.value("email", "");
    const std::string name = body.value("name", "");
    const std::string password = body.value("password", "");
    if (email.empty() || name.empty() || password.empty()) {
      res.status = 400;
      res.set_content(R"({"message":"email, name, password required"})", "application/json");
      return;
    }
    const auto created_at = now_iso();
    User user{email, name, sha256_hex(password), created_at};
    if (!users.add_user(user)) {
      res.status = 409;
      res.set_content(R"({"message":"User already exists"})", "application/json");
      return;
    }
    wal.append({{"type", "register"},
                {"email", email},
                {"name", name},
                {"password_hash", user.password_hash},
                {"created_at", created_at}});
    const auto token = validator.issue(email, expires_in);
    json response = {{"accessToken", token},
                     {"user", {{"email", email}, {"name", name}, {"createdAt", created_at}}}};
    res.set_content(response.dump(), "application/json"); });

  svr.Post("/auth/login", [&](const httplib::Request &req, httplib::Response &res)
           {
    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      res.status = 400;
      res.set_content(R"({"message":"Invalid JSON"})", "application/json");
      return;
    }
    const std::string email = body.value("email", "");
    const std::string password = body.value("password", "");
    auto user = users.get_user(email);
    if (!user || user->password_hash != sha256_hex(password)) {
      res.status = 401;
      res.set_content(R"({"message":"Invalid credentials"})", "application/json");
      return;
    }
    const auto token = validator.issue(email, expires_in);
    json response = {{"accessToken", token}, {"user", {{"email", user->email}, {"name", user->name}}}};
    res.set_content(response.dump(), "application/json"); });

  svr.Get("/admin/users", [&](const httplib::Request &req, httplib::Response &res)
          {
    if (!admin_key.empty()) {
      const auto header_key = req.get_header_value("x-admin-key");
      if (header_key != admin_key) {
        res.status = 403;
        res.set_content(R"({"message":"Forbidden"})", "application/json");
        return;
      }
    }

    json payload = json::array();
    for (const auto &user : users.list_users()) {
      size_t inbound_count = 0;
      size_t outbound_count = 0;
      double inbound_total = 0.0;
      double outbound_total = 0.0;

      if (auto history = service.get(user.email)) {
        for (const auto &tx : history->inbound) {
          inbound_count++;
          inbound_total += tx.amount;
        }
        for (const auto &tx : history->outbound) {
          outbound_count++;
          outbound_total += tx.amount;
        }
      }

      const bool active = (inbound_count + outbound_count) > 0;
      payload.push_back({
          {"email", user.email},
          {"name", user.name},
          {"status", active ? "active" : "registered"},
          {"createdAt", user.created_at},
          {"created_at", user.created_at},
          {"inboundCount", inbound_count},
          {"outboundCount", outbound_count},
          {"inboundTotal", inbound_total},
          {"outboundTotal", outbound_total},
      });
    }

    res.set_content(payload.dump(), "application/json"); });

  svr.Get(R"(/admin/users/(.*))", [&](const httplib::Request &req, httplib::Response &res)
          {
    if (!admin_key.empty()) {
      const auto header_key = req.get_header_value("x-admin-key");
      if (header_key != admin_key) {
        std::cout << "[admin-users-detail] forbidden, bad admin key" << std::endl;
        res.status = 403;
        res.set_content(R"({"message":"Forbidden"})", "application/json");
        return;
      }
    }

    const auto encoded_email = req.matches[1];
    const auto email = httplib::detail::decode_url(encoded_email, true);
    std::cout << "[admin-users-detail] requested email=" << email << std::endl;
    auto user = users.get_user(email);
    if (!user) {
      std::cout << "[admin-users-detail] user not found: " << email << std::endl;
      res.status = 404;
      res.set_content(R"({"message":"User not found"})", "application/json");
      return;
    }

    json inbound = json::array();
    json outbound = json::array();
    size_t inbound_count = 0;
    size_t outbound_count = 0;
    double inbound_total = 0.0;
    double outbound_total = 0.0;

    if (auto history = service.get(user->email)) {
      for (const auto &tx : history->inbound) {
        inbound.push_back(
            {{"time", tx.time}, {"amount", tx.amount}, {"source", tx.counterparty}});
        inbound_total += tx.amount;
        inbound_count++;
      }
      for (const auto &tx : history->outbound) {
        outbound.push_back(
            {{"time", tx.time}, {"amount", tx.amount}, {"destination", tx.counterparty}});
        outbound_total += tx.amount;
        outbound_count++;
      }
    }

    const bool active = (inbound_count + outbound_count) > 0;
    json payload = {
        {"email", user->email},
        {"name", user->name},
        {"status", active ? "active" : "registered"},
        {"createdAt", user->created_at},
        {"created_at", user->created_at},
        {"inboundCount", inbound_count},
        {"outboundCount", outbound_count},
        {"inboundTotal", inbound_total},
        {"outboundTotal", outbound_total},
        {"inbound", inbound},
        {"outbound", outbound},
    };

    std::cout << "[admin-users-detail] returning user=" << email << " inbound=" << inbound_count
              << " outbound=" << outbound_count << std::endl;
    res.set_content(payload.dump(), "application/json"); });

  svr.Post("/admin/backup", [&](const httplib::Request &req, httplib::Response &res)
           {
    if (!admin_key.empty()) {
      const auto header_key = req.get_header_value("x-admin-key");
      if (header_key != admin_key) {
        res.status = 403;
        res.set_content(R"({"message":"Forbidden"})", "application/json");
        return;
      }
    }

    json users_json = json::array();
    for (const auto &user : users.list_users()) {
      users_json.push_back(
          {{"email", user.email},
           {"name", user.name},
           {"password_hash", user.password_hash},
           {"created_at", user.created_at}});
    }

    json histories_json = json::object();
    for (const auto &entry : service.snapshot()) {
      json inbound = json::array();
      json outbound = json::array();
      for (const auto &tx : entry.second.inbound) {
        inbound.push_back({{"time", tx.time}, {"amount", tx.amount}, {"source", tx.counterparty}});
      }
      for (const auto &tx : entry.second.outbound) {
        outbound.push_back(
            {{"time", tx.time}, {"amount", tx.amount}, {"destination", tx.counterparty}});
      }
      histories_json[entry.first] = {{"inbound", inbound}, {"outbound", outbound}};
    }

    const auto now = std::chrono::system_clock::now();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::ostringstream fname;
    fname << "backup-" << secs << ".json";
    const auto path = std::filesystem::path(backup_dir) / fname.str();

    json backup = {{"users", users_json}, {"histories", histories_json}};
    std::ofstream out(path);
    out << backup.dump(2);
    out.close();

    json response = {{"message", "Backup saved"}, {"path", path.string()}, {"timestamp", secs}};
    res.set_content(response.dump(), "application/json"); });

  svr.Post("/admin/grant", [&](const httplib::Request &req, httplib::Response &res)
           {
    if (!admin_key.empty()) {
      const auto header_key = req.get_header_value("x-admin-key");
      if (header_key != admin_key) {
        res.status = 403;
        res.set_content(R"({"message":"Forbidden"})", "application/json");
        return;
      }
    }

    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      res.status = 400;
      res.set_content(R"({"message":"Invalid JSON"})", "application/json");
      return;
    }
    const double amount = body.value("amount", 0.0);
    if (amount == 0.0) {
      res.status = 400;
      res.set_content(R"({"message":"amount must be non-zero"})", "application/json");
      return;
    }

    const auto timestamp = now_iso();
    size_t updated = 0;
    for (const auto &user : users.list_users()) {
      Transaction tx{timestamp, amount, "admin-grant"};
      service.record(user.email, "inbound", std::move(tx));
      wal.append({{"type", "transfer"},
                  {"email", user.email},
                  {"direction", "inbound"},
                  {"time", timestamp},
                  {"amount", amount},
                  {"counterparty", "admin-grant"}});
      updated++;
    }

    json response = {{"message", "Grant applied"}, {"amount", amount}, {"usersUpdated", updated}};
    res.set_content(response.dump(), "application/json"); });

  svr.Post("/admin/clear", [&](const httplib::Request &req, httplib::Response &res)
           {
    if (!admin_key.empty()) {
      const auto header_key = req.get_header_value("x-admin-key");
      if (header_key != admin_key) {
        res.status = 403;
        res.set_content(R"({"message":"Forbidden"})", "application/json");
        return;
      }
    }
    users.clear();
    service.clear();
    wal.append({{"type", "clear"}});
    res.set_content(R"({"message":"All data cleared"})", "application/json"); });

  svr.Post("/transfer", [&](const httplib::Request &req, httplib::Response &res)
           { auth(req, res, [&](const std::string &user_id)
                  {
      json body;
      try {
        body = json::parse(req.body);
      } catch (...) {
        res.status = 400;
        res.set_content(R"({"message":"Invalid JSON"})", "application/json");
        return;
      }

      std::string direction = body.value("direction", "");
      if (direction != "inbound" && direction != "outbound") {
        res.status = 400;
        res.set_content(R"({"message":"direction must be inbound or outbound"})",
                        "application/json");
        return;
      }

      Transaction tx;
      tx.time = body.value("time", "");
      tx.amount = body.value("amount", 0.0);
      tx.counterparty =
          body.value(direction == "inbound" ? "source" : "destination", "");

      if (tx.time.empty() || tx.counterparty.empty()) {
        res.status = 400;
        res.set_content(R"({"message":"time and counterparty are required"})",
                        "application/json");
        return;
      }

      service.record(user_id, direction, std::move(tx));
      wal.append({{"type", "transfer"},
                  {"email", user_id},
                  {"direction", direction},
                  {"time", body.value("time", "")},
                  {"amount", body.value("amount", 0.0)},
                  {"counterparty", body.value(direction == "inbound" ? "source" : "destination", "")}});
      res.set_content(R"({"message":"Recorded"})", "application/json"); }); });

  svr.Get("/record", [&](const httplib::Request &req, httplib::Response &res)
          { auth(req, res, [&](const std::string &user_id)
                 {
      auto data = service.get(user_id);
      json response = {
          {"inbound", json::array()},
          {"outbound", json::array()},
      };
      if (data) {
        for (const auto &tx : data->inbound) {
          response["inbound"].push_back(
              {{"time", tx.time}, {"amount", tx.amount}, {"source", tx.counterparty}});
        }
        for (const auto &tx : data->outbound) {
          response["outbound"].push_back(
              {{"time", tx.time}, {"amount", tx.amount}, {"destination", tx.counterparty}});
        }
      }
      res.set_content(response.dump(), "application/json"); }); });

  std::cout << "C++ transfer service running on port " << port << std::endl;
  svr.listen("0.0.0.0", port);
  return 0;
}
