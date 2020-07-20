#include "unsw.hpp"
#include "jwt/jwt.h"
#include "openssl/sha.h"
#include <boost/lexical_cast.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <cstring>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

// Some helper function to do some sha256 math on the challenge name.
// This lets us have a unique flag per challenge, so leaking the underlying
// flag in one challenge is useless in other challenges.
std::string sha256sum(std::string challenge_name) {
  SHA256_CTX sha;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  // Length is 32 * 2 = 64. Plus a null byte.
  char output[65];

  SHA256_Init(&sha);
  SHA256_Update(&sha, challenge_name.c_str(), challenge_name.length());
  SHA256_Final(hash, &sha);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }
  output[64] = 0;
  return "FLAG{" + std::string(output) + "}";
}

namespace unsw {

// Config file used to host challenges.
// Usage in COMP6447 will be rhost: 127.0.0.1, lport: 9999, lhost: docker IP.
Config::Config(std::string lhost, std::string rhost, int lport, int rport,
               std::string challenge_name, std::string flag_placeholder) {
  this->lhost = lhost;
  this->rhost = rhost;
  this->lport = lport;
  this->rport = rport;
  this->challenge_name = challenge_name;

  std::cout << flag_placeholder << std::endl;
  this->flag_placeholder = flag_placeholder;
}

// Loads a json config from a file.
const std::vector<Config> load_config(const std::string filename) {
  std::ifstream fstream(filename);
  std::stringstream buffer;
  buffer << fstream.rdbuf();

  nlohmann::json obj = nlohmann::json::parse(buffer);
  std::vector<Config> configs;
  for (const auto &json : obj) {
    configs.push_back(Config(json["lhost"], json["rhost"],
                             json["lport"].get<int>(), json["rport"].get<int>(),
                             json["chal"], sha256sum(json["chal"])));
  }

  return configs;
}

// Generate a flag based on the IP of user, challenge name, and session ID.
// This gurantees a unique flag per session, whilst also tying a specific flag
// back to both a player and a challenge, as well as a session in the logs.
std::string generate_flag(const std::string ip,
                          const std::string challenge_name,
                          const std::string session_id, const std::string key) {
  auto token =
      jwt::create()
          .set_payload_claim("ip", jwt::claim(std::string(ip)))
          .set_payload_claim("chal", jwt::claim(std::string(challenge_name)))
          .set_payload_claim("session", jwt::claim(std::string(session_id)))
          .sign(jwt::algorithm::hs256{key});

  std::stringstream flag;
  flag << "FLAG{" << token << "}";

  return flag.str();
}

// Idk why I got this here tbh.
std::string generate_session_string() {
  return boost::lexical_cast<std::string>(boost::uuids::random_generator()());
}

} // namespace unsw
