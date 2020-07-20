#ifndef UNSW_HPP
#define UNSW_HPP

#include <cstddef>
#include <string>
#include <vector>

namespace unsw {
class Config {
public:
  Config(std::string lhost, std::string rhost, int lport, int rport,
         std::string challenge_name, std::string flag_placeholder);
  std::string lhost;
  std::string rhost;
  int lport;
  int rport;
  std::string challenge_name;
  std::string flag_placeholder;
};

// Self explanatory. Generates flags based on inputs.
std::string generate_flag(const std::string ip,
                          const std::string challenge_name,
                          const std::string session_id, const std::string key);

const std::vector<Config> load_config(const std::string filename);

// Returns a random UUID as a string.
std::string generate_session_string();
} // namespace unsw

#endif
