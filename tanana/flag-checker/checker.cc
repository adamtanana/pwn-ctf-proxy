#include "jwt/jwt.h"
#include "tanana/unsw/unsw.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/chrono/chrono.hpp>
#include <boost/chrono/io/time_point_io.hpp>
#include <boost/chrono/time_point.hpp>
#include <chrono>
#include <iostream>
#include <unordered_set>

class Flag {
public:
  // Helper class to hold flag data. This probably should be a struct.
  Flag(std::string flag, std::string zid, std::string ip, std::string session) {
    this->flag = flag;
    this->zid = zid;
    this->ip = ip;
    this->session = session;
  }
  std::string flag;
  std::string zid;
  std::string ip;
  std::string session;
  boost::chrono::system_clock::time_point time;
};

// Returns true if multiple flags/zids share the same IP. Probably worth looking
// into since people shouldn't be in the same house during COVID.
bool has_more_than_one_zid(std::vector<Flag> submissions) {
  std::unordered_set<std::string> zids;
  for (auto flag : submissions) {
    zids.insert(flag.zid);
  }

  return zids.size() > 1;
}

// Function to check the flags of players are legit, and return the challenge
// name.
void mark_them(char *key) {
  auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{key});

  // Expects a list of `zid FLAG{xxx}`.
  for (std::string line; std::getline(std::cin, line);) {
    std::vector<std::string> parts;
    boost::algorithm::split(parts, line, boost::algorithm::is_space());
    if (parts.size() < 2) {
      std::cout << "invalid: missing zid or flag. " << line << std::endl;
      continue;
    }

    auto zid = parts[0];
    auto flag = parts[1];
    // Do a quick sanity check that hte flag is legit.
    if (!(boost::algorithm::starts_with(flag, "FLAG{") &&
          boost::algorithm::ends_with(flag, "}"))) {
      std::cout << "invalid " << zid << ": flag. wrong format. " << flag
                << std::endl;
      continue;
    }

    std::string jwtS = flag.substr(5, flag.length() - 6);

    try {
      // This will throw an exception if the jwt is invalid.
      // Probably something dumb like FLAG{xxx}
      auto decoded = jwt::decode(jwtS);

      try {
        // This will throw an exception is the signature is invalid.
        // This shows that the flag has been falsely modified.
        verifier.verify(decoded);
      } catch (const std::exception &e) {
        std::cout << "invalid " << zid << ": signature. Possible fake flag. "
                  << flag << std::endl;
        continue;
      }

      // So... when I first wrote this, we didn't have sessions...
      // This is a throwback to when I didn't want to segfault the week I was
      // marking and the switch happened, and half the flags didn't have
      // sessions.
      if (decoded.has_payload_claim("session")) {
        std::cout << "valid " << zid << ": "
                  << decoded.get_payload_claim("chal").as_string() << " - "
                  << decoded.get_payload_claim("session").as_string() << " - "
                  << decoded.get_payload_claim("ip").as_string() << std::endl;
      } else {
        std::cout << "valid " << zid << ": "
                  << decoded.get_payload_claim("chal").as_string() << " - "
                  << decoded.get_payload_claim("ip").as_string() << std::endl;
      }
    } catch (const std::exception &e) {
      std::cout << "invalid " << zid << ": jwt. Possible fake flag. " << flag
                << std::endl;
      continue;
    }
  }
}

void cheaters_go_brrrr(char *key) {
  auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{key});

  // Map of player IP + challenge names to generated Flags.
  std::unordered_map<std::string, std::vector<Flag>> submissions;

  for (std::string line; std::getline(std::cin, line);) {
    std::vector<std::string> parts;
    boost::algorithm::split(parts, line, boost::algorithm::is_space());
    if (parts.size() != 2) {
      std::cout << "invalid: missing zid or flag." << std::endl;
      continue;
    }

    auto zid = parts[0];
    auto flag = parts[1];
    // Same logic as above function.
    if (!(boost::algorithm::starts_with(flag, "FLAG{") &&
          boost::algorithm::ends_with(flag, "}"))) {
      continue;
    }

    std::string jwtS = flag.substr(5, flag.length() - 6);

    try {
      // Only compare flags that are verified.
      auto decoded = jwt::decode(jwtS);
      verifier.verify(decoded);

      // Now that flag is verified to be signed, add it to the set.
      auto key = decoded.get_payload_claim("ip").as_string() + "-" +
                 decoded.get_payload_claim("chal").as_string();
      auto exists = submissions.find(key);
      if (exists == submissions.end()) {
        submissions[key] = std::vector<Flag>();
      };

      // Throwback v2.
      // Add all the zid's associated with this challenge/IP combo to a vector.
      if (decoded.has_payload_claim("session")) {
        submissions[key].push_back(
            Flag(flag, zid, decoded.get_payload_claim("ip").as_string(),
                 decoded.get_payload_claim("session").as_string()));
      } else {
        submissions[key].push_back(
            Flag(flag, zid, decoded.get_payload_claim("ip").as_string(), ""));
      }
    } catch (const std::exception &e) {
      continue;
    }
  }

  bool found_any = false;
  for (auto const &[key, val] : submissions) {
    if (val.size() > 1 && has_more_than_one_zid(val)) {
      std::cout << "Cheaters:" << std::endl;
      std::cout << key << std::endl;

      for (auto flag : val) {
        std::cout << flag.zid << ", session_id: " << flag.session << std::endl;
      }

      std::cout << std::endl;

      found_any = true;
    }
  }
  if (!found_any) {
    std::cout << "No cheaters woo!" << std::endl;
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "usage: flag-checker key <marker|cheaters>" << std::endl;
    return -1;
  }

  if (strcmp(argv[2], "marker") == 0) {
    mark_them(argv[1]);
  } else if (strcmp(argv[2], "cheaters") == 0) {
    cheaters_go_brrrr(argv[1]);
  } else {
    std::cerr << "usage: flag-checker key <marker|cheaters>" << std::endl;
    return -1;
  }
}
