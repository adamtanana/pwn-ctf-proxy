#include "tanana/unsw/unsw.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <ctype.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

// This code is bad and I should feel bad but it's 3 am at the time of writing
// and I need to do work tomorrow so unlucky, don't use this in prod ever.
std::string kkey;

namespace ctf_proxy {

// I for some reason wanna log everything, so let's escape strings before
// printing them out.
std::string escape_string(char *input, const size_t &len) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (size_t i = 0; i < len; i++) {
    std::string::value_type c = input[i];

    // Keep alphanumeric and other accepted characters intact
    if (isprint(c)) {
      escaped << c;
      continue;
    }

    // Any other characters are \x-encoded
    escaped << std::uppercase;
    escaped << "\\x" << std::setw(2) << int((unsigned char)c);
    escaped << std::nouppercase;
  }

  return escaped.str();
}

namespace ip = boost::asio::ip;

// Use boost API to host a proxy.
class bridge : public boost::enable_shared_from_this<bridge> {
public:
  typedef ip::tcp::socket socket_type;
  typedef boost::shared_ptr<bridge> ptr_type;

  bridge(boost::asio::io_service &ios, std::string challenge_name,
         std::string flag_placeholder)
      : downstream_socket_(ios), upstream_socket_(ios) {
    this->challenge_name = challenge_name;
    this->flag_placeholder = flag_placeholder;
    this->session_id = unsw::generate_session_string();
  }

  socket_type &downstream_socket() {
    // Client socket
    return downstream_socket_;
  }

  socket_type &upstream_socket() {
    // Remote server socket
    return upstream_socket_;
  }

  void start(const std::string &upstream_host, unsigned short upstream_port) {
    // Attempt connection to remote server (upstream side)
    upstream_socket_.async_connect(
        ip::tcp::endpoint(boost::asio::ip::address::from_string(upstream_host),
                          upstream_port),
        boost::bind(&bridge::handle_upstream_connect, shared_from_this(),
                    boost::asio::placeholders::error));
  }

  void handle_upstream_connect(const boost::system::error_code &error) {
    if (!error) {
      // Setup async read from client (downstream)
      downstream_socket_.async_read_some(
          boost::asio::buffer(downstream_data_, max_data_length),
          boost::bind(&bridge::handle_downstream_read, shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));

      // Setup async read from remote server (upstream)
      upstream_socket_.async_read_some(
          boost::asio::buffer(upstream_data_, max_data_length),
          boost::bind(&bridge::handle_upstream_read, shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
    } else if (error == boost::asio::error::connection_reset ||
               error == boost::asio::error::operation_aborted ||
               error == boost::asio::error::eof) {
      close();
    } else {
      close();
      BOOST_LOG_TRIVIAL(error)
          << "Error " << this->challenge_name << ": "
          << /*ip=*/downstream_socket_.remote_endpoint().address().to_string()
          << " " << error.message();
    }
  }

private:
  std::string challenge_name;
  std::string flag_placeholder;
  std::string session_id;
  /*
     Remote Server --> Proxy --> Client
  */

  // Read from remote server complete, now send data to client
  void handle_upstream_read(const boost::system::error_code &error,
                            const size_t &bytes_transferred) {
    if (!error) {
      // This is probably inefficient.
      // I doubt I'd overflow anything here since std::string should hopefully
      // just resize itself... right?
      std::string data(upstream_data_, bytes_transferred);
      boost::replace_all(
          data, this->flag_placeholder,
          unsw::generate_flag(
              /*ip=*/downstream_socket_.remote_endpoint().address().to_string(),
              /*chal=*/this->challenge_name,
              /*session_id=*/this->session_id,
              /*key*/ kkey));

      async_write(
          downstream_socket_, boost::asio::buffer(data.c_str(), data.length()),
          boost::bind(&bridge::handle_downstream_write, shared_from_this(),
                      boost::asio::placeholders::error));
    } else if (error == boost::asio::error::connection_reset ||
               error == boost::asio::error::operation_aborted ||
               error == boost::asio::error::eof) {
      close();
    } else {
      close();
      BOOST_LOG_TRIVIAL(error)
          << "Error " << this->challenge_name << ": "
          << /*ip=*/downstream_socket_.remote_endpoint().address().to_string()
          << " " << error.message();
    }
  }

  // Write to client complete, Async read from remote server
  void handle_downstream_write(const boost::system::error_code &error) {
    if (!error) {
      upstream_socket_.async_read_some(
          boost::asio::buffer(upstream_data_, max_data_length),
          boost::bind(&bridge::handle_upstream_read, shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
    } else if (error == boost::asio::error::connection_reset ||
               error == boost::asio::error::operation_aborted ||
               error == boost::asio::error::eof) {
      close();
    } else {
      close();
      BOOST_LOG_TRIVIAL(error)
          << "Error " << this->challenge_name << ": "
          << /*ip=*/downstream_socket_.remote_endpoint().address().to_string()
          << " " << error.message();
    }
  }
  /*
     Client --> Proxy --> Remote Server
  */

  // Read from client complete, now send data to remote server
  void handle_downstream_read(const boost::system::error_code &error,
                              const size_t &bytes_transferred) {
    if (!error) {
      std::string data(downstream_data_, bytes_transferred);
      // Replace instances of the template flag from the client
      // to stop people guessing the flag{sha256sum(chalname)}.
      boost::replace_all(data, this->flag_placeholder, "FLAG{nice try}");

      async_write(
          upstream_socket_, boost::asio::buffer(data.c_str(), data.length()),
          boost::bind(&bridge::handle_upstream_write, shared_from_this(),
                      boost::asio::placeholders::error));

      // Log the upstream message., with the session id & challenge name.
      BOOST_LOG_TRIVIAL(trace)
          << "[" << this->session_id << "] [" << this->challenge_name << "] "
          << boost::lexical_cast<std::string>(
                 downstream_socket_.remote_endpoint())
          << ": " << escape_string(downstream_data_, bytes_transferred);
    } else if (error == boost::asio::error::connection_reset ||
               error == boost::asio::error::operation_aborted ||
               error == boost::asio::error::eof) {
      close();
    } else {
      close();
      BOOST_LOG_TRIVIAL(error)
          << "Error " << this->challenge_name << ": "
          << /*ip=*/downstream_socket_.remote_endpoint().address().to_string()
          << " " << error.message();
    }
  }

  // Write to remote server complete, Async read from client
  void handle_upstream_write(const boost::system::error_code &error) {
    if (!error) {
      downstream_socket_.async_read_some(
          boost::asio::buffer(downstream_data_, max_data_length),
          boost::bind(&bridge::handle_downstream_read, shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
    } else if (error == boost::asio::error::connection_reset ||
               error == boost::asio::error::operation_aborted ||
               error == boost::asio::error::eof) {
      close();
    } else {
      close();
      BOOST_LOG_TRIVIAL(error)
          << "Error " << this->challenge_name << ": "
          << /*ip=*/downstream_socket_.remote_endpoint().address().to_string()
          << " " << error.message();
    }
  }

  void close() {
    boost::mutex::scoped_lock lock(mutex_);

    if (downstream_socket_.is_open()) {
      downstream_socket_.close();
    }

    if (upstream_socket_.is_open()) {
      upstream_socket_.close();
    }
  }

  socket_type downstream_socket_;
  socket_type upstream_socket_;

  // Is this overflowable? probably..
  enum { max_data_length = 16384 }; // 16KB
  char downstream_data_[max_data_length];
  char upstream_data_[max_data_length];

  boost::mutex mutex_;

  // boiletplate.
public:
  class acceptor {
  public:
    acceptor(boost::asio::io_service &io_service, const std::string &local_host,
             unsigned short local_port, const std::string &upstream_host,
             unsigned short upstream_port, std::string challenge_name,
             std::string flag_placeholder)
        : io_service_(io_service),
          localhost_address(
              boost::asio::ip::address_v4::from_string(local_host)),
          acceptor_(io_service_,
                    ip::tcp::endpoint(localhost_address, local_port)),
          upstream_port_(upstream_port), upstream_host_(upstream_host) {

      this->challenge_name = challenge_name;
      this->flag_placeholder = flag_placeholder;
    }

    bool accept_connections() {
      try {
        session_ = boost::shared_ptr<bridge>(new bridge(
            io_service_, this->challenge_name, this->flag_placeholder));

        acceptor_.async_accept(session_->downstream_socket(),
                               boost::bind(&acceptor::handle_accept, this,
                                           boost::asio::placeholders::error));
      } catch (std::exception &e) {
        BOOST_LOG_TRIVIAL(error) << "acceptor exception: " << e.what();
        return false;
      }

      return true;
    }

  private:
    std::string challenge_name;
    std::string flag_placeholder;
    void handle_accept(const boost::system::error_code &error) {
      if (!error) {
        session_->start(upstream_host_, upstream_port_);

        if (!accept_connections()) {
          BOOST_LOG_TRIVIAL(error) << "Failure during call to accept.";
        }
      } else {
        BOOST_LOG_TRIVIAL(error) << "Error: " << error.message();
      }
    }

    boost::asio::io_service &io_service_;
    ip::address_v4 localhost_address;
    ip::tcp::acceptor acceptor_;
    ptr_type session_;
    unsigned short upstream_port_;
    std::string upstream_host_;
  };
};
} // namespace ctf_proxy

void init() {
  // setup logging of connections.
  boost::log::add_file_log(
      boost::log::keywords::file_name = "proxy_%N.log",
      boost::log::keywords::rotation_size = 10 * 1024 * 1024,
      boost::log::keywords::auto_flush = true,
      boost::log::keywords::open_mode = std::ios::out | std::ios::app,
      boost::log::keywords::format =
          (boost::log::expressions::stream
           << boost::log::expressions::format_date_time<
                  boost::posix_time::ptime>("TimeStamp", "[%Y-%m-%d %H:%M:%S]")
           << ": <" << boost::log::trivial::severity << "> "
           << boost::log::expressions::smessage));

  boost::log::add_common_attributes();
}

constexpr int64_t max_backoff_milliseconds = 600000; // 10 minutes.
constexpr int64_t max_retries = 10;

void start_challenge(unsw::Config config) {
  boost::asio::io_service ios;
  BOOST_LOG_TRIVIAL(info) << "Starting challenge thread: "
                          << config.challenge_name
                          << " on port: " << config.lport;
  int retry_count = 0;
  int64_t delay_milliseconds = 0;
  do {
    try {
      // Each thread listens on a specific port, and passed through any traffic
      // to a different specific port. If a message from server->client contains
      // the flag_placeholder, it is replaced inline with a flag generated by
      // unsw::generate_flag.
      ctf_proxy::bridge::acceptor acceptor(
          ios, config.lhost, config.lport, config.rhost, config.rport,
          config.challenge_name, config.flag_placeholder);

      // Start listening for connections.
      acceptor.accept_connections();

      ios.run();
    } catch (std::exception &e) {
      BOOST_LOG_TRIVIAL(fatal)
          << "Challenge down?: " << config.challenge_name
          << ",  retry_count=" << retry_count << ", err: " << e.what();
    }

    // If fails for somereason (*cough* bad students), do an exponential backoff
    // to reboot it.
    if (delay_milliseconds == 0) {
      delay_milliseconds = 1000; // 1 second initialiiy.
    } else {
      delay_milliseconds =
          std::min(delay_milliseconds << retry_count, max_backoff_milliseconds);
    }

    boost::this_thread::sleep_for(
        boost::chrono::milliseconds(delay_milliseconds));
    ++retry_count;
  } while (retry_count < max_retries);
}

int main(int argc, char *argv[]) {
  init();
  if (argc != 3) {
    std::cerr << "usage: ctf-proxy key config.json" << std::endl;
    return 1;
  }

  kkey = argv[1];
  std::vector<boost::thread> challenge_threads;

  for (unsw::Config config : unsw::load_config(argv[2])) {
    challenge_threads.push_back(boost::thread(start_challenge, config));
  }

  for (boost::thread &t : challenge_threads) {
    t.join();
  }

  return 0;
}
