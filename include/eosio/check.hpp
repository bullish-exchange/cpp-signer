#pragma once

#include <stdexcept>
#include <string>

namespace eosio {

/**
 *  @defgroup system System
 *  @ingroup core
 *  @brief Defines wrappers over eosio_assert
 */

namespace detail {
   [[noreturn]] inline void assert_or_throw(const std::string& msg) {
         throw std::runtime_error(std::string(msg));
   }
   [[noreturn]] inline void assert_or_throw(const char* msg) {
         throw std::runtime_error(msg);
   }
   [[noreturn]] inline void assert_or_throw(std::string&& msg) {
         throw std::runtime_error(std::move(msg));
   }
   [[noreturn]] inline void assert_or_throw(uint64_t code) {
         throw std::runtime_error(std::to_string(code));
   }
} // ns eosio::detail

/**
 *  Assert if the predicate fails and use the supplied message.
 *
 *  @ingroup system
 *
 *  Example:
 *  @code
 *  eosio::check(a == b, "a does not equal b");
 *  @endcode
 */
inline void check(bool pred, const std::string& msg) {
   if (!pred)
      detail::assert_or_throw(msg);
}

/**
 *  Assert if the predicate fails and use the supplied message.
 *
 *  @ingroup system
 *
 *  Example:
 *  @code
 *  eosio::check(a == b, "a does not equal b");
 *  @endcode
 */
inline void check(bool pred, const char* msg) {
   if (!pred)
      detail::assert_or_throw(msg);
}

/**
 *  Assert if the predicate fails and use the supplied message.
 *
 *  @ingroup system
 *
 *  Example:
 *  @code
 *  eosio::check(a == b, "a does not equal b");
 *  @endcode
 */
inline void check(bool pred, std::string&& msg) {
   if (!pred)
      detail::assert_or_throw(std::move(msg));
}

/**
 *  Assert if the predicate fails and use a subset of the supplied message.
 *
 *  @ingroup system
 *
 *  Example:
 *  @code
 *  const char* msg = "a does not equal b b does not equal a";
 *  eosio::check(a == b, "a does not equal b", 18);
 *  @endcode
 */
inline void check(bool pred, const char* msg, size_t n) {
   if (!pred)
      detail::assert_or_throw(std::string{msg, n});
}

/**
 *  Assert if the predicate fails and use a subset of the supplied message.
 *
 *  @ingroup system
 *
 *  Example:
 *  @code
 *  std::string msg = "a does not equal b b does not equal a";
 *  eosio::check(a == b, msg, 18);
 *  @endcode
 */
inline void check(bool pred, const std::string& msg, size_t n) {
   if (!pred)
      detail::assert_or_throw(msg.substr(0, n));
}

/**
 *  Assert if the predicate fails and use the supplied error code.
 *
 *  @ingroup system
 *
 *  Example:
 *  @code
 *  eosio::check(a == b, 13);
 *  @endcode
 */
inline void check(bool pred, uint64_t code) {
   if (!pred)
      detail::assert_or_throw(code);
}
} // namespace eosio
