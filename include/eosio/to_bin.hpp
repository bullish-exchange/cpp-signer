#pragma once

#include <eosio/stream.hpp>

#include <deque>
#include <list>
#include <map>
#include <set>
#include <vector>

namespace eosio {

template <typename S>
void varuint32_to_bin(uint64_t val, S& stream) {
   check( !(val >> 32), convert_stream_error( stream_error::varuint_too_big) );
   do {
      uint8_t b = val & 0x7f;
      val >>= 7;
      b |= ((val > 0) << 7);
      stream.write(b);
   } while (val);
}

inline void push_varuint32(std::vector<char>& bin, uint32_t v) {
   vector_stream st{ bin };
   varuint32_to_bin(v, st);
}

template <typename S>
void to_bin(const std::string& sv, S& stream) {
   varuint32_to_bin(sv.size(), stream);
   stream.write(sv.data(), sv.size());
}

template <typename T, typename S>
void to_bin_range(const T& obj, S& stream) {
   varuint32_to_bin(obj.size(), stream);
   for (auto& x : obj) {
      to_bin(x, stream);
   }
}

template <typename T, std::size_t N, typename S>
void to_bin(const T (&obj)[N], S& stream) {
   varuint32_to_bin(N, stream);
   if (has_bitwise_serialization<T>()) {
      stream.write(reinterpret_cast<const char*>(&obj), N * sizeof(T));
   } else {
      for (auto& x : obj) {
        to_bin(x, stream);
      }
   }
}

template <typename T, typename S>
void to_bin(const std::vector<T>& obj, S& stream) {
   varuint32_to_bin(obj.size(), stream);
   if (has_bitwise_serialization<T>()) {
      stream.write(reinterpret_cast<const char*>(obj.data()), obj.size() * sizeof(T));
   } else {
      for (auto& x : obj) {
         to_bin(x, stream);
      }
   }
}

template <typename T, typename S>
void to_bin(const std::list<T>& obj, S& stream) {
   to_bin_range(obj, stream);
}

template <typename T, typename S>
void to_bin(const std::deque<T>& obj, S& stream) {
   to_bin_range(obj, stream);
}

template <typename T, typename S>
void to_bin(const std::set<T>& obj, S& stream) {
   to_bin_range(obj, stream);
}

template <typename T, typename U, typename S>
void to_bin(const std::map<T, U>& obj, S& stream) {
   to_bin_range(obj, stream);
}

template <typename S>
void to_bin(const input_stream& obj, S& stream) {
   varuint32_to_bin(obj.end - obj.pos, stream);
   stream.write(obj.pos, obj.end - obj.pos);
}

template <typename First, typename Second, typename S>
void to_bin(const std::pair<First, Second>& obj, S& stream) {
   to_bin(obj.first, stream);
   return to_bin(obj.second, stream);
}

template <typename T, std::size_t N, typename S>
void to_bin(const std::array<T, N>& obj, S& stream) {
   for (const T& elem : obj) {
      to_bin(elem, stream);
   }
}

template <typename S>
void to_bin(const char& obj, S& stream) {
  stream.write(reinterpret_cast<const char*>(&obj), sizeof(obj));
}

} // namespace eosio
