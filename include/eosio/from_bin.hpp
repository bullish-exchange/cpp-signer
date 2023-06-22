#pragma once

#include <eosio/stream.hpp>

#include <deque>
#include <list>
#include <map>
#include <set>
#include <tuple>
#include <vector>
#include <string>

namespace eosio {

template <typename T, typename S>
void from_bin(T& obj, S& stream);

template <typename S>
void varuint32_from_bin(uint32_t& dest, S& stream) {
   dest          = 0;
   int     shift = 0;
   uint8_t b     = 0;
   do {
      check( shift < 35, convert_stream_error(stream_error::invalid_varuint_encoding) );
      from_bin(b, stream);
      dest |= uint32_t(b & 0x7f) << shift;
      shift += 7;
   } while (b & 0x80);
}

template <typename S>
void varuint64_from_bin(uint64_t& dest, S& stream) {
   dest          = 0;
   int     shift = 0;
   uint8_t b     = 0;
   do {
      check( shift < 70, convert_stream_error(stream_error::invalid_varuint_encoding) );
      from_bin(b, stream);
      dest |= uint64_t(b & 0x7f) << shift;
      shift += 7;
   } while (b & 0x80);
}

template <typename S>
void varint32_from_bin(int32_t& result, S& stream) {
   uint32_t v;
   varuint32_from_bin(v, stream);
   if (v & 1)
      result = ((~v) >> 1) | 0x80000000;
   else
      result = v >> 1;
}

template <typename T, typename S>
void from_bin_assoc(T& v, S& stream) {
   uint32_t size;
   varuint32_from_bin(size, stream);
   for (size_t i = 0; i < size; ++i) {
      typename T::value_type elem;
      from_bin(elem, stream);
      v.emplace(elem);
   }
}

template <typename T, typename S>
void from_bin_sequence(T& v, S& stream) {
   uint32_t size;
   varuint32_from_bin(size, stream);
   for (size_t i = 0; i < size; ++i) {
      v.emplace_back();
      from_bin(v.back(), stream);
   }
}

template <typename T, std::size_t N, typename S>
void from_bin(T (&v)[N], S& stream) {
   uint32_t size;
   varuint32_from_bin(size, stream);
   check( size == N, convert_stream_error(stream_error::array_size_mismatch) );
   if (has_bitwise_serialization<T>()) {
      stream.read(reinterpret_cast<char*>(v), size * sizeof(T));
   } else {
      for (size_t i = 0; i < size; ++i) {
         from_bin(v[i], stream);
      }
   }
}

template <typename T, typename S>
void from_bin(std::vector<T>& v, S& stream) {
   if (has_bitwise_serialization<T>()) {
      if (sizeof(size_t) >= 8) {
         uint64_t size;
         varuint64_from_bin(size, stream);
         stream.check_available(size * sizeof(T));
         v.resize(size);
         stream.read(reinterpret_cast<char*>(v.data()), size * sizeof(T));
      } else {
         uint32_t size;
         varuint32_from_bin(size, stream);
         stream.check_available(size * sizeof(T));
         v.resize(size);
         stream.read(reinterpret_cast<char*>(v.data()), size * sizeof(T));
      }
   } else {
      uint32_t size;
      varuint32_from_bin(size, stream);
      v.resize(size);
      for (size_t i = 0; i < size; ++i) {
         from_bin(v[i], stream);
      }
   }
}

template <typename T, typename S>
void from_bin(std::set<T>& v, S& stream) {
   return from_bin_assoc(v, stream);
}

template <typename T, typename U, typename S>
void from_bin(std::map<T, U>& v, S& stream) {
   uint32_t size;
   varuint32_from_bin(size, stream);
   for (size_t i = 0; i < size; ++i) {
      std::pair<T, U> elem;
      from_bin(elem, stream);
      v.emplace(elem);
   }
}

template <typename T, typename S>
void from_bin(std::deque<T>& v, S& stream) {
   return from_bin_sequence(v, stream);
}

template <typename T, typename S>
void from_bin(std::list<T>& v, S& stream) {
   return from_bin_sequence(v, stream);
}

template <typename S>
void from_bin(input_stream& obj, S& stream) {
   if (sizeof(size_t) >= 8) {
      uint64_t size;
      varuint64_from_bin(size, stream);
      stream.check_available(size);
      stream.read_reuse_storage(obj.pos, size);
      obj.end = obj.pos + size;
   } else {
      uint32_t size;
      varuint32_from_bin(size, stream);
      stream.check_available(size);
      stream.read_reuse_storage(obj.pos, size);
      obj.end = obj.pos + size;
   }
}

template <typename First, typename Second, typename S>
void from_bin(std::pair<First, Second>& obj, S& stream) {
   from_bin(obj.first, stream);
   from_bin(obj.second, stream);
}

template <typename S>
inline void from_bin(std::string& obj, S& stream) {
   uint32_t size;
   varuint32_from_bin(size, stream);
   obj.resize(size);
   stream.read(obj.data(), obj.size());
}

template <typename T, std::size_t N, typename S>
void from_bin(std::array<T, N>& obj, S& stream) {
   for (T& elem : obj) {
      from_bin(elem, stream);
   }
}

template <typename S>
void from_bin(char& obj, S& stream) {
  stream.read(reinterpret_cast<char*>(&obj), sizeof(char));
}

template <typename S>
void from_bin(unsigned char& obj, S& stream) {
  stream.read(reinterpret_cast<char*>(&obj), sizeof(char));
}

} // namespace eosio
