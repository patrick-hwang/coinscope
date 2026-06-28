#ifndef BLACKLIST_HPP
#define BLACKLIST_HPP

#include <cstdint>

#include <netinet/in.h>
#include <unordered_set>


struct sockaddr_storage_hashfunc {
	size_t operator()(const sockaddr_storage &h) const {
		size_t seed = std::hash<decltype(h.ss_family)>{}(h.ss_family) + 0x9e3779b0;
		if (h.ss_family == AF_INET) {
			const struct sockaddr_in *sin = (const struct sockaddr_in *)&h;
			return seed ^ (std::hash<decltype(sin->sin_addr.s_addr)>{}(sin->sin_addr.s_addr) + 0x9e3779b0 + (seed << 6) + (seed >> 2));
		} else if (h.ss_family == AF_INET6) {
			const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&h;
			uint64_t a, b;
			memcpy(&a, &sin6->sin6_addr, 8);
			memcpy(&b, ((uint8_t*)&sin6->sin6_addr) + 8, 8);
			seed ^= std::hash<uint64_t>{}(a) + 0x9e3779b0 + (seed << 6) + (seed >> 2);
			return seed ^ std::hash<uint64_t>{}(b) + 0x9e3779b0 + (seed << 6) + (seed >> 2);
		}
		return seed;
	}
};

struct sockaddr_storage_eq {
	bool operator()(const sockaddr_storage &lhs, const sockaddr_storage &rhs) const {
		if (lhs.ss_family != rhs.ss_family) return false;
		if (lhs.ss_family == AF_INET) {
			const struct sockaddr_in *l = (const struct sockaddr_in *)&lhs;
			const struct sockaddr_in *r = (const struct sockaddr_in *)&rhs;
			return l->sin_addr.s_addr == r->sin_addr.s_addr;
		} else if (lhs.ss_family == AF_INET6) {
			const struct sockaddr_in6 *l = (const struct sockaddr_in6 *)&lhs;
			const struct sockaddr_in6 *r = (const struct sockaddr_in6 *)&rhs;
			return memcmp(&l->sin6_addr, &r->sin6_addr, 16) == 0;
		}
		return false;
	}
};


typedef std::unordered_set<struct sockaddr_storage, sockaddr_storage_hashfunc, sockaddr_storage_eq> ipaddr_set;

extern ipaddr_set g_blacklist;


#endif
