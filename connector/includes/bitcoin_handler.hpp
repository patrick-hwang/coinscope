#ifndef BITCOIN_HANDLER_HPP
#define BITCOIN_HANDLER_HPP

#include <cstdint>

#include <unordered_set>
#include <string>
#include <map>
#include <memory>

#include <netinet/in.h>

#include <ev++.h>

#include "read_buffer.hpp"
#include "write_buffer.hpp"

namespace bitcoin {


const uint32_t RECV_MASK = 0x0000ffff; // all receive flags should be in the mask 
const uint32_t RECV_HEADER = 0x1;
const uint32_t RECV_PAYLOAD = 0x2;
const uint32_t RECV_VERSION_INIT = 0x4; /* we initiated the handshake, now waiting to receive version */
const uint32_t RECV_VERSION_INIT_HDR = 0x8; /* we initiated the handshake, now waiting to receive version */
const uint32_t RECV_VERSION_REPLY_HDR = 0x10;
const uint32_t RECV_VERSION_REPLY = 0x20;

const uint32_t SEND_MASK = 0xffff0000;
const uint32_t SEND_MESSAGE = 0x10000;
const uint32_t SEND_VERSION_INIT = 0x20000; /* we initiated the handshake */
const uint32_t SEND_VERSION_REPLY = 0x40000;
   

class handler {
private:
	read_buffer read_queue; /* application needs to read and act on this data */

	write_buffer write_queue; /* application wants this written out across network */

	struct sockaddr_storage remote_addr;

	struct sockaddr_storage local_addr; /* address we connected on (TODO) */

	uint32_t timestamp;

	uint32_t state;

	int io_events;
	ev::io io;
	ev::timer timer; ev::tstamp last_activity;
	ev::timer active_ping_timer;
	uint32_t id;
	static uint32_t id_pool;

	inline void io_set(int e) {
		if (e != io_events) {
			io_events = e;
			io.set(io_events);
		}
	}

public:
	handler(int fd, uint32_t a_state, const struct sockaddr_storage &a_remote_addr, const struct sockaddr_storage &a_local_addr);
	~handler();
	uint32_t get_id() const { return id; }
	void handle_message_recv(const struct packed_message *msg);
	void io_cb(ev::io &watcher, int revents);
	void pinger_cb(ev::timer &w, int revents);
	void active_pinger_cb(ev::timer &w, int revents);
	struct sockaddr_storage get_remote_addr() const { return remote_addr; }
	struct sockaddr_storage get_local_addr() const { return local_addr; }
	/* appends message, leaves write queue unseeked, but increments to_write. */
	void append_for_write(const struct packed_message *m);
	void append_for_write(std::unique_ptr<struct packed_message> m);
	/* this is an optimized call for reducing copies. buf better be a packed_message internally */
	void append_for_write(wrapped_buffer<uint8_t> buf); 
	void disconnect();
private:
	void suicide(); /* get yourself ready for suspension (e.g., stop loop activity) if safe, just delete self */
	/* could implement move operators, but others are odd */
	handler & operator=(handler other);
	handler(const handler &);
	handler(const handler &&other);
	handler & operator=(handler &&other);


	void start_pingers();
	void do_read(ev::io &watcher, int revents);
	void do_write(ev::io &watcher, int revents);
};

struct handler_hashfunc {
	size_t operator()(const std::unique_ptr<handler> &h) const {
		return std::hash<uint32_t>()(h->get_id());
	}
};

struct handler_equal {
	bool operator()(const std::unique_ptr<handler> &lhs, const std::unique_ptr<handler> &rhs) const {
		return lhs->get_id() == rhs->get_id();
	}
};


typedef std::unordered_set<std::unique_ptr<handler>, handler_hashfunc, handler_equal> handler_set;
typedef std::map<uint32_t, std::unique_ptr<handler> > handler_map;

/* since I have to work with libev, hard to get away from raw pointers */
extern handler_map g_active_handlers;
extern handler_set g_inactive_handlers;

class connect_handler { /* for non-blocking connectors */
public:
	/* fd should be non-blocking socket. Connect has not been called yet */
	connect_handler(int fd, const struct sockaddr_storage &remote_addr); 
	void io_cb(ev::io &watcher, int revents);
	~connect_handler();
private:
	struct sockaddr_storage remote_addr_;
	ev::io io;
	void setup_handler(int fd);
	connect_handler & operator=(connect_handler other);
	connect_handler(const connect_handler &);
	connect_handler(const connect_handler &&other);
	connect_handler & operator=(connect_handler &&other);
};


class accept_handler {
public:
	accept_handler(int fd, const struct sockaddr_storage &a_local_addr); /* fd should be a listening, non-blocking socket */
	void io_cb(ev::io &watcher, int revents);
	~accept_handler();
private:
	struct sockaddr_storage local_addr; /* left in network byte order */
	ev::io io;
	accept_handler & operator=(accept_handler other);
	accept_handler(const accept_handler &);
	accept_handler(const accept_handler &&other);
	accept_handler & operator=(accept_handler &&other);
};

/* Tor SOCKS5 connect handler for .onion addresses */
class tor_connect_handler {
public:
	tor_connect_handler(const struct sockaddr_storage &onion_addr);
	tor_connect_handler(const struct sockaddr_storage &onion_addr, const char *hostname);
	void io_cb(ev::io &watcher, int revents);
	~tor_connect_handler();
private:
	enum tor_state {
		TOR_CONNECT_PROXY,
		TOR_SEND_GREETING,
		TOR_RECV_GREETING,
		TOR_SEND_CONNECT,
		TOR_RECV_CONNECT,
		TOR_HANDSHAKE_DONE
	};
	struct sockaddr_storage remote_addr_; /* the .onion target address */
	struct sockaddr_in proxy_addr_;       /* Tor SOCKS5 proxy (127.0.0.1:9050) */
	ev::io io;
	int fd_;
	tor_state state_;
	char onion_host_[64];
	uint16_t onion_port_;
	int written_;
	int to_write_;
	void advance();
	/* Send the SOCKS5 greeting */
	void send_greeting();
	/* Parse SOCKS5 greeting response */
	void recv_greeting();
	/* Send SOCKS5 connect command */
	void send_connect();
	/* Parse SOCKS5 connect response */
	void recv_connect();
	tor_connect_handler & operator=(tor_connect_handler other) = delete;
	tor_connect_handler(const tor_connect_handler &) = delete;
	tor_connect_handler(const tor_connect_handler &&other) = delete;
	tor_connect_handler & operator=(tor_connect_handler &&other) = delete;
};

};

#endif
