/* standard C libraries */
#include <cstdlib>
#include <cstring>
#include <cassert>


/* standard C++ libraries */
#include <vector>
#include <set>
#include <random>
#include <utility>
#include <iostream>
#include <fstream>

/* standard unix libraries */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>

/* third party libraries */
#include <ev++.h>

/* our libraries */
#include "autogen.hpp"
#include "bitcoin.hpp"
#include "bitcoin_handler.hpp"
#include "command_handler.hpp"
#include "iobuf.hpp"
#include "netwrap.hpp"
#include "logger.hpp"
#include "network.hpp"
#include "config.hpp"
#include "blacklist.hpp"

using namespace std;

namespace bc = bitcoin;

ipaddr_set g_blacklist;


static void log_watcher(ev::timer &w, int /*revents*/) {
	if (g_log_buffer == nullptr) {
		try {
			g_log_buffer = new log_buffer(unix_sock_client(*static_cast<string*>(w.data), true));
		} catch(const network_error &e) {
			g_log_buffer = nullptr;
			g_log<ERROR>(e.what());
		}
	}
}

static void load_blacklist() {
	const libconfig::Config *cfg(get_config());
	const char *filename = cfg->lookup("connector.blacklist");
	ifstream file(filename);;

	if (file) {
		g_blacklist.clear();

		string line;
		struct sockaddr_storage entry;
		bzero(&entry, sizeof(entry));

		while(getline(file, line)) {
			if (inet_pton(AF_INET, line.c_str(), &((struct sockaddr_in*)&entry)->sin_addr) == 1) {
				entry.ss_family = AF_INET;
				g_blacklist.insert(entry);
			} else if (inet_pton(AF_INET6, line.c_str(), &((struct sockaddr_in6*)&entry)->sin6_addr) == 1) {
				entry.ss_family = AF_INET6;
				g_blacklist.insert(entry);
			} else {
				g_log<ERROR>("Invalid blacklist entry (not IPv4 or IPv6)", line);
			}
		}
	
		g_log<CONNECTOR>("Loading blacklist, received", g_blacklist.size(), "unique entries");
	} else {
		g_log<ERROR>("Could not open blacklist file");
	}

	file.close();

}

static void hup_watcher(ev::sig & /*s*/, int /* revents */) {
	load_blacklist();
}


int main(int argc, char *argv[]) {

	/* check limits or no point */

	struct rlimit limit;
	if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
		cerr << "Could not get limit\n";
		return EXIT_FAILURE;
	}

	if (limit.rlim_cur < 999900) {
		cerr << "limit too low, aborting (" << limit.rlim_cur << ")\n";
		return EXIT_FAILURE;
	}


	if (startup_setup(argc, argv) != 0) {
		return EXIT_FAILURE;
	}

	const libconfig::Config *cfg(get_config());
	const char *config_file = cfg->lookup("version").getSourceFile();

	signal(SIGPIPE, SIG_IGN);

	cerr << "Starting up and transferring to log server" << endl;

	string root((const char*)cfg->lookup("logger.root"));
	string logpath = root + "servers";
	try {
		g_log_buffer = new log_buffer(unix_sock_client(logpath, true));
	} catch (const network_error &e) {
		cerr << "WARNING: Could not connect to log server! " << e.what() << endl;
	}


	ev::timer logwatch;
	logwatch.set<log_watcher>(&logpath);
	logwatch.set(10.0, 10.0);
	logwatch.start();

	ev::sig sigwatch;
	sigwatch.set<hup_watcher>();
	sigwatch.set(SIGHUP);
	sigwatch.start();

	const char *control_filename = cfg->lookup("connector.control_path");
	unlink(control_filename);

	struct sockaddr_un control_addr;
	bzero(&control_addr, sizeof(control_addr));
	control_addr.sun_family = AF_UNIX;
	strcpy(control_addr.sun_path, control_filename);

	int control_sock = Socket(AF_UNIX, SOCK_STREAM, 0);
	fcntl(control_sock, F_SETFL, O_NONBLOCK);
	Bind(control_sock, (struct sockaddr*)&control_addr, strlen(control_addr.sun_path) + 
	     sizeof(control_addr.sun_family));
	Listen(control_sock, cfg->lookup("connector.control_listen"));

	ev::default_loop loop;


	vector<unique_ptr<bc::accept_handler> > bc_accept_handlers;

	libconfig::Setting &list = cfg->lookup("connector.bitcoin.listeners");
	for(int index = 0; index < list.getLength(); ++index) {
		libconfig::Setting &setting = list[index];
		string family((const char*)setting[0]);
		string addr_str((const char*)setting[1]);
		uint16_t port((int)setting[2]);
		int backlog(setting[3]);

		g_log<DEBUG>("Attempting to instantiate listener on ", family,
		               addr_str, port, "with backlog", backlog);

		struct sockaddr_storage bitcoin_addr;
		bzero(&bitcoin_addr, sizeof(bitcoin_addr));
		int domain;
		socklen_t addrlen;

		if (family == "AF_INET6") {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&bitcoin_addr;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(port);
			sin6->sin6_addr = in6addr_any;
			domain = AF_INET6;
			addrlen = sizeof(*sin6);
			if (inet_pton(AF_INET6, addr_str.c_str(), &sin6->sin6_addr) != 1) {
				g_log<ERROR>("Bad IPv6 address format on address", index, strerror(errno));
				continue;
			}
			sin6->sin6_addr = in6addr_any;
		} else {
			struct sockaddr_in *sin = (struct sockaddr_in *)&bitcoin_addr;
			sin->sin_family = AF_INET;
			sin->sin_port = htons(port);
			sin->sin_addr.s_addr = INADDR_ANY;
			domain = AF_INET;
			addrlen = sizeof(*sin);
			if (inet_pton(AF_INET, addr_str.c_str(), &sin->sin_addr) != 1) {
				g_log<ERROR>("Bad IPv4 address format on address", index, strerror(errno));
				continue;
			}
			sin->sin_addr.s_addr = INADDR_ANY;
		}

		int bitcoin_sock = Socket(domain, SOCK_STREAM, 0);
		fcntl(bitcoin_sock, F_SETFL, O_NONBLOCK);
		int optval = 1;
		setsockopt(bitcoin_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		Bind(bitcoin_sock, (struct sockaddr*)&bitcoin_addr, addrlen);
		Listen(bitcoin_sock, backlog);

		bc_accept_handlers.emplace_back(new bc::accept_handler(bitcoin_sock, bitcoin_addr));

	}


	ctrl::accept_handler ctrl_handler(control_sock);


	{
		ifstream cfile(config_file);
		string s("");
		string line;
		for(string line; getline(cfile,line);) {
			s += line + "\n";
		}
		g_log<CONNECTOR>("Initiating with commit: ", commit_hash);
		g_log<CONNECTOR>("Full config: ", s);
		cfile.close();
	}

	load_blacklist();
	
	while(true) {
		/* add timer to attempt recreation of lost control channel */
		loop.run();
	}
	
	g_log<CONNECTOR>("Orderly shutdown");
	return EXIT_SUCCESS;
}
