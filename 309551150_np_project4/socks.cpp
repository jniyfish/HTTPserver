#include <iostream>
#include <stdlib.h>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <cstdlib>
#include <cstring>
#include <string>
#include <array>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

using namespace std;
using namespace boost::asio;
io_service ioservice;
static void sig_handler (int sig);
const char config_file[] = "socks.conf";


typedef struct http_header_info
{
	string method;
	string path;
	string protocol;
	string host;
	string uri;
	string query;

}http_header_info;

class Session : public std::enable_shared_from_this<Session>
{
	private:
		ip::tcp::socket socket_;
		ip::tcp::resolver resolver;
		array<unsigned char, 4096> bytes_;
		http_header_info header_info;
		std::vector<unsigned char> in_buf_;
		std::vector<unsigned char> out_buf_;
		std::string remote_host_;
		std::string remote_port_;
		ip::tcp::socket out_socket_;
		boost::asio::ip::tcp::endpoint remote_ep;
		boost::asio::ip::address remote_ad;
		ip::tcp::acceptor acceptor;
		std::string s;

	public:
		Session(io_service &ioservice): 
		socket_(ioservice), 
		resolver(ioservice), 
		in_buf_(4096) ,
		out_buf_(4096) ,
		out_socket_(ioservice),
		acceptor(ioservice, ip::tcp::endpoint(ip::tcp::v4(), 0))
		{}

		ip::tcp::socket &socket(){
			return socket_;
		}
		void start(){
			signal (SIGCHLD, sig_handler);
			auto h =  boost::bind(&Session::read_handler, this, _1, _2);
			remote_ep = socket_.remote_endpoint();
			remote_ad = remote_ep.address();
			s = remote_ad.to_string();
			socket_.async_read_some(buffer(in_buf_), h );
		}
	
		void read_handler(const boost::system::error_code &ec, size_t bytes_transferred){
			if (!ec){
				if ( in_buf_[0] == 0x04){
					remote_host_ = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf_[4]))).to_string();
					remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf_[2])));

					if(in_buf_[4]== 0x00 && in_buf_[5] == 0x00 && in_buf_[6] == 0x00 ){
						//SOCK4A
						int domain[1024];
						char value[1024]={0};
						for(size_t i=9,j=0;;i++,j++ ){
							if(in_buf_[i] == 0x00)
								break;
							domain[j]  = in_buf_[i];
							value[j] = domain[j];
						}
						string fuck ="";
						fuck += value;
						srand( time(NULL) );
						int x = rand();
						string port = to_string(x);
						string portE = "443";
						boost::asio::io_service iossss;
						ip::tcp::resolver res(iossss);
						ip::tcp::resolver::query queryA(ip::tcp::v4(), value, portE);
						ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(queryA);
						for (ip::tcp::resolver::iterator iter; endpoint_iterator != iter; endpoint_iterator++){
							remote_host_ = endpoint_iterator->endpoint().address().to_string();
							remote_port_ =   std::to_string(endpoint_iterator->endpoint().port());
						}
					}
					
					if(in_buf_[1] == 0x01){		
						cout << "DEBUG"<< endl;		
						do_resolve();	
					}
					else if (in_buf_[1] == 0x02){
						do_passive_tcp();
					}
					else 
						cout << "DEBUG"<< endl;
				}
			}
		}
		void do_passive_tcp(){
			auto h = boost::bind(&Session::handler, this, _1);
			acceptor.async_accept(out_socket_, h);
			int bindPermit = 0;
			FILE	*conf = fopen (config_file, "r");
			boost::asio::io_service iosss;
			ip::tcp::resolver res(iosss);
			ip::tcp::resolver::query queryA(remote_host_, remote_port_);
			ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(queryA);
			for (ip::tcp::resolver::iterator iter; endpoint_iterator != iter; endpoint_iterator++)
    		{
				char buf[1024];
				while(fgets(buf, 1024, conf) ){
					bindPermit = 0;
    		    	string str = endpoint_iterator->endpoint().address().to_string();
					char *questIP = new char[str.length() + 1];
            		strcpy(questIP, str.c_str());
					if(buf[7]=='b')
						bindPermit +=1;
					bool fuckingflag =  true;
					for(size_t i=9,j=0; i<strlen(buf);i++,j++){
						if(buf[i]=='*')
							break;
						if(buf[i] != questIP[j]){
							fuckingflag = false;
							break;
						}
					}
					if(fuckingflag == true)
						bindPermit += 1;
					if(bindPermit == 2)
						break;
				}
    		}
			cout << "<S_IP>: " << s << endl;
			cout << "<S_PORT>: " << remote_ep.port() << endl;
			cout << "<D_IP>: " << remote_host_ << endl;
			cout << "<D_PORT>: " << remote_port_ << endl;
			cout << "<Command>: BIND" << endl;
			int port =  acceptor.local_endpoint().port();
			unsigned char reply[8];
			reply[0] = 0;
			reply[1] = 90;
			reply[2] = port / 256;
			reply[3] = port % 256;
			for(int i = 4; i < 8; i++) {
				reply[i] = 0;
			}
			if(bindPermit != 2){
				reply[1] = 91;
				cout << "<Reply>: Reject\n" << endl;
			}
			else if(bindPermit == 2){
				cout << "<Reply>: Accept\n" << endl;
			}
			boost::asio::write(socket_, boost::asio::buffer(reply, 8));
			fclose(conf);
		}
		void do_resolve(){
			ip::tcp::resolver::query query(remote_host_, remote_port_);
			resolver.async_resolve(query,
			[this](const boost::system::error_code& ec, ip::tcp::resolver::iterator it)
			{
				if (!ec)
				{
					do_connect(it);
				}
			});
		}
		void do_connect(ip::tcp::resolver::iterator& it){
			out_socket_.async_connect(*it, 
			[this](const boost::system::error_code& ec)
			{
				if (!ec)
				{
					int connectPermit = 0;
					FILE	*conf = fopen (config_file, "r");
					boost::asio::io_service ioss;
					ip::tcp::resolver res(ioss);
					ip::tcp::resolver::query queryA(remote_host_, remote_port_);
					ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(queryA);
					for (ip::tcp::resolver::iterator iter; endpoint_iterator != iter; endpoint_iterator++)
    				{
						char buf[1024];
						while(fgets(buf, 1024, conf) ){
							connectPermit = 0;
    				    	string str = endpoint_iterator->endpoint().address().to_string();
							char *questIP = new char[str.length() + 1];
            				strcpy(questIP, str.c_str());
							if(buf[7]=='c')
								connectPermit +=1;
							bool fuckingflag =  true;
							for(size_t i=9,j=0; i<strlen(buf);i++,j++){
								if(buf[i]=='*')
									break;
								if(buf[i] != questIP[j]){
									fuckingflag = false;
									break;
								}
							}
							if(fuckingflag == true)
								connectPermit += 1;
							if(connectPermit == 2)
								break;
						}
    				}
					fclose(conf);
					cout << "<S_IP>: " << s << endl;
					cout << "<S_PORT>: " << remote_ep.port() << endl;
					cout << "<D_IP>: " << remote_host_ << endl;
					cout << "<D_PORT>: " << remote_port_ << endl;
					cout << "<Command>: CONNECT" << endl;
					in_buf_[0] = 0x00; in_buf_[1] = 0x5A;
					in_buf_[2] = 0x00; in_buf_[3] = 0x00; 
					in_buf_[4] = 0x00; in_buf_[5] = 0x00; 
					in_buf_[6] = 0x00; in_buf_[7] = 0x00; 
					if( connectPermit != 2 ){
						in_buf_[1] = 0x5B;
						cout << "<Reply>: Reject\n" << endl;
					}
					else if( connectPermit == 2 ){
						cout << "<Reply>: Accept\n" << endl;
					}
					boost::asio::async_write(socket_, boost::asio::buffer(in_buf_, 8), // Always 10-byte according to RFC1928
					[this](boost::system::error_code ec, std::size_t length)
					{
						if (!ec)
						{}
					});
					do_read(3);
				}
			});
		}
		void do_read(int direction){
			if (direction & 0x1)
				socket_.async_receive(boost::asio::buffer(in_buf_),
					[this](boost::system::error_code ec, std::size_t length)
					{
						if (!ec)
						{
							std::ostringstream what; what << "--> " << std::to_string(length) << " bytes";

							do_write(1, length);
						}

					});

			if (direction & 0x2)
				out_socket_.async_receive(boost::asio::buffer(out_buf_),
					[this](boost::system::error_code ec, std::size_t length)
					{
						if (!ec)
						{
							std::ostringstream what; what << "<-- " << std::to_string(length) << " bytes";

							do_write(2, length);
						} 
					});
		}
		void do_write(int direction, std::size_t Length){		
				switch (direction)
				{
				case 1:
					boost::asio::async_write(out_socket_, boost::asio::buffer(in_buf_, Length),
						[this, direction](boost::system::error_code ec, std::size_t length)
						{
							if (!ec)
								do_read(direction);

						});
					break;
				case 2:
					boost::asio::async_write(socket_, boost::asio::buffer(out_buf_, Length),
						[this, direction](boost::system::error_code ec, std::size_t length)
						{
							if (!ec)
								do_read(direction);

						});
					break;
				}
		}
		void handler(const boost::system::error_code &ec){
			if (!ec){
					cout << out_socket_.remote_endpoint().address() << endl;
					unsigned char reply[8];
					cout << "send second reply\n";
					reply[0] = 0;
					reply[1] = 90;
					reply[2] = 0;	
					reply[3] = 0;
					boost::asio::write(socket_,buffer(reply, 8));
					do_read(3);
				}
		}

};

class server{
	private:
		io_service &ioservice_;
		ip::tcp::acceptor acceptor_;

	public:
		server(io_service &ioservice, int port)
			:   ioservice_(ioservice), 
			acceptor_(ioservice, ip::tcp::endpoint(ip::tcp::v4(), port)) //bind port
		{
			do_accept();
		}
		void do_accept(){	
			Session* new_session = new Session(ioservice_);
			auto h = boost::bind(&server::handler, this, _1, new_session);
			acceptor_.async_accept(new_session->socket(),h);
		}
		void handler(const boost::system::error_code &ec, Session* new_session){
			if (!ec){
				ioservice_.notify_fork(boost::asio::io_service::fork_prepare);
				if( fork()==0){
					ioservice_.notify_fork(boost::asio::io_service::fork_child);
					new_session->start();
				}
				else{
					ioservice_.notify_fork(boost::asio::io_service::fork_child);
					do_accept();
				}
			}
		}

};
int main(int argc, char* argv[]){
	signal (SIGCHLD, sig_handler);
	try{
		if (argc != 2){
			std::cerr << "Usage: async_tcp_echo_server <port>\n";
			return EXIT_FAILURE;
		}

		server s(ioservice, atoi(argv[1]));
		ioservice.run();
	}
	catch(std::exception& e){
		std::cerr << "Exception: " << e.what() << "\n";
		exit(EXIT_FAILURE);
	}
	return EXIT_SUCCESS;
}

static void sig_handler (int sig){
	if (sig == SIGCHLD)
		while (waitpid (-1, NULL, WNOHANG) > 0);
	signal (sig, sig_handler);
}