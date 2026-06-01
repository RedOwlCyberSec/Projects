// adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/PROJECTS/beginner/simple-port-scanner/

#include "PortScanner.hpp"
#include <fstream>
#include <iostream>

const std::unordered_map<uint16_t, std::string> PortScanner::basicPorts{
	{21, "FTP"},
	{22, "SSH"},
	{23, "TelNet"},
	{25, "SMTP"},
	{53, "DNS"},
	{67, "DHCP server"},
	{68, "DHCP client"},
	{80, "HTTP"},
	{110, "POP3"},
	{143, "IMAP"},
	{161, "SNMP"},
	{443, "HTTPS"},
	{445, "SMB"},
	{465, "SMTPS"},
	{993, "IMAPS"},
	{1080, "SOCKS"},
	{1521, "ORACLE DB"},
	{3306, "MySQL"},
	{3389, "RDP"},
	{5432, "PostgreSQL"},
	{6379, "Redis"},
};

void PortScanner::parse_port(std::string& port) {
	auto t = std::find(port.begin(), port.end(), '-');
	if (t == port.end()) {
		startPort = 1;
		endPort = std::stoi(port);
		return;
	}
	auto it = port.begin();
	std::string s = "", e = "";
	while (it != port.end()) {
		if (*it == '-') {
			break;
		}
		s += *it;
		++it;
	}
	++it;
	while (it != port.end()) {
		e += *it;
		++it;
	}

	int start = std::stoi(s);
	int end = std::stoi(e);
	//check a valid bounds
	if (start == 0 || end > MAX_PORT || start > end) {
		startPort = 1;
		endPort = MAX_PORT;
	}
	else {
		startPort = static_cast<uint16_t>(start);
		endPort = static_cast<uint16_t>(end);
	}
}
PortScanner::PortScanner(std::string& domainName, std::string& port, int max_threads, std::uint8_t expiry_time) {
	this->domainName = std::move(domainName);
	this->MAX_THREADS = max_threads;
	this->expiry_time = expiry_time;

	parse_port(port);
	auto result = resolver.resolve(this->domainName, "");
	endpoint = *result.begin();

	setup_queue();

}

void PortScanner::setup_queue() {
	q = std::queue<uint16_t>();
	for (int i = startPort; i <= endPort; i++) {
		q.push(i);
	}
}


void PortScanner::set_options(std::string& domainName, std::string& port, int max_threads, std::uint8_t expiry_time) {
	this->domainName = std::move(domainName);
	this->MAX_THREADS = max_threads;
	this->expiry_time = expiry_time;
	parse_port(port);


	auto result = resolver.resolve(this->domainName, "");
	endpoint = *result.begin();


}

void PortScanner::show_progress() {
    // Calculate the progress percentage
    float progress = static_cast<float>(open_ports + closed_ports + filtered_ports) / (endPort - startPort + 1);
    int barWidth = 70; // Width of the progress bar
    int pos = barWidth * progress;

    // Print the progress bar
    std::cout << "[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos)
            std::cout << "="; // Progress indicator
        else
            std::cout << " "; // Empty space
    }
    std::cout << "] " << int(progress * 100.0f) << " %\r"; // '\r' to return to the start of the line
    std::cout.flush(); // Flush the output to ensure it displays immediately
}


void PortScanner::set_max_port(std::uint16_t port) {
	endPort = port;
}
void PortScanner::set_max_threads(int value) {
	MAX_THREADS = value;
}

void PortScanner::set_ip_address(std::string ip) {
	domainName = std::move(ip);

}

void PortScanner::set_expiry_time(std::uint8_t value) {
	expiry_time = value;
}

void PortScanner::start() {
	setup_queue();
	for (int i = 0; i < MAX_THREADS; i++) {
		boost::asio::post(strand, [this]() {
			scan();
		});

	}
}

void PortScanner::run() {
    std::ofstream outputFile("port_scan_results.csv");
    
    if (outputFile.is_open()) {
        outputFile << "PORT,STATE,SERVICE,BANNER\n";  // CSV header
    }

    io.run();
    
    // After the scan completes
    outputFile << "\nSummary\n";
    outputFile << "Open ports: " << open_ports << "\n";
    outputFile << "Closed ports: " << closed_ports << "\n";
    outputFile << "Filtered ports: " << filtered_ports << "\n";
    
    outputFile.close();
}

void PortScanner::scan() {
    if (q.empty() || cnt >= MAX_THREADS) return;

    uint16_t port = q.front();
    q.pop();
    ++cnt;

    auto socket = std::make_shared<tcp::socket>(io);
    auto timer = std::make_shared<boost::asio::steady_timer>(io);
    auto complete = std::make_shared<bool>(false);

    tcp::endpoint endpoint(this->endpoint.address(), port);

    timer->expires_after(std::chrono::seconds(expiry_time));

    timer->async_wait(boost::asio::bind_executor(strand, [this, complete, socket, port](boost::system::error_code ec) {
        if (!ec && !*complete)  {
            *complete = true;
            socket->close();
            std::ofstream outputFile("port_scan_results.csv", std::ios_base::app);
            if (outputFile.is_open()) {
                outputFile << port << ",FILTERED,NULL,NULL\n";
            }
            ++filtered_ports;
            --cnt;
            show_progress(); // Update progress bar
            scan();
        }
    }));

    socket->async_connect(endpoint, boost::asio::bind_executor(strand, [this,socket, timer, port, complete](boost::system::error_code ec) {
        if (*complete) return;
        *complete = true;
        timer->cancel();

        std::string service = "---";
        auto banner = std::make_shared<std::string>("---");
        auto it = basicPorts.find(port);
        if (it != basicPorts.end()) {
            service = it->second;
        }

        if (!ec) {
            auto buf = std::make_shared<std::array<char, 128>>();
            socket->async_read_some(boost::asio::buffer(*buf),boost::asio::bind_executor(strand,
            [this, port, buf, banner, service](boost::system::error_code ec, std::size_t n) {
                if (!ec && n > 0) {
                    banner->assign(buf->data(), n);
                }
                std::ofstream outputFile("port_scan_results.csv", std::ios_base::app);
                if (outputFile.is_open()) {
                    outputFile << port << ",OPEN," << service.c_str() << "," << banner->c_str() << "\n";
                }
                ++open_ports;
                --cnt;
                show_progress(); // Update progress bar
                scan();
            }));
        } else {
            std::ofstream outputFile("port_scan_results.csv", std::ios_base::app);
            if (outputFile.is_open()) {
                outputFile << port << ",CLOSED," << service.c_str() << ",NULL\n";
            }
            ++closed_ports;
            --cnt;
            show_progress(); // Update progress bar
            scan();
        }
    }));
}

