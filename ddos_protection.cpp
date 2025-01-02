#include <iostream>
#include <pcap.h>
#include <unordered_map>
#include <string>
#include <chrono>
#include <thread>
// #include <arpa/inet.h>
// #include <sys/socket.h>

std::unordered_map<std::string, int> ipRequestCount;
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ip *ipHeader = (struct ip *)(packet + 14);
    std::string clientIp = inet_ntoa(ipHeader->ip_src);
    ipRequestCount[clientIp]++;
}


void printTrafficPerSecond(){
    while(true){
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "[+] Requests in last second:" << std::endl;
        for (const auto &entry : ipRequestCount){
            std::cout << entry.second << " Requests/S    FROM " << entry.first << std::endl;
        }
        ipRequestCount.clear();
    }}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr){
        std::cerr << "[ERROR] Something broke idk: " << errbuf << std::endl;
        return 1;
    }
    
     std::cout << "[+] DDoS Real-Time Protection - [ACTIVE]" << std::endl;
     std::thread printThread(printTrafficPerSecond);
        pcap_loop(handle, 0, packetHandler, nullptr);
      pcap_close(handle);
      printThread.join();
    return 0;
}
