#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

int requestAndReceiveHTTPS(const std::string& serverName, const std::string& path) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;

    std::string requestLine = "GET " + path + " HTTP/1.0\r\n";
    requestLine += "User-agent: my463Crawler/1.1\r\n";
    requestLine += "Host: " + serverName + "\r\n";
    requestLine += "Connection: close\r\n\r\n";

    const char* sendbuf = requestLine.c_str();
    char recvbuf[512];
    int iResult;
    int recvbuflen = 512;

    SSL_CTX* ctx;
    SSL* ssl;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed with error: " << iResult << std::endl;
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(serverName.c_str(), "443", &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed with error: " << iResult << std::endl;
        WSACleanup();
        return 1;
    }

    // Attempt to connect to the first address returned by getaddrinfo
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to the server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            std::cerr << "Socket failed with error: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return 1;
        }

        // Connect to server
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        std::cerr << "Unable to connect to server!" << std::endl;
        WSACleanup();
        return 1;
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create an SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Create an SSL structure
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, ConnectSocket);

    // Establish an SSL connection
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL connect failed" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
    iResult = SSL_write(ssl, sendbuf, (int)strlen(sendbuf));
    if (iResult <= 0) {
        std::cerr << "SSL write failed" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }
    std::cout << "Wrote to " << serverName << ": \n" << sendbuf << std::endl;
    std::cout << "Received: \n" << std::endl;
    // Receive data until the server closes the connection
    do {
        iResult = SSL_read(ssl, recvbuf, recvbuflen);
        if (iResult > 0)
            std::cout << recvbuf;
        else if (iResult == 0)
            std::cout << "Connection closed" << std::endl;
        else {
            std::cerr << "SSL read failed" << std::endl;
            ERR_print_errors_fp(stderr);
            break;
        }
    
    } while (iResult > 0);

    
    // Cleanup
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}


int main()
{
    requestAndReceiveHTTPS("quotes.toscrape.com", "/author/Albert-Einstein/");
}

