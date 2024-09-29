#include <iostream>
#include <string>
#include <curl/curl.h>  
#include <openssl/evp.h>  
#include <openssl/hmac.h> 
#include <sstream>
#include <iomanip>
#include <json/json.h>
using namespace std;

// Define API Key and Secret
std::string apiKey = "mx0vglrx6MexRTXWDf";
std::string apiSecret = "1d9fd17022fb4675a41053f36dd1e3f5";
std::string baseUrl = "https://futures.testnet.mexc.com";

// Function to sign requests
std::string signRequest(const std::string& message, const std::string& secret) {
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        std::cerr << "Failed to fetch HMAC implementation" << std::endl;
        return "";
    }

    EVP_MAC_CTX* mac_ctx = EVP_MAC_CTX_new(mac);
    if (!mac_ctx) {
        std::cerr << "Failed to create HMAC context" << std::endl;
        EVP_MAC_free(mac);
        return "";
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(mac_ctx, (const unsigned char*)secret.c_str(), secret.length(), params) != 1) {
        std::cerr << "Failed to initialize HMAC with secret" << std::endl;
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return "";
    }

    if (EVP_MAC_update(mac_ctx, (const unsigned char*)message.c_str(), message.length()) != 1) {
        std::cerr << "Failed to update HMAC with message" << std::endl;
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return "";
    }

    unsigned char result[EVP_MAX_MD_SIZE];
    size_t len = 0;
    if (EVP_MAC_final(mac_ctx, result, &len, sizeof(result)) != 1) {
        std::cerr << "Failed to finalize HMAC" << std::endl;
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        return "";
    }

    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);

    std::stringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
    }

    return ss.str();
}

// Callback function for CURL to handle the response
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}
// Function to place a limit order
std::string createLimitOrder(const std::string& symbol, double quantity, double price) {
    std::cout << "Creating limit order..." << std::endl;

    std::string url = baseUrl + "/api/v1/private/order/submit";
    std::string payload = "symbol=" + symbol + 
                          "&price=" + std::to_string(price) + 
                          "&quantity=" + std::to_string(quantity) + 
                          "&side=BUY" + 
                          "&type=LIMIT";
    std::string signature = signRequest(payload, apiSecret);

    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string readBuffer;

    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("X-MEXC-APIKEY: " + apiKey).c_str());
        headers = curl_slist_append(headers, ("X-MEXC-SIGNATURE: " + signature).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);  // Set timeout

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return "Error occurred while placing order.";
        }

        curl_easy_cleanup(curl);
    }
    cout<<"rachit is " << endl;
    cout<<readBuffer;
    return readBuffer;

}

int main() {
        std::cout << "hello";
    curl_global_init(CURL_GLOBAL_DEFAULT);  // Initialize CURL

    std::string orderResponse = createLimitOrder("BTCUSDT", 0.1, 50000.0);
    std::cout << "Order placed response: " << orderResponse << std::endl;

    // // Extract orderId from orderResponse if needed.
    // // Here we assume you would parse JSON to get the order ID
    // std::string orderId; // Extract this from the orderResponse

    // std::string modifiedResponse = modifyOrder(orderId, 51000.0);
    // std::cout << "Order modified response: " << modifiedResponse << std::endl;

    // std::string cancelResponse = cancelOrder(orderId);
    // std::cout << "Order canceled response: " << cancelResponse << std::endl;

    // std::string positions = getCurrentPositions();
    // std::cout << "Current Positions: " << positions << std::endl;

    // curl_global_cleanup();  // Cleanup CURL
    return 0;
}



// Function to modify an order
std::string modifyOrder(const std::string& orderId, double newPrice) {
    std::string url = baseUrl + "/api/v1/order/modify";
    std::string payload = "orderId=" + orderId + "&price=" + std::to_string(newPrice);
    std::string signature = signRequest(payload, apiSecret);

    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string readBuffer;

    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("X-MEXC-APIKEY: " + apiKey).c_str());
        headers = curl_slist_append(headers, ("X-MEXC-SIGNATURE: " + signature).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);  // Set timeout

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    }

    return readBuffer;
}

// Function to cancel an order
std::string cancelOrder(const std::string& orderId) {
    std::string url = baseUrl + "/api/v1/order/cancel";
    std::string payload = "orderId=" + orderId;
    std::string signature = signRequest(payload, apiSecret);

    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string readBuffer;

    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("X-MEXC-APIKEY: " + apiKey).c_str());
        headers = curl_slist_append(headers, ("X-MEXC-SIGNATURE: " + signature).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);  // Set timeout

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    }

    return readBuffer;
}

// Function to get current positions
std::string getCurrentPositions() {
    std::string url = baseUrl + "/api/v1/position";
    
    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string readBuffer;

    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("X-MEXC-APIKEY: " + apiKey).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);  // Set timeout

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    }

    return readBuffer;
}
