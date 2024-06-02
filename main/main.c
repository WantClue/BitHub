#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_http_client.h"
#include "cJSON.h"
#include "sdkconfig.h"
#include "lwip/inet.h"

#include "ssd1306.h"
#include "font8x8_basic.h"

#define WIFI_SSID CONFIG_WIFI_SSID
#define WIFI_PASSWORD CONFIG_WIFI_PASSWORD

static const char *TAG = "wifi_scan";

static EventGroupHandle_t wifi_event_group;
const int CONNECTED_BIT = BIT0;

static char *output_buffer = NULL;  // Buffer to store response of HTTP request
static int output_len = 0;          // Stores number of bytes read

#define MAX_VALID_IPS 256
static char valid_ips[MAX_VALID_IPS][16];
static int valid_ip_count = 0;
static bool subnet_scan_done = false;

// float for combined hashrate
static float combined_hashrate = 0.0;
static float current_scan_hashrate = 0.0;
static float last_combined_hashrate = 0.0;

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
    }
}

static void initialise_wifi(void) {
    esp_netif_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );
}

static bool is_valid_api_response(const char *json_str) {
    cJSON *json = cJSON_Parse(json_str);
    if (json == NULL) {
        ESP_LOGI(TAG, "Invalid JSON: %s", json_str);
        return false;
    }

    const char *required_keys[] = {
        "power", "voltage", "current", "fanSpeed", "temp", "boardtemp1", "boardtemp2", 
        "hashRate", "bestDiff", "freeHeap", "coreVoltage", "coreVoltageActual", 
        "frequency", "ssid", "wifiStatus", "sharesAccepted", "sharesRejected", 
        "uptimeSeconds", "ASICModel", "stratumURL", "stratumPort", "stratumUser", 
        "version", "boardVersion", "runningPartition", "flipscreen", "invertscreen", 
        "invertfanpolarity", "autofanspeed", "fanspeed"
    };
    const char *required_keys_1[] = {
        "power", "voltage", "current", "fanSpeed", "temp", 
        "hashRate", "bestDiff", "freeHeap", "coreVoltage", "coreVoltageActual", 
        "frequency", "ssid", "wifiStatus", "sharesAccepted", "sharesRejected", 
        "uptimeSeconds", "ASICModel", "stratumURL", "stratumPort", "stratumUser", 
        "version", "boardVersion", "runningPartition", "flipscreen", "invertscreen", 
        "invertfanpolarity", "autofanspeed", "fanspeed"
    };

    size_t required_keys_len = sizeof(required_keys) / sizeof(required_keys[0]);
    size_t required_keys_1_len = sizeof(required_keys_1) / sizeof(required_keys_1[0]);
    bool is_valid = true;
    for (size_t i = 0; i < required_keys_len; i++) {
        if (!cJSON_HasObjectItem(json, required_keys[i])) {
            is_valid = false;
            break;
        }
    }

    if (!is_valid) {
        is_valid = true;
        for (size_t i = 0; i < required_keys_1_len; i++) {
            if (!cJSON_HasObjectItem(json, required_keys_1[i])) {
                is_valid = false;
                break;
            }
        }
    }

    cJSON_Delete(json);
    return is_valid;
}

static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // If not a chunked response, store the entire payload
                if (output_buffer == NULL) {
                    output_buffer = (char *) malloc(evt->data_len + 1);  // +1 for null terminator
                    output_len = 0;
                    if (output_buffer == NULL) {
                        ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                        return ESP_FAIL;
                    }
                } else {
                    output_buffer = (char *) realloc(output_buffer, output_len + evt->data_len + 1);
                    if (output_buffer == NULL) {
                        ESP_LOGE(TAG, "Failed to reallocate memory for output buffer");
                        return ESP_FAIL;
                    }
                }
                memcpy(output_buffer + output_len, evt->data, evt->data_len);
                output_len += evt->data_len;
                output_buffer[output_len] = '\0';  // Null-terminate the string

                // Parse hashrate and update combined_hashrate
                cJSON *json = cJSON_Parse(output_buffer);
                if (json != NULL) {
                    cJSON *hashrate = cJSON_GetObjectItem(json, "hashRate");
                    if (hashrate != NULL) {
                        current_scan_hashrate += (float) hashrate->valuedouble;
                    }
                    cJSON_Delete(json);
                }
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
            if (output_buffer != NULL) {
                ESP_LOGI(TAG, "HTTP response: %s", output_buffer);
            }
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGI(TAG, "HTTP_EVENT_REDIRECT");
            break;
    }
    return ESP_OK;
}

static void rescan_valid_ips_task(void *pvParameters) {
    esp_http_client_config_t config = {
        .url = "http://192.168.1.1/api/system/info", // Placeholder URL
        .event_handler = http_event_handler,
        .transport_type = HTTP_TRANSPORT_OVER_TCP,   // Disable TLS
        .timeout_ms = 500,  // Set timeout for HTTP requests to 0.5 seconds
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    while (1) {
        if (subnet_scan_done) {
            float temp_valid_ip_scan_hashrate = 0.0; // Reset the temporary valid IP scan hashrate

            for (int i = 0; i < valid_ip_count; i++) {
                char url[50];
                snprintf(url, sizeof(url), "http://%s/api/system/info", valid_ips[i]);
                esp_http_client_set_url(client, url);

                ESP_LOGI(TAG, "Rescanning IP: %s", url);

                esp_err_t err = esp_http_client_perform(client);
                if (err == ESP_OK) {
                    if (output_buffer != NULL && is_valid_api_response(output_buffer)) {
                        ESP_LOGI(TAG, "Valid JSON response from IP: %s", valid_ips[i]);

                        // Update the current scan hashrate
                        cJSON *json = cJSON_Parse(output_buffer);
                        if (json != NULL) {
                            cJSON *hashrate = cJSON_GetObjectItem(json, "hashRate");
                            if (hashrate != NULL) {
                                temp_valid_ip_scan_hashrate += (float) hashrate->valuedouble;
                            }
                            cJSON_Delete(json);
                        }
                    }
                }

                if (output_buffer != NULL) {
                    free(output_buffer);
                    output_buffer = NULL;
                    output_len = 0;
                }
            }

            combined_hashrate = temp_valid_ip_scan_hashrate > 0 ? temp_valid_ip_scan_hashrate : combined_hashrate;
        }
        vTaskDelay(pdMS_TO_TICKS(10000));  // Delay 10 seconds
    }

    esp_http_client_cleanup(client);
}

static void scan_subnet_task(void *pvParameters) {
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"), &ip_info);
    char base_ip[16];
    snprintf(base_ip, sizeof(base_ip), IPSTR, IP2STR(&ip_info.ip));
    char *last_dot = strrchr(base_ip, '.');
    if (last_dot != NULL) {
        *last_dot = '\0';
    }

    esp_http_client_config_t config = {
        .url = "http://192.168.1.1/api/system/info",
        .event_handler = http_event_handler,
        .transport_type = HTTP_TRANSPORT_OVER_TCP,
        .timeout_ms = 500,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    while (1) {
        // Temporary variables to store the results of the current scan
        int temp_valid_ip_count = 0;
        char temp_valid_ips[MAX_VALID_IPS][16];
        float temp_scan_hashrate = 0.0;

        // Scan the entire subnet
        for (int i = 1; i <= 255; i++) {
            char ip[20];
            snprintf(ip, sizeof(ip), "%s.%d", base_ip, i);
            char url[50];
            snprintf(url, sizeof(url), "http://%s/api/system/info", ip);
            esp_http_client_set_url(client, url);

            ESP_LOGI(TAG, "Scanning IP: %s", url);

            esp_err_t err = esp_http_client_perform(client);
            if (err == ESP_OK) {
                if (output_buffer != NULL) {
                    ESP_LOGI(TAG, "HTTP response from %s: %s", url, output_buffer);
                    if (is_valid_api_response(output_buffer)) {
                        ESP_LOGI(TAG, "Device found at IP: %s", url);
                        if (temp_valid_ip_count < MAX_VALID_IPS) {
                            strncpy(temp_valid_ips[temp_valid_ip_count], ip, sizeof(temp_valid_ips[0]) - 1);
                            temp_valid_ips[temp_valid_ip_count][sizeof(temp_valid_ips[0]) - 1] = '\0';
                            temp_valid_ip_count++;

                            // Update the temporary scan hashrate
                            cJSON *json = cJSON_Parse(output_buffer);
                            if (json != NULL) {
                                cJSON *hashrate = cJSON_GetObjectItem(json, "hashRate");
                                if (hashrate != NULL) {
                                    temp_scan_hashrate += (float) hashrate->valuedouble;
                                }
                                cJSON_Delete(json);
                            }
                        }
                    } else {
                        ESP_LOGI(TAG, "Invalid JSON response from IP: %s", url);
                    }
                }
            } else {
                ESP_LOGI(TAG, "HTTP GET request failed for IP %s: %s", url, esp_err_to_name(err));
            }

            if (output_buffer != NULL) {
                free(output_buffer);
                output_buffer = NULL;
                output_len = 0;
            }
        }

        // Update the valid IPs and combined hashrate only if we found new valid IPs
        if (temp_valid_ip_count > 0) {
            valid_ip_count = temp_valid_ip_count;
            memcpy(valid_ips, temp_valid_ips, sizeof(temp_valid_ips));
            combined_hashrate = temp_scan_hashrate;
        }

        subnet_scan_done = true; // Set flag indicating that subnet scan is complete
        ESP_LOGI(TAG, "Subnet scan complete. Found %d valid IPs.", valid_ip_count);
        vTaskDelay(pdMS_TO_TICKS(300000));  // Delay 5 minutes before next scan
    }

    esp_http_client_cleanup(client);
}

void ssd1306_task(void *pvParameters) {
    SSD1306_t dev;
    ESP_LOGI(TAG, "CONFIG_SDA_GPIO=%d", CONFIG_SDA_GPIO);
    ESP_LOGI(TAG, "CONFIG_SCL_GPIO=%d", CONFIG_SCL_GPIO);
    ESP_LOGI(TAG, "CONFIG_RESET_GPIO=%d", CONFIG_RESET_GPIO);
    i2c_master_init(&dev, CONFIG_SDA_GPIO, CONFIG_SCL_GPIO, CONFIG_RESET_GPIO);
    ssd1306_init(&dev, 128, 64);
    ssd1306_clear_screen(&dev, false);
    ssd1306_contrast(&dev, 0xff);
    ssd1306_display_text(&dev, 0, "Hello, Miner!", 13, false);
    
    char hashrate_str[20];

    while (1) {
        // Update the display with the combined hashrate
        snprintf(hashrate_str, sizeof(hashrate_str), "Hashrate: %.2f", combined_hashrate);
        ssd1306_clear_line(&dev, 2, false);
        ssd1306_display_text(&dev, 2, hashrate_str, strlen(hashrate_str), false);

        // Delay for a while before updating again
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    initialise_wifi();

    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
    // Create a task to initialize and display hashrate on the SSD1306 display
    xTaskCreate(&ssd1306_task, "ssd1306_task", 4096, NULL, 5, NULL);

    // Create a task to scan the entire subnet every 5 minutes
    xTaskCreate(&scan_subnet_task, "scan_subnet_task", 8192, NULL, 5, NULL);

    // Create a task to rescan valid IPs every 10 seconds
    xTaskCreate(&rescan_valid_ips_task, "rescan_valid_ips_task", 8192, NULL, 5, NULL);

    
}
