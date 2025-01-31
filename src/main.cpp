// wifi promiscuous mode sniffer for Espressif ESP32 Dev Module/esp-wroom-32u
// rough idea cames from https://www.hackster.io/p99will/esp32-wifi-mac-scanner-sniffer-promiscuous-4c12f4
#include <WiFi.h>
#include <Wire.h>

#include "esp_wifi.h"

// #define USE_JSON_LIB

#define FILTER_LIST_MAX_SIZE 2
#define FILTER_ENABLED true
#define CHANNEL 1
#define HOP_CHANNEL false
#define MAX_CHANNEL 13 // max Channel -> US = 11, EU = 13, Japan = 14

#ifdef USE_JSON_LIB
#include <ArduinoJson.h>
JsonDocument json;
#endif

String BssidFilter[FILTER_LIST_MAX_SIZE] = {
    "000000000000",
    "000000000000"};

// filter only for management and data frames
const wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};

typedef struct
{
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

/**
 * Converts uint8 array to literal string
 * a uint8 is 2 char for hex value, when a mac address contains 0, it may gets ignored
 * e.g. 12-34-01-00-56-78 results in 12-34-1-0-56-78, or 1234105678
 * which will be undistinguishable
 */
String macAddrToString(MacAddr addr)
{
  String str = "";
  String seg = "";
  for (int i = 0; i < 6; i++)
  {
    seg = String(addr.mac[i], HEX);
    if (seg.length() == 1)
    {
      seg = "0" + seg;
    }
    str += seg;
  }
  return str;
}

// 802.11 Data Frame Structure
// +--------------------+----------------------+
// | Field              | Size (bytes)         |
// +--------------------+----------------------+
// | Frame Control      | 2                    |
// | Duration/ID        | 2                    |
// | Address 1 (DA)     | 6                    |
// | Address 2 (SA)     | 6                    |
// | Address 3 (BSSID)  | 6                    |
// | Sequence Control   | 2                    |
// | Address 4 (optional)| 6                   |
// | Frame Body         | 0-2312               |
// | FCS                | 4                    |
// +--------------------+----------------------+
typedef struct
{
  int16_t fctl;
  int16_t duration;
  MacAddr da;
  MacAddr sa;
  MacAddr bssid;
  int16_t seqctl;
  unsigned char payload[];
} __attribute__((packed)) WifiPayload;

// a fancier way to mark bit fields
typedef struct
{
  unsigned protocol : 2;
  unsigned type : 2;
  unsigned subtype : 4;
  unsigned to_ds : 1;
  unsigned from_ds : 1;
  unsigned more_frag : 1;
  unsigned retry : 1;
  unsigned pwr_mgt : 1;
  unsigned more_data : 1;
  unsigned wep : 1;
  unsigned order : 1;
} __attribute__((packed)) WifiFrameCtl;

int curChannel = CHANNEL;
int lastRssi = 0;
String lastMac = "000000000000";
void sniffer(void *buf, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
  // metadata header
  wifi_pkt_rx_ctrl_t rx_ctl = p->rx_ctrl;
  int len = rx_ctl.sig_len;
  // 802.11 packet head & data
  WifiPayload *wh = (WifiPayload *)p->payload;
  len -= sizeof(WifiPayload);
  if (len < 0)
  {
    Serial.println("Received 0 payload");
    return;
  }
  // big endian for network, small for data in memory
  int fctl = ntohs(wh->fctl);
  WifiFrameCtl *fc = (WifiFrameCtl *)&fctl;

  String mac = macAddrToString(wh->sa);
  String bssid = macAddrToString(wh->bssid);

  // simple output filter
  // show only desired bssid, remove item for same mac
  for (size_t i = 0; i < FILTER_LIST_MAX_SIZE; i++)
  {
    if (!FILTER_ENABLED || bssid == BssidFilter[i])
    {
      if (lastMac != mac || abs(lastRssi - rx_ctl.rssi) > 1)
      {
#ifdef USE_JSON_LIB
        json["mac"] = mac;
        json["rssi"] = rx_ctl.rssi;
        json["bssid"] = bssid;
        serializeJson(json, Serial);
        Serial.println();
#else
        Serial.println(" {\"mac\":\"" + mac + "\"" + "," + "\"rssi\":" + rx_ctl.rssi + "," + "\"bssid\":\"" + bssid + "\"" + "}");
#endif
      }
      lastMac = mac;
      lastRssi = rx_ctl.rssi;
      break;
    }
  }
}

void setup()
{
  /* start Serial */
  Serial.begin(115200);

  /* setup wifi */
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

  Serial.setDebugOutput(false);
  Serial.println("starting!");
}

void loop()
{
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  delay(1000);
  if (HOP_CHANNEL)
  {
    curChannel++;
    if (curChannel > MAX_CHANNEL)
    {
      curChannel = 1;
    }
  }
}
