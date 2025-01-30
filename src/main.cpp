#include <WiFi.h>
#include <Wire.h>

#include <ArduinoJson.h>

#include "esp_wifi.h"

// macList structure
// +-----------------+-----------------+-----------------+-----------------+
// | Column 1        | Column 2        | Column 3        | Column 4        |
// +-----------------+-----------------+-----------------+-----------------+
// | MAC Address     | TTL             | online time     | BSSID           |
// +-----------------+-----------------+-----------------+-----------------+
String maclist[64][4];
int listcount = 0;
JsonDocument json;

String KnownMac[10][2] = { // Put devices you want to be reconized
    {"Will-Phone", "EC1F7ffffffD"},
    {"Will-PC", "E894Fffffff3"},
    {"NAME", "MACADDRESS"},
    {"NAME", "MACADDRESS"},
    {"NAME", "MACADDRESS"},
    {"NAME", "MACADDRESS"},
    {"NAME", "MACADDRESS"},
    {"NAME", "MACADDRESS"},
    {"NAME", "MACADDRESS"}

};

String defaultTTL = "60"; // Maximum time (Apx seconds) elapsed before device is consirded offline

// filter only for management and data frames
const wifi_promiscuous_filter_t filt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};

typedef struct
{ // or this
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

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

String macAddrToPlainString(MacAddr addr)
{
  String str = "";
  String seg = "";
  for (int i = 0; i < 6; i++)
  {
    seg = String((char)addr.mac[i]);
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
} __attribute__((packed)) WifiMgmtHdr;

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

#define maxCh 13 // max Channel -> US = 11, EU = 13, Japan = 14

int curChannel = 1;
MacAddr lastAddr = {};

void sniffer(void *buf, wifi_promiscuous_pkt_type_t type)
{                                                            // This is where packets end up after they get sniffed
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf; // Dont know what these 3 lines do
  wifi_pkt_rx_ctrl_t ctl = p->rx_ctrl;
  int len = p->rx_ctrl.sig_len;
  WifiMgmtHdr *wh = (WifiMgmtHdr *)p->payload;
  len -= sizeof(WifiMgmtHdr);
  if (len < 0)
  {
    Serial.println("Receuved 0");
    return;
  }
  String packet;
  String mac;
  String debug;
  int fctl = ntohs(wh->fctl);
  WifiFrameCtl *fc = (WifiFrameCtl *)&fctl;
  

  //! Following code works, but a structured package data should be used for more info
  // for (int i = 10; i <= 10 + 6 + 1; i++)
  // { // This reads the first couple of bytes of the packet. This is where you can read the whole packet replaceing the "8+6+1" with "p->rx_ctrl.sig_len"
  //   String currentSeg = String((wh->sa).mac[i], HEX);
  //   // when coverting 1 byte (8bits, 2 hex letter) value to string, values with 4+ preceding zeros might get ignored
  //   // which will cause missing digit in mac addr
  //   if (currentSeg.length() == 1)
  //   {
  //     currentSeg = "0" + currentSeg;
  //   } else if (currentSeg.length() == 0)
  //   {
  //     currentSeg = "00";
  //   }

  //   packet += currentSeg;
  // }
  // for (int i = 0; i <= 11; i++)
  // { // This removes the 'nibble' bits from the stat and end of the data we want. So we only get the mac address.
  //   mac += packet[i];
  // }
  // Serial.println("Original packet: " + packet);
  // Serial.println("Original debug: " + debug);

  // mac = macAddrToString(wh->sa);
  // mac.toUpperCase();

  //bssid?
  // Serial.println(String(wh->bssid.mac + 22, 6+2+6+16));
  // Serial.println(String((char*)fc, 16));
  // Serial.println(macAddrToString(wh->bssid));

  // String realmac;
  // for (int i = 0; i < 5; i++)
  // {
  //   realmac += String((wh->sa).mac[i], HEX);
  // }
  // // Serial.println(realmac);

  // if (mac.length() != 12)
  // {
  //   Serial.println("Invalid MAC: " + mac);
  // }

  // json.clear();
  // json["mac"] = mac;
  // json["rssi"] = ctl.rssi;

  Serial.println("{\"mac\":\"" + macAddrToString(wh->sa) + "\"" + "," + "\"rssi\":" + ctl.rssi + "," + "\"bssid\":\"" + macAddrToString(wh->bssid) + "\"" + "}");

  // serializeJson(json, Serial);
  // Serial.println();

  // int added = 0;
  // for (int i = 0; i <= 63; i++)
  // { // checks if the MAC address has been added before
  //   if (mac == maclist[i][0])
  //   {
  //     maclist[i][1] = defaultTTL;
  //     if (maclist[i][2] == "OFFLINE")
  //     {
  //       maclist[i][2] = "0";
  //     }
  //     added = 1;
  //   }
  // }

  // if (added == 0)
  // { // If its new. add it to the array.
  //   maclist[listcount][0] = mac;
  //   maclist[listcount][1] = defaultTTL;
  //   // Serial.println(mac);
  //   listcount++;
  //   if (listcount >= 64)
  //   {
  //     Serial.println("Too many addresses");
  //     listcount = 0;
  //   }
  // }
}

//===== SETUP =====//
void setup()
{

  /* start Serial */
  Serial.begin(115200);

  /* setup wifi */
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  Serial.println("Init: " + String(esp_wifi_init(&cfg)));
  Serial.println("Set storage: " + String(esp_wifi_set_storage(WIFI_STORAGE_RAM)));
  Serial.println("Set mode: " + String(esp_wifi_set_mode(WIFI_MODE_NULL)));
  Serial.println("Start: " + String(esp_wifi_start()));
  Serial.println("Set promiscuous: " + String(esp_wifi_set_promiscuous(true)));
  Serial.println("Set filter: " + String(esp_wifi_set_promiscuous_filter(&filt)));
  Serial.println("Set rx callback: " + String(esp_wifi_set_promiscuous_rx_cb(&sniffer)));
  Serial.println("Set channel: " + String(esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE)));

  Serial.setDebugOutput(false);
  Serial.println("starting!");
}

void purge()
{ // This maanges the TTL
  for (int i = 0; i <= 63; i++)
  {
    if (!(maclist[i][0] == ""))
    {
      int ttl = (maclist[i][1].toInt());
      ttl--;
      if (ttl <= 0)
      {
        // Serial.println("OFFLINE: " + maclist[i][0]);
        // maclist[i][2] = "OFFLINE";
        maclist[i][2] = -1;
        maclist[i][1] = defaultTTL;
      }
      else
      {
        maclist[i][1] = String(ttl);
      }
    }
  }
}

void updatetime()
{ // This updates the time the device has been online fo

  for (int i = 0; i <= 63; i++)
  {
    if (!(maclist[i][0] == ""))
    {
      if (maclist[i][2] == "")
        maclist[i][2] = "0";
      // if (!(maclist[i][2] == "OFFLINE"))
      // {
        int timehere = (maclist[i][2].toInt());
        timehere++;
        maclist[i][2] = String(timehere);
      // }

      // Serial.println(maclist[i][0] + " : " + maclist[i][2]);
      // Serial.println("");
      // Serial.println(
      //     String(maclist[i][0].charAt(0)) + String(maclist[i][0].charAt(1)) + "-" + String(maclist[i][0].charAt(2)) + String(maclist[i][0].charAt(3)) + "-" + String(maclist[i][0].charAt(4)) + String(maclist[i][0].charAt(5)) + "-" + String(maclist[i][0].charAt(6)) + String(maclist[i][0].charAt(7)) + "-" + String(maclist[i][0].charAt(8)) + String(maclist[i][0].charAt(9)) + "-" + String(maclist[i][0].charAt(10)) + String(maclist[i][0].charAt(11)) + "(" + String(maclist[i][2]) + ")");
      // json["mac"][i] = maclist[i][0];
      // json["time"][i] = maclist[i][2].toInt();
    }
  }

  // serializeJson(json, Serial);
  // Serial.println();
}

void showpeople()
{ // This checks if the MAC is in the reckonized list and then displays it on the OLED and/or prints it to serial.
  String forScreen = "";
  for (int i = 0; i <= 63; i++)
  {
    String tmp1 = maclist[i][0];
    if (!(tmp1 == ""))
    {
      for (int j = 0; j <= 9; j++)
      {
        String tmp2 = KnownMac[j][1];
        if (tmp1 == tmp2)
        {
          forScreen += (KnownMac[j][0] + " : " + maclist[i][2] + "\n");
          Serial.print(KnownMac[j][0] + " : " + tmp1 + " : " + maclist[i][2] + "\n -- \n");
        }
      }
    }
  }
}

//===== LOOP =====//
void loop()
{
  // Serial.println("Changed channel:" + String(curChannel));
  if (curChannel > maxCh)
  {
    curChannel = 1;
  }
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  delay(1000);
  // updatetime();
  // purge();
  // showpeople();
  // curChannel++;
}
