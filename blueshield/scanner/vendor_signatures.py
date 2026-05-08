"""
Per-vendor BLE manufacturer-data signatures.

The Bluetooth SIG company-ID lookup tells us *who made the chip* but not
*what the device is*. This module adds vendor-specific patterns that resolve
the actual product class (audio / fitness / tracker / car / etc.) from
recognisable manufacturer-data prefixes and known device-name patterns.

Sources cross-referenced:
  - https://github.com/Theengs/decoder              (~150 device JSON descriptors)
  - https://github.com/custom-components/ble_monitor (~50 sensor parsers)
  - https://github.com/Bluetooth-Devices/bluetooth-data-tools
  - Vendor SDK docs (Garmin Connect IQ, Fitbit Web API, Whoop Strap docs)
  - public reverse-engineering writeups (Tile, Chipolo, Soundcore, Pebble)
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import re


@dataclass
class VendorMatch:
    vendor: str
    device_class: str        # phone / audio / watch / fitness_tracker / tracker_tag / iot / etc.
    label: str
    confidence: float
    notes: str = ""


# ── Manufacturer-data → device class patterns ──────────────────────────────────
# Each entry maps a Bluetooth SIG company ID to a vendor + likely device class.
# The `name_patterns` (regex against advertised local name) further refine it.
VENDOR_MFG_PATTERNS: dict[int, dict] = {
    # --- Audio (headphones, earbuds, speakers) -------------------------------
    # Note: 0x0157 ledger entry is shared between Anker, Chipolo and Govee in
    # SIG history. We pick one representative (Anker/Soundcore audio) here and
    # let name patterns disambiguate; specific Chipolo/Govee patterns are also
    # caught in NAME_ONLY_PATTERNS below.
    0x0157: {"vendor": "Anker / Soundcore", "class": "audio",
              "label": "Soundcore audio device", "conf": 0.55,
              "name_patterns": [r"soundcore", r"liberty", r"space\s+", r"motion\s*x",
                                r"chipolo", r"govee", r"ihoment", r"h\d{4}"]},
    0x008B: {"vendor": "Sennheiser / Sonova", "class": "audio",
              "label": "Sennheiser headset / Sonova device", "conf": 0.80,
              "name_patterns": [r"sennheiser", r"momentum", r"hd\d{3}", r"epos"]},
    0x009E: {"vendor": "Bose", "class": "audio",
              "label": "Bose audio device", "conf": 0.85,
              "name_patterns": [r"bose", r"qc\d+", r"quietcomfort", r"soundlink"]},
    0x012D: {"vendor": "Sony", "class": "audio",
              "label": "Sony audio device", "conf": 0.70,
              "name_patterns": [r"wf-\w+", r"wh-\w+", r"linkbuds", r"srs-\w+"]},
    0x0057: {"vendor": "Harman / JBL", "class": "audio",
              "label": "JBL audio device", "conf": 0.80,
              "name_patterns": [r"jbl", r"harman", r"akg", r"ue\s*\w+"]},
    0x0184: {"vendor": "Beats Electronics", "class": "audio",
              "label": "Beats audio device", "conf": 0.95,
              "name_patterns": [r"beats", r"powerbeats"]},
    0x0067: {"vendor": "GN Netcom", "class": "audio",
              "label": "Jabra headset", "conf": 0.85,
              "name_patterns": [r"jabra", r"resound", r"evolve"]},
    # --- Input (HID keyboards / mice) ----------------------------------------
    0x0046: {"vendor": "Logitech", "class": "hid_input",
              "label": "Logitech input device", "conf": 0.75,
              "name_patterns": [r"mx\s", r"k\d{3}", r"m\d{3}", r"craft", r"keys",
                                r"trackpad", r"presenter"]},
    0x009A: {"vendor": "Cherry", "class": "hid_keyboard",
              "label": "Cherry keyboard", "conf": 0.80,
              "name_patterns": [r"cherry", r"mx\s*board"]},
    0x0017: {"vendor": "NewLogic", "class": "hid_input",
              "label": "Input device", "conf": 0.30, "name_patterns": []},
    # --- Watches / wearables ------------------------------------------------
    0x0087: {"vendor": "Garmin", "class": "watch",
              "label": "Garmin watch / device", "conf": 0.92,
              "name_patterns": [r"garmin", r"forerunner", r"fenix", r"venu",
                                r"vivoactive", r"epix", r"instinct", r"edge"]},
    0x006B: {"vendor": "Polar Electro", "class": "fitness_tracker",
              "label": "Polar device", "conf": 0.92,
              "name_patterns": [r"polar", r"h\d+", r"vantage", r"verity",
                                r"ignite", r"grit"]},
    0x0103: {"vendor": "Suunto", "class": "watch",
              "label": "Suunto watch", "conf": 0.92,
              "name_patterns": [r"suunto", r"core", r"\d\s*peak", r"vertical"]},
    0x0173: {"vendor": "Withings", "class": "fitness_tracker",
              "label": "Withings device", "conf": 0.85,
              "name_patterns": [r"withings", r"scanwatch", r"steel"]},
    0x0394: {"vendor": "Whoop", "class": "fitness_tracker",
              "label": "Whoop strap", "conf": 0.95,
              "name_patterns": [r"whoop"]},
    0x021B: {"vendor": "Fitbit (legacy)", "class": "fitness_tracker",
              "label": "Fitbit device", "conf": 0.90,
              "name_patterns": [r"fitbit", r"versa", r"sense", r"charge",
                                r"luxe", r"inspire", r"ace"]},
    0x09C2: {"vendor": "Fitbit", "class": "fitness_tracker",
              "label": "Fitbit device", "conf": 0.92,
              "name_patterns": [r"fitbit", r"versa", r"sense", r"charge"]},
    0x0212: {"vendor": "Amazfit / Huami", "class": "watch",
              "label": "Amazfit / Mi Band", "conf": 0.85,
              "name_patterns": [r"amazfit", r"mi\s*band", r"gts", r"gtr",
                                r"bip", r"redmi\s+watch"]},

    # --- Trackers / finders --------------------------------------------------
    0x00B5: {"vendor": "Tile", "class": "tracker_tag",
              "label": "Tile tracker", "conf": 0.95,
              "name_patterns": [r"tile_", r"tilemate", r"slim", r"sticker", r"pro"]},
    # 0x0157 is shared with Anker/Govee — see entry above.

    # --- Phones / computers --------------------------------------------------
    0x004C: {"vendor": "Apple", "class": "apple_device",
              "label": "Apple device (see Continuity decode)", "conf": 0.30,
              "name_patterns": []},  # Apple has its own dedicated decoder
    0x0006: {"vendor": "Microsoft", "class": "computer",
              "label": "Microsoft / Windows device", "conf": 0.40,
              "name_patterns": [r"surface", r"windows", r"xbox", r"hololens"]},
    0x0075: {"vendor": "Samsung", "class": "phone",
              "label": "Samsung device", "conf": 0.30,
              "name_patterns": [r"galaxy", r"sm-\w+", r"tab\s+s\d"]},
    0x00E0: {"vendor": "Google", "class": "phone",
              "label": "Google device", "conf": 0.50,
              "name_patterns": [r"pixel", r"nest"]},
    0x0131: {"vendor": "Cypress / Infineon", "class": "ble_chip", "label": "BLE module", "conf": 0.10, "name_patterns": []},

    # --- Medical -------------------------------------------------------------
    0x00D0: {"vendor": "Dexcom", "class": "cgm",
              "label": "Dexcom CGM", "conf": 0.99,
              "name_patterns": [r"dexcom", r"dxcm\d+"]},
    0x010A: {"vendor": "Abbott Diabetes", "class": "cgm",
              "label": "FreeStyle Libre CGM", "conf": 0.98,
              "name_patterns": [r"abbott", r"libre"]},
    0x008F: {"vendor": "Medtronic", "class": "medical",
              "label": "Medtronic medical device", "conf": 0.92,
              "name_patterns": [r"medtronic", r"guardian", r"minimed"]},
    0x010E: {"vendor": "Tandem Diabetes", "class": "insulin_pump",
              "label": "Tandem t:slim X2", "conf": 0.95,
              "name_patterns": [r"tslim", r"t:slim", r"tandem", r"mobi"]},
    0x06F4: {"vendor": "Sonova / Phonak", "class": "hearing_aid",
              "label": "Phonak hearing aid", "conf": 0.95,
              "name_patterns": [r"phonak", r"audeo", r"naida", r"unitron"]},
    0x008A: {"vendor": "Oticon", "class": "hearing_aid",
              "label": "Oticon hearing aid", "conf": 0.92,
              "name_patterns": [r"oticon", r"intent", r"more", r"opn"]},
    0x07C1: {"vendor": "GN ReSound", "class": "hearing_aid",
              "label": "GN ReSound hearing aid", "conf": 0.95,
              "name_patterns": [r"resound", r"jabra\s+enhance"]},
    # 0x008B already declared in audio block above.

    # --- Cars / vehicles -----------------------------------------------------
    0x05B6: {"vendor": "Tesla", "class": "car",
              "label": "Tesla vehicle", "conf": 0.95,
              "name_patterns": [r"tesla", r"model\s*[3sxy]"]},
    0x0084: {"vendor": "BMW Group", "class": "car",
              "label": "BMW / MINI vehicle", "conf": 0.85,
              "name_patterns": [r"bmw", r"mini"]},
    0x000F: {"vendor": "Broadcom", "class": "ble_chip",
              "label": "BLE module (Broadcom)", "conf": 0.05, "name_patterns": []},
    0x0009: {"vendor": "Infineon", "class": "ble_chip",
              "label": "BLE module (Infineon)", "conf": 0.05, "name_patterns": []},
    0x000D: {"vendor": "Texas Instruments", "class": "ble_chip",
              "label": "BLE module (TI)", "conf": 0.05, "name_patterns": []},
    0x005D: {"vendor": "Realtek", "class": "ble_chip",
              "label": "BLE module (Realtek)", "conf": 0.05, "name_patterns": []},
    0x0059: {"vendor": "Nordic Semi", "class": "ble_chip",
              "label": "BLE module (Nordic)", "conf": 0.05, "name_patterns": []},
    0x02E5: {"vendor": "Espressif", "class": "ble_chip",
              "label": "ESP32 device", "conf": 0.05, "name_patterns": []},

    # --- IoT / home ----------------------------------------------------------
    # 0x0157 (Anker / Chipolo / Govee shared entry) already declared above —
    # name patterns disambiguate.
    0x0739: {"vendor": "Tuya", "class": "iot",
              "label": "Tuya / SmartLife device", "conf": 0.85,
              "name_patterns": [r"tuya", r"tplink", r"tapo", r"bs\d+"]},
    0x008C: {"vendor": "Gimbal", "class": "proximity",
              "label": "Gimbal beacon", "conf": 0.85, "name_patterns": []},
    0x004F: {"vendor": "APT Licensing", "class": "ble_device",
              "label": "Audio licensee", "conf": 0.30, "name_patterns": []},
}


# Common "noise" patterns for IoT devices that often broadcast generic names
# (RGB strips, Govee bulbs, ESP32 dev kits, etc.)
NAME_ONLY_PATTERNS: list[tuple[str, str, str, float]] = [
    # (name regex, device_class, label, confidence)
    (r"^elk-bledom",                    "smart_light",      "ELK-BLEDOM RGB strip",       0.95),
    (r"^ihoment",                       "smart_light",      "Govee bulb (Ihoment)",       0.92),
    (r"^h\d{4}_",                       "smart_light",      "Govee bulb",                 0.88),
    (r"^bose\s+",                       "audio",            "Bose audio",                 0.92),
    (r"^jbl\s+|^jbl-|^harman",          "audio",            "JBL / Harman speaker",       0.92),
    (r"^sony\s+(wf|wh|wi|srs)-?",       "audio",            "Sony earbuds / headphones",  0.95),
    (r"^wf-\d|^wh-\d|^wi-\d",           "audio",            "Sony audio device",          0.92),
    (r"^airpods",                       "audio",            "AirPods (by name)",          0.85),
    (r"^beats\s+|^powerbeats|^solo\s*\d|^studio\s+(buds|pro)","audio","Beats audio",      0.92),
    (r"^sennheiser|^cx[\s_-]?\d+|^momentum",  "audio",      "Sennheiser audio",           0.92),
    (r"^pixel\s+buds",                  "audio",            "Google Pixel Buds",          0.95),
    (r"^surface\s+(headphones|earbuds)","audio",            "Microsoft Surface audio",    0.95),
    (r"^anker\s+|^anc\s+",              "audio",            "Anker / Soundcore",          0.85),
    (r"^soundcore|^liberty\s*\d|^space\s+(one|q\d+)","audio","Soundcore audio",           0.92),
    (r"^bowers|^b&w|^pi\d|^px\d",       "audio",            "Bowers & Wilkins",           0.92),
    (r"^bo[\W_]play|^beoplay|^b&o",     "audio",            "Bang & Olufsen",             0.92),
    (r"^master\s+&\s+dynamic|^md\s+",   "audio",            "Master & Dynamic",           0.92),
    (r"^jlab\b|^jbuds|^go\s+air|^epic\s+air","audio",       "JLab earbuds",               0.92),
    (r"^marshall\s+|^major\s*[ivx]+|^minor\s*[ivx]+|^stockwell|^emberton|^willen","audio","Marshall audio", 0.92),
    (r"^skullcandy|^crusher\s|^indy\s|^push\s|^dime\s|^hesh","audio","Skullcandy audio",   0.92),
    (r"^klipsch|^t5\s",                 "audio",            "Klipsch audio",              0.92),
    (r"^edifier|^w\d{3}",               "audio",            "Edifier audio",              0.85),
    (r"^audio-?technica|^ath-",         "audio",            "Audio-Technica",             0.92),
    (r"^shure",                         "audio",            "Shure",                      0.92),
    (r"^akg",                           "audio",            "AKG",                        0.92),
    (r"^plantronics|^poly\b|^backbeat", "audio",            "Poly (Plantronics)",         0.92),
    (r"^jabra\b|^elite\s+\d|^evolve",   "audio",            "Jabra headset",              0.92),
    (r"^razer\s+(opus|hammerhead|barracuda)","audio",       "Razer headset",              0.92),
    (r"^logitech\s+(g\d+|astro)",       "audio",            "Logitech G / Astro",         0.92),
    (r"^steelseries\s+arctis",          "audio",            "SteelSeries Arctis",         0.92),
    (r"^gopro",                         "camera",           "GoPro",                      0.92),
    (r"^dji\b|^osmo\b|^mavic|^mini\s+\d","camera",          "DJI device",                 0.90),
    (r"^insta360",                      "camera",           "Insta360",                   0.92),
    (r"^sonos\s+|^roam\b|^move\b|^era\s+\d|^arc\b|^beam\b|^ray\b","audio","Sonos speaker", 0.92),
    (r"^denon\s+|^heos",                "audio",            "Denon / HEOS",               0.92),
    (r"^yamaha\s+|^musiccast",          "audio",            "Yamaha audio",               0.90),
    (r"^libratone",                     "audio",            "Libratone",                  0.92),

    # Keyboards / mice / trackpads
    (r"^magic\s+(keyboard|mouse|trackpad)","hid_apple",     "Apple Magic peripheral",     0.95),
    (r"^mx\s+(keys|master|anywhere)",   "hid_logitech",     "Logitech MX",                0.95),
    (r"^k\d{3}",                        "hid_keyboard",     "Logitech keyboard",          0.85),
    (r"^m\d{3}\s",                      "hid_mouse",        "Logitech mouse",             0.80),
    (r"^logi[\s_-]",                    "hid_logitech",     "Logitech device",            0.85),
    (r"^keychron",                      "hid_keyboard",     "Keychron keyboard",          0.95),
    (r"^cherry\s+",                     "hid_keyboard",     "Cherry keyboard",            0.92),
    (r"^razer\s+",                      "hid_input",        "Razer peripheral",           0.92),
    (r"^corsair",                       "hid_input",        "Corsair peripheral",         0.92),
    (r"^xbox\s+wireless|^xbox\s+controller","controller",   "Xbox controller",            0.95),
    (r"^dualsense|^dualshock",          "controller",       "PlayStation controller",     0.95),
    (r"^joy-?con|^pro\s+controller|^switch\s+",   "controller", "Switch controller",       0.95),
    (r"^8bitdo\s+",                     "controller",       "8BitDo controller",          0.95),
    (r"^stadia\s+",                     "controller",       "Stadia controller",          0.95),
    (r"^scuf\s+",                       "controller",       "SCUF controller",            0.92),
    (r"^astro\s+",                      "audio",            "Astro headset",              0.92),
    (r"^magic\s+(pencil|stylus)|^apple\s+pencil","stylus",  "Apple Pencil",               0.95),
    (r"^surface\s+pen",                 "stylus",           "Surface Pen",                 0.95),
    (r"^s\s*pen|^samsung\s+pen",        "stylus",           "Samsung S Pen",               0.92),

    # Watches / fitness
    (r"^apple\s+watch",                 "watch",            "Apple Watch",                0.95),
    (r"^galaxy\s+watch",                "watch",            "Samsung Galaxy Watch",       0.95),
    (r"^fitbit\s+",                     "fitness_tracker",  "Fitbit",                     0.95),
    (r"^garmin\s+|^forerunner|^fenix|^venu","watch",        "Garmin watch",               0.95),
    (r"^polar\s+|^vantage\s+|^h\d+\s",  "fitness_tracker",  "Polar device",               0.92),
    (r"^suunto",                        "watch",            "Suunto watch",               0.95),
    (r"^withings\s+|^scanwatch",        "fitness_tracker",  "Withings",                   0.92),
    (r"^whoop\s+",                      "fitness_tracker",  "Whoop strap",                0.95),
    (r"^amazfit",                       "watch",            "Amazfit",                    0.95),
    (r"^mi\s+band|^xiaomi\s+smart\s+band","fitness_tracker","Xiaomi Mi Band",            0.95),
    (r"^huawei\s+(band|watch)",         "watch",            "Huawei wearable",            0.92),
    (r"^honor\s+(band|watch)",          "watch",            "Honor wearable",             0.92),
    (r"^coros\s+|^pace\s+\d|^apex\s+\d|^vertix","watch",    "Coros watch",                0.92),
    (r"^wahoo\s+|^kickr|^elemnt",       "fitness",          "Wahoo cycling device",       0.92),
    (r"^stryd",                         "fitness",          "Stryd running pod",          0.95),
    (r"^supersapiens",                  "fitness",          "Supersapiens CGM",           0.95),
    (r"^oura\s+|^ring\s+\d",            "fitness_tracker",  "Oura Ring",                  0.92),
    (r"^ultrahuman",                    "fitness_tracker",  "Ultrahuman Ring",            0.92),

    # Trackers
    (r"^tile\s|^tile_",                 "tracker_tag",      "Tile tracker",               0.95),
    (r"^chipolo",                       "tracker_tag",      "Chipolo tracker",            0.95),
    (r"^smarttag|^galaxy\s+smarttag",   "tracker_tag",      "Galaxy SmartTag",            0.95),
    (r"^airtag",                        "tracker_tag",      "Apple AirTag",               0.95),

    # Medical
    (r"^dxcm\d+|^dexcom",               "cgm",              "Dexcom CGM",                 0.97),
    (r"^libre\d|^abt\w+",               "cgm",              "FreeStyle Libre",            0.95),
    (r"^medtronic|^guardian",           "medical",          "Medtronic device",           0.92),
    (r"^t:slim|^tslim|^tandem",         "insulin_pump",     "Tandem insulin pump",        0.95),
    (r"^omnipod",                       "insulin_pump",     "Omnipod 5",                  0.95),
    (r"^accu-?chek",                    "medical",          "Roche Accu-Chek",            0.92),
    (r"^contour",                       "medical",          "Bayer Contour glucose",      0.92),
    (r"^omron",                         "medical",          "Omron blood pressure",       0.92),
    (r"^philips\s+heart",               "medical",          "Philips heart monitor",      0.90),

    # Hearing aids / hearables
    (r"^phonak\s+|^audeo|^naida",       "hearing_aid",      "Phonak hearing aid",         0.95),
    (r"^oticon",                        "hearing_aid",      "Oticon hearing aid",         0.95),
    (r"^resound",                       "hearing_aid",      "GN ReSound hearing aid",     0.95),
    (r"^widex",                         "hearing_aid",      "Widex hearing aid",          0.95),
    (r"^starkey|^livio",                "hearing_aid",      "Starkey hearing aid",        0.95),
    (r"^signia\s+|^pure\s+ax",          "hearing_aid",      "Signia hearing aid",         0.92),

    # Phones
    (r"^pixel\s+\d|^pixel\s+(pro|fold)","phone",            "Google Pixel phone",         0.92),
    (r"^iphone",                        "phone",            "iPhone (by name)",           0.85),
    (r"^galaxy\s+(s|note|a|z)",         "phone",            "Samsung Galaxy phone",       0.92),
    (r"^oneplus",                       "phone",            "OnePlus phone",              0.90),
    (r"^xiaomi|^redmi|^poco",           "phone",            "Xiaomi/Redmi/POCO",          0.85),
    (r"^huawei|^mate\s+\d",             "phone",            "Huawei phone",               0.85),

    # Cars
    (r"^tesla|^model\s*[3sxy]",         "car",              "Tesla vehicle",              0.95),
    (r"^bmw|^mini",                     "car",              "BMW Group vehicle",          0.85),

    # IoT
    (r"^homepod",                       "smart_speaker",    "Apple HomePod",              0.95),
    (r"^echo\s+|^alexa|^amazon\s+(echo|dot|show|studio)","smart_speaker","Amazon Echo",   0.92),
    (r"^chromecast|^google\s+home|^google\s+nest\s+(audio|hub|mini|wifi)","smart_speaker","Google Home / Nest",0.92),
    (r"^apple\s*tv|^appletv",           "tv",               "Apple TV",                   0.95),
    (r"^roku\s+|^streambar",            "tv",               "Roku device",                0.92),
    (r"^fire\s*(tv|stick|cube)|^firetv","tv",               "Amazon Fire TV",             0.92),
    (r"^nvidia\s+shield|^shield\s+tv",  "tv",               "Nvidia Shield TV",           0.95),
    (r"^lg\s+(oled|webos|smart\s+tv|tv)","tv",              "LG smart TV",                0.90),
    (r"^samsung\s+tv|^[sq]\s*\d+\s+(uhd|qled|oled)","tv",   "Samsung TV",                 0.88),
    (r"^sony\s+(bravia|tv)",            "tv",               "Sony Bravia TV",             0.90),
    (r"^vizio",                         "tv",               "Vizio TV",                   0.85),
    (r"^nest\s+(hub|mini|audio|cam|doorbell|thermostat)","iot","Google Nest device",      0.92),
    (r"^thermostat|^ecobee",            "iot",              "Smart thermostat",           0.85),
    (r"^hue\s+|^philips\s+hue",         "smart_light",      "Philips Hue",                0.95),
    (r"^lifx\s+|^lifx_",                "smart_light",      "LIFX bulb",                  0.95),
    (r"^wyze",                          "iot",              "Wyze device",                0.90),
    (r"^smartthings",                   "iot",              "Samsung SmartThings",        0.85),
    (r"^august\s+|^yale\s+|^schlage|^level\s+lock|^kwikset","smart_lock","Smart lock",    0.95),
    (r"^ring\s+(doorbell|cam|peephole)","iot",              "Ring doorbell / camera",     0.95),
    (r"^eufy\s+(cam|doorbell|robovac)", "iot",              "Eufy / Anker security",      0.92),
    (r"^arlo\s+",                       "iot",              "Arlo camera",                0.92),
    (r"^roborock|^roomba|^eufy\s+robovac","iot",            "Robot vacuum",               0.90),
    (r"^lg\s+(washer|dryer|fridge|oven|range)","iot",       "LG appliance",               0.85),
    (r"^samsung\s+(washer|dryer|fridge|oven)","iot",        "Samsung appliance",          0.85),
    (r"^smart\s+(plug|switch|outlet)|^kasa\b","iot",        "Smart plug",                 0.85),
    (r"^shelly\s+|^shelly1|^shellyplus", "iot",             "Shelly device",              0.92),
    (r"^aqara\s+|^aqarah1|^xiaomi\s+",  "iot",              "Aqara/Xiaomi sensor",        0.85),
    (r"^mi\s*flora|^miflora|^xiaomi\s+plant|^hhcc","iot",   "Mi Flora plant sensor",      0.95),

    # Cars (extended)
    (r"^ford\s+|^sync\s+\d|^bronco|^mustang|^f-?\d+","car","Ford vehicle",                0.85),
    (r"^honda\s+|^civic|^accord|^crv\b","car",              "Honda vehicle",              0.85),
    (r"^toyota\s+|^corolla|^camry|^rav4|^prius","car",      "Toyota vehicle",             0.85),
    (r"^chevrolet|^chevy\s+|^silverado|^corvette","car",    "Chevrolet vehicle",          0.85),
    (r"^audi\s+|^q\d\b|^a\d\b\s","car",                     "Audi vehicle",               0.80),
    (r"^mercedes|^amg\s+",              "car",              "Mercedes-Benz",              0.85),
    (r"^porsche\s+|^taycan|^panamera|^macan","car",         "Porsche vehicle",            0.92),
    (r"^volvo\s+|^xc\d+|^ex\d+",        "car",              "Volvo vehicle",              0.85),
    (r"^rivian\s+|^r1[st]\b",           "car",              "Rivian vehicle",             0.92),
    (r"^lucid\s+|^lucid\s+air",         "car",              "Lucid vehicle",              0.92),

    # Tools / industrial
    (r"^dewalt|^milwaukee|^bosch\s+(tool|professional)","industrial","Power tool",        0.92),
    (r"^victron|^bms\s+|^battery\s+",   "industrial",       "Battery / energy device",    0.85),
    (r"^solaredge|^enphase",            "industrial",       "Solar inverter",             0.90),
]


def match_by_name(name: str) -> Optional[VendorMatch]:
    """Match a device by its advertised local name against known patterns."""
    if not name:
        return None
    n = name.strip().lower()
    for rx, dclass, label, conf in NAME_ONLY_PATTERNS:
        if re.search(rx, n):
            return VendorMatch(vendor=label, device_class=dclass, label=label, confidence=conf)
    return None


def match_by_mfg_id(mfg_id: int, name: str = "") -> Optional[VendorMatch]:
    """Match by manufacturer ID, refining via name patterns when set."""
    if mfg_id not in VENDOR_MFG_PATTERNS:
        return None
    p = VENDOR_MFG_PATTERNS[mfg_id]
    n = (name or "").lower()
    conf = p["conf"]
    label = p["label"]
    # Bump confidence + specialise the label when a name pattern matches.
    for rx in p.get("name_patterns", []):
        if re.search(rx, n):
            conf = min(conf + 0.10, 0.99)
            label = name  # use the actual product name from the device
            break
    return VendorMatch(vendor=p["vendor"], device_class=p["class"], label=label, confidence=conf)
