/*
 * BlueShield nRF52840 Radio Jammer Firmware
 *
 * Minimal firmware for Nordic nRF52840 USB Dongle (PCA10059) that provides
 * direct RADIO peripheral control via USB CDC-ACM text protocol.
 *
 * Protocol: 115200 8N1, CR/LF-terminated commands, "radio_test>" prompt.
 * Compatible with Nordic SDK `radio_test` sample subset + BlueShield extensions.
 *
 * Build: make (requires arm-none-eabi-gcc + Nordic nRF5 SDK 17.1.0)
 * Flash: make flash DEVICE=/dev/ttyACM0 (via USB DFU bootloader)
 *
 * Legal: Use only in authorized research with Faraday enclosure.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "nrf.h"
#include "nrf_drv_radio.h"    // Nordic radio driver (optional)
#include "nrf_delay.h"
#include "app_usbd.h"
#include "app_usbd_cdc_acm.h"
#include "nrf_log.h"

// ─── Configuration ──────────────────────────────────────────────────────────

#define BLUESHIELD_FW_VERSION  "blueshield_nrf_jammer v1.0"
#define UART_BUF_SIZE          128
#define MAX_CMD_ARGS           4

// Current radio state
static struct {
    uint8_t mode;                // nrf_radio_mode_t
    int8_t  tx_power;            // dBm
    uint8_t channel;             // 0-80 (2400+N MHz)
    bool    tx_active;
    bool    sweep_active;
    uint8_t sweep_start;
    uint8_t sweep_end;
    uint16_t sweep_dwell_ms;
} g_state = {
    .mode = RADIO_MODE_MODE_Ble_1Mbit,
    .tx_power = 8,
    .channel = 0,
    .tx_active = false,
    .sweep_active = false,
};

// ─── Radio primitives ───────────────────────────────────────────────────────

/**
 * Configure the RADIO peripheral for TX on the current channel.
 * Sets TX power to +8 dBm (max for nRF52840 without FEM).
 */
static void radio_configure_tx(void)
{
    NRF_RADIO->POWER = 1;
    NRF_RADIO->MODE = g_state.mode;
    NRF_RADIO->FREQUENCY = g_state.channel;  // 2400 + N MHz
    NRF_RADIO->TXPOWER = g_state.tx_power;
    NRF_RADIO->MODECNF0 = (RADIO_MODECNF0_RU_Default << RADIO_MODECNF0_RU_Pos) |
                          (RADIO_MODECNF0_DTX_Center << RADIO_MODECNF0_DTX_Pos);
    NRF_RADIO->SHORTS = 0;
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->EVENTS_DISABLED = 0;
    NRF_RADIO->EVENTS_END = 0;
}

/**
 * Start unmodulated continuous wave (CW) carrier on current channel.
 */
static void radio_start_cw_carrier(void)
{
    radio_configure_tx();
    NRF_RADIO->TEST = (RADIO_TEST_CONSTCARRIER_Enabled << RADIO_TEST_CONSTCARRIER_Pos);
    NRF_RADIO->TASKS_TXEN = 1;
    while (NRF_RADIO->EVENTS_READY == 0) {}
    NRF_RADIO->EVENTS_READY = 0;
    g_state.tx_active = true;
}

/**
 * Start PRBS9 modulated carrier TX (simulates a real BLE packet).
 */
static void radio_start_modulated(void)
{
    radio_configure_tx();
    NRF_RADIO->TEST = (RADIO_TEST_PLLLOCK_Enabled << RADIO_TEST_PLLLOCK_Pos);
    NRF_RADIO->TASKS_TXEN = 1;
    while (NRF_RADIO->EVENTS_READY == 0) {}
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->TASKS_START = 1;
    g_state.tx_active = true;
}

/**
 * Immediately disable radio and clear test mode.
 */
static void radio_stop(void)
{
    NRF_RADIO->TEST = 0;
    NRF_RADIO->TASKS_DISABLE = 1;
    while (NRF_RADIO->EVENTS_DISABLED == 0) {}
    NRF_RADIO->EVENTS_DISABLED = 0;
    g_state.tx_active = false;
    g_state.sweep_active = false;
}

/**
 * Hop-and-jam loop: cycles TX carrier across a channel range.
 * Called from main loop when sweep_active is true.
 */
static void radio_sweep_tick(void)
{
    static uint8_t cur_ch = 0;
    if (!g_state.sweep_active) return;

    if (cur_ch < g_state.sweep_start) cur_ch = g_state.sweep_start;

    // Disable current
    NRF_RADIO->TASKS_DISABLE = 1;
    while (NRF_RADIO->EVENTS_DISABLED == 0) {}
    NRF_RADIO->EVENTS_DISABLED = 0;

    // Advance channel
    cur_ch++;
    if (cur_ch > g_state.sweep_end) cur_ch = g_state.sweep_start;
    g_state.channel = cur_ch;

    // Re-enable on new channel
    NRF_RADIO->FREQUENCY = cur_ch;
    NRF_RADIO->TEST = (RADIO_TEST_CONSTCARRIER_Enabled << RADIO_TEST_CONSTCARRIER_Pos);
    NRF_RADIO->TASKS_TXEN = 1;
    while (NRF_RADIO->EVENTS_READY == 0) {}
    NRF_RADIO->EVENTS_READY = 0;

    nrf_delay_ms(g_state.sweep_dwell_ms);
}

// ─── Command protocol parser ────────────────────────────────────────────────

static void cdc_printf(const char *fmt, ...);

static int tokenize(char *line, char *argv[], int max_argv)
{
    int argc = 0;
    char *p = line;
    while (*p && argc < max_argv) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0) break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    return argc;
}

static void handle_cmd(char *line)
{
    char *argv[MAX_CMD_ARGS];
    int argc = tokenize(line, argv, MAX_CMD_ARGS);
    if (argc == 0) return;

    if (strcmp(argv[0], "version") == 0) {
        cdc_printf("%s [nrf52840, +8dBm, BLE5/Coded PHY]\r\n",
                   BLUESHIELD_FW_VERSION);
    }
    else if (strcmp(argv[0], "set_mode") == 0 && argc >= 2) {
        if (strcmp(argv[1], "nrf_1Mbit") == 0)
            g_state.mode = RADIO_MODE_MODE_Nrf_1Mbit;
        else if (strcmp(argv[1], "nrf_2Mbit") == 0)
            g_state.mode = RADIO_MODE_MODE_Nrf_2Mbit;
        else if (strcmp(argv[1], "ble_1Mbit") == 0)
            g_state.mode = RADIO_MODE_MODE_Ble_1Mbit;
        else if (strcmp(argv[1], "ble_2Mbit") == 0)
            g_state.mode = RADIO_MODE_MODE_Ble_2Mbit;
        else if (strcmp(argv[1], "ble_lr125Kbit") == 0)
            g_state.mode = RADIO_MODE_MODE_Ble_LR125Kbit;
        cdc_printf("OK mode=%s\r\n", argv[1]);
    }
    else if (strcmp(argv[0], "set_tx_power") == 0 && argc >= 2) {
        int dbm = atoi(argv[1]);
        if (dbm > 8) dbm = 8;          // nRF52840 max conducted
        if (dbm < -40) dbm = -40;
        g_state.tx_power = dbm;
        cdc_printf("OK tx_power=%d\r\n", dbm);
    }
    else if (strcmp(argv[0], "set_channel") == 0 && argc >= 2) {
        int ch = atoi(argv[1]);
        if (ch >= 0 && ch <= 80) {
            g_state.channel = ch;
            cdc_printf("OK channel=%d freq=%dMHz\r\n", ch, 2400 + ch);
        }
    }
    else if (strcmp(argv[0], "start_tx_carrier") == 0) {
        radio_start_cw_carrier();
        cdc_printf("OK TX carrier ch=%d\r\n", g_state.channel);
    }
    else if (strcmp(argv[0], "start_tx_modulated_carrier") == 0) {
        radio_start_modulated();
        cdc_printf("OK TX modulated ch=%d\r\n", g_state.channel);
    }
    else if (strcmp(argv[0], "start_channel_sweep") == 0 && argc >= 4) {
        g_state.sweep_start = atoi(argv[1]);
        g_state.sweep_end = atoi(argv[2]);
        g_state.sweep_dwell_ms = atoi(argv[3]);
        if (g_state.sweep_dwell_ms < 1) g_state.sweep_dwell_ms = 1;
        g_state.sweep_active = true;
        cdc_printf("OK sweep %d-%d dwell=%dms\r\n",
                   g_state.sweep_start, g_state.sweep_end,
                   g_state.sweep_dwell_ms);
    }
    else if (strcmp(argv[0], "stop") == 0) {
        radio_stop();
        cdc_printf("OK stopped\r\n");
    }
    else if (strcmp(argv[0], "reboot_bootloader") == 0) {
        cdc_printf("OK entering bootloader\r\n");
        nrf_delay_ms(100);
        NRF_POWER->GPREGRET = 0xB1;
        NVIC_SystemReset();
    }
    else {
        cdc_printf("ERR unknown: %s\r\n", argv[0]);
    }
}

// ─── Main loop ──────────────────────────────────────────────────────────────

static char rx_buf[UART_BUF_SIZE];
static int rx_pos = 0;

/* USB CDC event handlers omitted for brevity — see Nordic SDK CDC example */

static void cdc_printf(const char *fmt, ...)
{
    char buf[128];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n > 0) {
        // Transmit via app_usbd_cdc_acm_write(&cdc, buf, n);
        // Details depend on CDC ACM class instance setup
    }
}

static void on_rx_byte(char c)
{
    if (c == '\r' || c == '\n') {
        if (rx_pos > 0) {
            rx_buf[rx_pos] = 0;
            handle_cmd(rx_buf);
            rx_pos = 0;
            cdc_printf("radio_test> ");
        }
    } else if (rx_pos < UART_BUF_SIZE - 1) {
        rx_buf[rx_pos++] = c;
    }
}

int main(void)
{
    // Initialize clock, USB, CDC-ACM...
    // (Boilerplate from Nordic SDK peripheral/usbd_cdc_acm example)
    // See Makefile for complete integration

    cdc_printf("\r\n%s\r\nType 'version' for info.\r\n", BLUESHIELD_FW_VERSION);
    cdc_printf("radio_test> ");

    while (1) {
        // USB stack tick
        // app_usbd_event_queue_process();

        // Process one RX byte if available
        // (call on_rx_byte() per byte)

        // Sweep tick if active
        if (g_state.sweep_active) {
            radio_sweep_tick();
        }
    }
}
