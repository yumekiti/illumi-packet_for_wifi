# Example using PIO to drive a set of WS2812 LEDs.

import array, time
from machine import Pin, UART
import rp2

# Configure the number of WS2812 LEDs.
NUM_LEDS = 12
PIN_NUM = 26
brightness = 1
uart = UART(0, baudrate=9600, tx=Pin(0), rx=Pin(1), timeout=10)
rxData = bytes()

@rp2.asm_pio(sideset_init=rp2.PIO.OUT_LOW, out_shiftdir=rp2.PIO.SHIFT_LEFT, autopull=True, pull_thresh=24)
def ws2812():
    T1 = 2
    T2 = 5
    T3 = 3
    wrap_target()
    label("bitloop")
    out(x, 1)               .side(0)    [T3 - 1]
    jmp(not_x, "do_zero")   .side(1)    [T1 - 1]
    jmp("bitloop")          .side(1)    [T2 - 1]
    label("do_zero")
    nop()                   .side(0)    [T2 - 1]
    wrap()


# Create the StateMachine with the ws2812 program, outputting on pin
sm = rp2.StateMachine(0, ws2812, freq=8_000_000, sideset_base=Pin(PIN_NUM))

# Start the StateMachine, it will wait for data on its FIFO.
sm.active(1)

# Display a pattern on the LEDs via an array of LED RGB values.
ar = array.array("I", [0 for _ in range(NUM_LEDS)])

WHITE = (255, 255, 255)
GREEN = (136, 0, 0)
RED = (0, 255, 0)
BLUE = (0, 0, 255)
PURPLE = (128, 0, 128)
PINK = (255, 192, 203)
YELLOW = (255, 255, 0)
ORANGE = (255, 165, 0)
CYAN = (0, 156, 209)
LIME = (0, 255, 0)
GRAY = (136, 136, 136)
BLACK = (0, 0, 0)

# 0 White others
# 1 Red Anomaly
# 2 Green LLDP
# 3 Lime DNS
# 4 Pink ICMP
# 5 Cyan DHCP
# 6 Purple ARP
# 7 Orange IGMP
# 8 Yellow UDP
# 9 Blue TCP
PACKETS = (WHITE, RED, GREEN, LIME, PINK, CYAN, PURPLE, ORANGE, YELLOW, BLUE)

##########################################################################
def pixels_show():
    dimmer_ar = array.array("I", [0 for _ in range(NUM_LEDS)])
    for i,c in enumerate(ar):
        r = int(((c >> 8) & 0xFF) * brightness)
        g = int(((c >> 16) & 0xFF) * brightness)
        b = int((c & 0xFF) * brightness)
        dimmer_ar[i] = (g<<16) + (r<<8) + b
    sm.put(dimmer_ar, 8)

def pixels_set(i, color):
    ar[i] = (color[1]<<16) + (color[0]<<8) + color[2]

def display_color_directionally(direction, color):
    branch_num = 5
    black_color = (0, 0, 0)
    if direction == 0:
        for i in range(NUM_LEDS - branch_num):
            if ((branch_num - 1) - i) >= 0:
                pixels_set(((branch_num - 1) - i), color)
            if (branch_num + i) <= (NUM_LEDS - 1):
                pixels_set((branch_num + i), color)
            pixels_show()
            time.sleep_ms(50)
            if ((branch_num - 1) - i) >= 0:
                pixels_set(((branch_num - 1) - i), black_color)
            if (branch_num + i) <= (NUM_LEDS - 1):
                pixels_set((branch_num + i), black_color)
            pixels_show()
    elif direction == 1:
        for i in range(NUM_LEDS - branch_num):
            if (NUM_LEDS - (i + 1)) >= 0:
                pixels_set((NUM_LEDS - (i + 1)), color)
            if i >= (NUM_LEDS - branch_num) - branch_num:
                pixels_set(i - ((NUM_LEDS - branch_num) - branch_num), color)
            pixels_show()
            time.sleep_ms(50)
            if (NUM_LEDS - (i + 1)) >= 0:
                pixels_set((NUM_LEDS - (i + 1)), black_color)
            if i >= (NUM_LEDS - branch_num) - branch_num:
                pixels_set(i - ((NUM_LEDS - branch_num) - branch_num), black_color)
            pixels_show()


display_color_directionally(1, WHITE)

while True:
    rxData = uart.readline()
    if rxData is not None:
        direction = int(rxData[0])
        color = int(rxData[1])
        if 0 <= color <= 9:
            display_color_directionally(direction, PACKETS[color])

