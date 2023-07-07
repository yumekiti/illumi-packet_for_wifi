# Example using PIO to drive a set of WS2812 LEDs.

import array, time
from machine import Pin, UART
import rp2

# Configure the number of WS2812 LEDs.
NUM_LEDS = 12
PIN_NUM = 22
brightness = 0.2
uart = UART(0, baudrate=9600, tx=Pin(16), rx=Pin(17), timeout=10)
rxData = bytes()
FILTER = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9']

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

##########################################################################
def pixels_show():
    dimmer_ar = array.array("I", [0 for _ in range(NUM_LEDS)])
    for i,c in enumerate(ar):
        r = int(((c >> 8) & 0xFF) * brightness)
        g = int(((c >> 16) & 0xFF) * brightness)
        b = int((c & 0xFF) * brightness)
        dimmer_ar[i] = (g<<16) + (r<<8) + b
    sm.put(dimmer_ar, 8)
    time.sleep_ms(10)

def pixels_set(i, color):
    ar[i] = (color[1]<<16) + (color[0]<<8) + color[2]

def pixels_fill_show(color):
    branch_num = 5
    for i in range((NUM_LEDS - branch_num)):
        pixels_set((branch_num - i), color)
        pixels_set(branch_num + i, color)
        pixels_show()
        pixels_set((branch_num - i), BLACK)
        pixels_set(branch_num + i, BLACK)
        pixels_show()

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

COLORS = (WHITE, GREEN, RED, BLUE, PURPLE, PINK, YELLOW, ORANGE, CYAN, LIME, GRAY, BLACK)

# 0 White others
# 1 Green
# 2 Red Anomaly
# 3 Blue TCP
# 4 Purple ARP
# 5 Pink ICMP
# 6 Yellow UDP
# 7 Orange IGMP
# 8 Cyan DHCP
# 9 Lime DNS
PACKETS = (WHITE, GREEN, RED, BLUE, PURPLE, PINK, YELLOW, ORANGE, CYAN, LIME)

print("read start")

for color in PACKETS:       
    pixels_fill_show(color)

while True:
    rxData = uart.readline()
    if rxData is not None and rxData in FILTER:
        num = int(rxData)
        if num >= 0 and num <= 9:
            pixels_fill_show(PACKETS[num])