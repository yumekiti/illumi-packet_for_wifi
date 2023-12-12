# Example using PIO to drive a set of WS2812 LEDs.

import array, time
from machine import Pin, UART
import rp2

# Configure the number of WS2812 LEDs.
NUM_LEDS = 13
PIN_NUM = 7
brightness = 1.0
separator = [5, 4, 3, 1]
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

def pixels_set(i, color):
    ar[i] = (color[1]<<16) + (color[0]<<8) + color[2]

def pixels_fill(color):
    for i in range(len(ar)):
        pixels_set(i, color)

def color_chase(color, wait):
    for i in range(NUM_LEDS):
        pixels_set(i, color)
        time.sleep(wait)
        pixels_show()
    time.sleep(0.2)
 
def wheel(pos):
    # Input a value 0 to 255 to get a color value.
    # The colours are a transition r - g - b - back to r.
    if pos < 0 or pos > 255:
        return (0, 0, 0)
    if pos < 85:
        return (255 - pos * 3, pos * 3, 0)
    if pos < 170:
        pos -= 85
        return (0, 255 - pos * 3, pos * 3)
    pos -= 170
    return (pos * 3, 0, 255 - pos * 3)
 
 
def rainbow_cycle(wait):
    for j in range(255):
        for i in range(NUM_LEDS):
            rc_index = (i * 256 // NUM_LEDS) + j
            pixels_set(i, wheel(rc_index & 255))
        pixels_show()
        time.sleep(wait)

def light_up_sections(separator, direction, color):
    if direction == 0:
        start_index = 0
        for section_length in separator:
            end_index = start_index + section_length
            for i in range(start_index, end_index):
                pixels_set(i, color)
            pixels_show()

            time.sleep_ms(80)

            for i in range(start_index, end_index):
                pixels_set(i, BLACK)
            pixels_show()

            start_index = end_index
    elif direction == 1:
        start_index = NUM_LEDS
        for section_length in reversed(separator):
            start_index -= section_length
            end_index = start_index + section_length
            for i in range(start_index, end_index):
                pixels_set(i, color)
            pixels_show()

            time.sleep_ms(80)

            for i in range(start_index, end_index):
                pixels_set(i, BLACK)
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

light_up_sections(separator, 0, WHITE)

while True:
    rxData = uart.readline()
    if rxData is not None:
        direction = int(rxData[0])
        color = int(rxData[1])
        if color >= 0 and color <= 9:
            light_up_sections(separator, direction, PACKETS[color])
