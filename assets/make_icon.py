#!/usr/bin/env python3
"""Generate the VortexSSH icon (SVG source) — a vortex spiral on a dark tile."""

import math

SIZE = 256
CX = CY = SIZE / 2

# Archimedean spiral: r = r0 + k * theta
TURNS = 2.4
R0 = 12.0
R_MAX = 104.0
THETA_MAX = 2 * math.pi * TURNS
K = (R_MAX - R0) / THETA_MAX

STEPS = 900
points = []
for i in range(STEPS + 1):
    theta = THETA_MAX * i / STEPS
    r = R0 + K * theta
    x = CX + r * math.cos(theta)
    y = CY + r * math.sin(theta)
    points.append(f"{x:.2f},{y:.2f}")

polyline = " ".join(points)

svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{SIZE}" height="{SIZE}" viewBox="0 0 {SIZE} {SIZE}">
  <defs>
    <linearGradient id="tile" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#1d2130"/>
      <stop offset="1" stop-color="#0d0f17"/>
    </linearGradient>
    <linearGradient id="spiral" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#22d3ee"/>
      <stop offset="0.55" stop-color="#0ea5e9"/>
      <stop offset="1" stop-color="#6366f1"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="#22d3ee" stop-opacity="0.18"/>
      <stop offset="1" stop-color="#22d3ee" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="{SIZE}" height="{SIZE}" rx="52" fill="url(#tile)"/>
  <circle cx="{CX}" cy="{CY}" r="112" fill="url(#glow)"/>
  <polyline points="{polyline}" fill="none" stroke="url(#spiral)"
            stroke-width="15" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="{CX}" cy="{CY}" r="6" fill="#22d3ee"/>
</svg>
"""

with open("assets/icon.svg", "w") as f:
    f.write(svg)
print("wrote assets/icon.svg")
