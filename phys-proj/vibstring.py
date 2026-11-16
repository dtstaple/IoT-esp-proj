"""
Physics 307 - Project 5, styled like the course `anim` tool
===========================================================
Same leapfrog orbit physics as orbit_sim.py, but rendered in the classic
`anim` look: a tilted 3D wireframe box with numbered tick axes, a glowing
orbit trail, a shaded 3D planet, and a live "Total Current Energy" readout.

HOW TO RUN (VS Code):
    pip install numpy matplotlib
    python orbit_anim3d.py circular
    python orbit_anim3d.py ellipse
    python orbit_anim3d.py precess
    python orbit_anim3d.py offset_sun

Units: AU, solar masses, years  ->  G = 4*pi^2.
Orbits live in the z = 0 plane; the 3D frame is just for the view.
"""

import sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

from animstyle import AnimView, make_sphere_sprite

G = 4.0 * np.pi**2
M = 1.0

# pos0/vel0 are 3-vectors (z=0). extent sizes the box to the orbit.
SCENARIOS = {
    "circular":   dict(pos0=[1, 0, 0], vel0=[0, 2*np.pi, 0],
                       sun=[0, 0, 0], eps=0.0, extent=3, tick=1),
    "ellipse":    dict(pos0=[1, 0, 0], vel0=[0, 5.0, 0],
                       sun=[0, 0, 0], eps=0.0, extent=3, tick=1),
    "precess":    dict(pos0=[1, 0, 0], vel0=[0, 5.0, 0],
                       sun=[0, 0, 0], eps=0.05, extent=3, tick=1),
    "offset_sun": dict(pos0=[1.2, 0.3, 0], vel0=[0, 5.0, 0],
                       sun=[0.2, 0.3, 0], eps=0.0, extent=3, tick=1),
}

DT = 1.0e-3
STEPS_PER_FRAME = 20
TRAIL_LENGTH = 6000


def acceleration(pos, sun, eps):
    d = pos - sun
    r = np.linalg.norm(d)
    return -G * M * d / r ** (3.0 + eps)


def leapfrog_step(pos, vel, sun, eps, dt):
    pos = pos + vel * (dt / 2.0)
    vel = vel + acceleration(pos, sun, eps) * dt
    pos = pos + vel * (dt / 2.0)
    return pos, vel


def specific_energy(pos, vel, sun):
    r = np.linalg.norm(pos - sun)
    return 0.5 * float(vel @ vel) - G * M / r


def run(name):
    if name not in SCENARIOS:
        raise SystemExit(f"Unknown scenario '{name}'. Options: {', '.join(SCENARIOS)}")
    cfg = SCENARIOS[name]
    pos = np.array(cfg["pos0"], float)
    vel = np.array(cfg["vel0"], float)
    sun = np.array(cfg["sun"], float)
    eps = cfg["eps"]
    t = 0.0
    trail = []

    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(8, 8))
    fig.patch.set_facecolor("black")
    ax.set_facecolor("black")
    fig.canvas.manager.set_window_title(f"Physics 307 - anim style: {name}")

    view = AnimView(ax, extent=cfg["extent"], az=45, el=18, tick_step=cfg["tick"])
    view.draw_frame()

    # glowing trail = four stacked lines (wide+faint -> thin+bright)
    glow_specs = [(9, 0.04), (6, 0.08), (3.5, 0.16), (1.6, 0.95)]
    trail_lines = [ax.plot([], [], color="#ff7a1a", lw=lw, alpha=a,
                           solid_capstyle="round", zorder=3)[0]
                   for lw, a in glow_specs]

    # Sun sprite (static, at its position)
    sun_sprite = make_sphere_sprite(top=(1.0, 0.95, 0.5), bottom=(1.0, 0.7, 0.15),
                                    glow=(1.0, 0.8, 0.3))
    sxx, syy, _ = view.project(sun)
    rs = cfg["extent"] * 0.16
    ax.imshow(sun_sprite, extent=[sxx[0]-rs, sxx[0]+rs, syy[0]-rs, syy[0]+rs],
              zorder=4, interpolation="bilinear")

    # Planet sprite (moves)
    planet_sprite = make_sphere_sprite()
    rp = cfg["extent"] * 0.14
    px, py, _ = view.project(pos)
    planet_img = ax.imshow(planet_sprite,
                           extent=[px[0]-rp, px[0]+rp, py[0]-rp, py[0]+rp],
                           zorder=5, interpolation="bilinear")

    readout = ax.text(0.03, 0.97, "", transform=ax.transAxes, color="white",
                      family="monospace", fontsize=11, va="top")

    def update(_):
        nonlocal pos, vel, t
        for _ in range(STEPS_PER_FRAME):
            pos, vel = leapfrog_step(pos, vel, sun, eps, DT)
            t += DT
        trail.append(pos.copy())
        if len(trail) > TRAIL_LENGTH:
            del trail[0]

        X, Y, _ = view.project(np.array(trail))
        for line in trail_lines:
            line.set_data(X, Y)

        px, py, _ = view.project(pos)
        planet_img.set_extent([px[0]-rp, px[0]+rp, py[0]-rp, py[0]+rp])

        e = specific_energy(pos, vel, sun)
        readout.set_text(f"Total Current Energy: {e:.6e}")
        return (*trail_lines, planet_img, readout)

    anim = FuncAnimation(fig, update, interval=20, blit=False, cache_frame_data=False)
    plt.show()
    return anim


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "ellipse")