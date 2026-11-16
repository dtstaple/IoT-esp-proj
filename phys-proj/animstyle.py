"""
animstyle.py - a small renderer that mimics the Syracuse Physics 307 `anim`
tool look: a tilted 3D wireframe box with numbered tick axes on a black field,
glowing orbit trails, shaded 3D sphere bodies, and a text energy readout.

Pure matplotlib (no OpenGL), so it runs anywhere and screenshots cleanly.
Used by orbit_anim3d.py.
"""

import numpy as np


# ----------------------------------------------------------------------
# Shaded-sphere sprite (an RGBA image of a lit ball with a soft glow halo)
# ----------------------------------------------------------------------
def make_sphere_sprite(n=256, radius_frac=0.60,
                       top=(0.23, 0.48, 0.85), bottom=(0.26, 0.82, 0.48),
                       glow=(0.30, 0.60, 1.0)):
    """Return an (n, n, 4) RGBA array of a shaded sphere with a glow halo.

    top/bottom give the vertical color gradient (blue over green, like anim).
    """
    u = np.linspace(-1, 1, n)
    U, V = np.meshgrid(u, u)
    R = np.hypot(U, V)

    img = np.zeros((n, n, 4))

    # --- the solid, lit sphere (inside the disk of radius radius_frac) ---
    disk = R < radius_frac
    sx = np.where(disk, U / radius_frac, 0.0)
    sy = np.where(disk, V / radius_frac, 0.0)
    sz = np.sqrt(np.clip(1 - sx**2 - sy**2, 0, 1))

    light = np.array([-0.5, 0.6, 0.8])
    light /= np.linalg.norm(light)
    diff = np.clip(sx * light[0] + sy * light[1] + sz * light[2], 0, 1)
    ambient = 0.25
    shade = ambient + (1 - ambient) * diff

    top = np.array(top)
    bottom = np.array(bottom)
    g = ((sy + 1) / 2)[..., None]           # 0 at bottom, 1 at top
    base = bottom[None, None, :] * (1 - g) + top[None, None, :] * g
    rgb = base * shade[..., None]

    # specular highlight
    view = np.array([0, 0, 1.0])
    half = light + view
    half /= np.linalg.norm(half)
    spec = np.clip(sx * half[0] + sy * half[1] + sz * half[2], 0, 1) ** 40
    rgb = np.clip(rgb + spec[..., None] * 0.9, 0, 1)

    img[disk, :3] = rgb[disk]
    img[disk, 3] = 1.0

    # --- soft glow halo just outside the disk ---
    halo = (R >= radius_frac) & (R < 1.0)
    t = (R - radius_frac) / (1.0 - radius_frac)     # 0 at edge -> 1 at rim
    halo_alpha = np.clip((1 - t) ** 2, 0, 1) * 0.55
    img[halo, :3] = np.array(glow)[None, :]
    img[halo, 3] = halo_alpha[halo]

    return img


# ----------------------------------------------------------------------
# The 3D view: axonometric projection + wireframe frame drawing
# ----------------------------------------------------------------------
class AnimView:
    def __init__(self, ax, extent=12, az=45, el=18, tick_step=2):
        self.ax = ax
        self.L = extent
        self.tick_step = tick_step
        self.az = np.radians(az)
        self.el = np.radians(el)
        self._R = self._rotation()

    def _rotation(self):
        az, el = self.az, self.el
        Rz = np.array([[np.cos(az), -np.sin(az), 0],
                       [np.sin(az),  np.cos(az), 0],
                       [0, 0, 1]])
        Rx = np.array([[1, 0, 0],
                       [0, np.cos(el), -np.sin(el)],
                       [0, np.sin(el),  np.cos(el)]])
        return Rx @ Rz

    def project(self, P):
        """3D world points -> (screen_x, screen_y, depth)."""
        P = np.atleast_2d(np.asarray(P, dtype=float))
        c = P @ self._R.T
        return c[:, 0], c[:, 2], c[:, 1]   # x=right, y=up(screen), depth

    # -- draw the static coordinate frame once --
    def draw_frame(self):
        L = self.L
        white = "#f2f2f2"

        # faint bounding cube
        r = [-L, L]
        corners = np.array([[x, y, z] for x in r for y in r for z in r])
        for i in range(len(corners)):
            for j in range(i + 1, len(corners)):
                if np.sum(corners[i] != corners[j]) == 1:   # share an edge
                    X, Y, _ = self.project(np.vstack([corners[i], corners[j]]))
                    self.ax.plot(X, Y, color=white, lw=0.6, alpha=0.25)

        # three axes through the origin, with ticks + numeric labels
        for axis in range(3):
            p0 = np.zeros(3); p1 = np.zeros(3)
            p0[axis], p1[axis] = -L, L
            X, Y, _ = self.project(np.vstack([p0, p1]))
            self.ax.plot(X, Y, color=white, lw=0.9, alpha=0.7)

            perp_axis = (axis + 1) % 3
            for t in range(-L, L + 1, self.tick_step):
                if t == 0:
                    continue
                base = np.zeros(3); base[axis] = t
                a = base.copy(); b = base.copy()
                a[perp_axis] -= L * 0.025
                b[perp_axis] += L * 0.025
                Xt, Yt, _ = self.project(np.vstack([a, b]))
                self.ax.plot(Xt, Yt, color=white, lw=0.7, alpha=0.5)
                Xl, Yl, _ = self.project(base)
                self.ax.text(Xl[0], Yl[0], f"{t}", color=white,
                             fontsize=6, alpha=0.65, ha="center", va="center")

        m = L * 1.25
        self.ax.set_xlim(-m, m)
        self.ax.set_ylim(-m, m)
        self.ax.set_aspect("equal")
        self.ax.axis("off")