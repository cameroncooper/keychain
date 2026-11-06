-- Hyprland 0.57+ (Lua). Load after your desktop's default window rules.
-- This controls presentation, not authorization or trusted-surface isolation.
hl.window_rule({
  match = { class = "^cameroncooper[.]keychain[.]Authentication$" },
  float = true,
  center = true,
  size = { 420, 340 },
  opacity = "1 override 1 override",
  tag = "-default-opacity",
})
