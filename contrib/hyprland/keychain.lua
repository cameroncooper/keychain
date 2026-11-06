-- Hyprland 0.57+ (Lua). Load after your desktop's default window rules.
-- This controls presentation, not authorization or trusted-surface isolation.
hl.window_rule({
  match = { class = "^cameroncooper[.]keychain[.]Authentication$" },
  float = true,
  center = true,
  size = { 420, 290 },
  rounding = 16,
  border_size = 1,
  opacity = "1 override 1 override",
  tag = "-default-opacity",
})
