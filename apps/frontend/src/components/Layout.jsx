import { useEffect, useState } from "react";
import { Link as RouterLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Avatar,
  Badge,
  Box,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Toolbar,
  Typography,
} from "@mui/material";
import DashboardIcon from "@mui/icons-material/SpaceDashboardOutlined";
import ScanIcon from "@mui/icons-material/TravelExploreOutlined";
import ApiScanIcon from "@mui/icons-material/CodeOutlined";
import HistoryIcon from "@mui/icons-material/HistoryOutlined";
import UsersIcon from "@mui/icons-material/GroupOutlined";
import SettingsIcon from "@mui/icons-material/SettingsOutlined";
import LogoutIcon from "@mui/icons-material/LogoutOutlined";
import NotificationsIcon from "@mui/icons-material/NotificationsNoneOutlined";
import ShieldIcon from "@mui/icons-material/VerifiedUserOutlined";
import { useAuth } from "../context/AuthContext";
import { api } from "../api/client";
import { tokens } from "../theme";

const DRAWER_WIDTH = 236;

const NAV_ITEMS = [
  { label: "Dashboard", icon: DashboardIcon, path: "/" },
  { label: "New Scan", icon: ScanIcon, path: "/scans/new" },
  { label: "API Scan", icon: ApiScanIcon, path: "/scans/new-api" },
  { label: "Scan History", icon: HistoryIcon, path: "/scans" },
  { label: "Users", icon: UsersIcon, path: "/users" },
  { label: "Settings", icon: SettingsIcon, path: "/settings" },
];

const AUDIT_ROLES = ["company_admin", "platform_admin", "auditor"];

function RadarMark() {
  return (
    <Box
      sx={{
        width: 30,
        height: 30,
        borderRadius: "50%",
        position: "relative",
        display: "grid",
        placeItems: "center",
        background: `radial-gradient(circle at center, ${tokens.accentDim}, transparent 70%)`,
        border: `1px solid ${tokens.accent}66`,
        "&::before": {
          content: '""',
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          background: `conic-gradient(from 0deg, ${tokens.accent}, transparent 35%)`,
          animation: "ssai-sweep 2.6s linear infinite",
          opacity: 0.55,
          "@media (prefers-reduced-motion: reduce)": { animation: "none" },
        },
        "@keyframes ssai-sweep": {
          from: { transform: "rotate(0deg)" },
          to: { transform: "rotate(360deg)" },
        },
      }}
    >
      <Box
        sx={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          bgcolor: tokens.accent,
          boxShadow: `0 0 8px ${tokens.accent}`,
          zIndex: 1,
        }}
      />
    </Box>
  );
}

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [anchorEl, setAnchorEl] = useState(null);
  const [notifAnchorEl, setNotifAnchorEl] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);

  const initials = user
    ? `${user.first_name?.[0] || ""}${user.last_name?.[0] || ""}`.toUpperCase()
    : "?";

  const navItems = AUDIT_ROLES.includes(user?.role)
    ? [...NAV_ITEMS, { label: "Audit Logs", icon: ShieldIcon, path: "/audit-logs" }]
    : NAV_ITEMS;

  const loadNotifications = () => {
    api.get("/notifications").then((res) => {
      setNotifications(res.data.data.items);
      setUnreadCount(res.data.data.unread_count);
    });
  };

  useEffect(() => {
    loadNotifications();
    const interval = setInterval(loadNotifications, 20000);
    return () => clearInterval(interval);
  }, []);

  const openNotifications = (e) => {
    setNotifAnchorEl(e.currentTarget);
  };

  const onNotificationClick = async (n) => {
    if (!n.is_read) {
      await api.post(`/notifications/${n.id}/read`);
      loadNotifications();
    }
    setNotifAnchorEl(null);
    if (n.scan_id) navigate(`/scans/${n.scan_id}`);
  };

  const markAllRead = async () => {
    await api.post("/notifications/read-all");
    loadNotifications();
  };

  return (
    <Box sx={{ display: "flex", minHeight: "100vh" }}>
      <Drawer
        variant="permanent"
        sx={{
          width: DRAWER_WIDTH,
          flexShrink: 0,
          "& .MuiDrawer-paper": {
            width: DRAWER_WIDTH,
            boxSizing: "border-box",
            bgcolor: tokens.panel,
            borderRight: `1px solid ${tokens.border}`,
          },
        }}
      >
        <Toolbar sx={{ gap: 1.25, px: 2.5 }}>
          <RadarMark />
          <Typography
            variant="h6"
            sx={{ letterSpacing: 0.3, fontSize: "1.05rem" }}
          >
            SecureScan AI
          </Typography>
        </Toolbar>

        <List sx={{ px: 1.5, mt: 1 }}>
          {navItems.map(({ label, icon: Icon, path }) => {
            const active =
              path === "/"
                ? location.pathname === "/"
                : location.pathname.startsWith(path);

            return (
              <ListItemButton
                key={path}
                component={RouterLink}
                to={path}
                selected={active}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  color: active ? tokens.accent : tokens.textMuted,
                  "&.Mui-selected": {
                    bgcolor: tokens.accentDim,
                    "&:hover": { bgcolor: tokens.accentDim },
                  },
                }}
              >
                <ListItemIcon sx={{ color: "inherit", minWidth: 38 }}>
                  <Icon fontSize="small" />
                </ListItemIcon>
                <ListItemText
                  primary={label}
                  primaryTypographyProps={{ fontSize: "0.9rem", fontWeight: 600 }}
                />
              </ListItemButton>
            );
          })}
        </List>
      </Drawer>

      <Box sx={{ flexGrow: 1, display: "flex", flexDirection: "column" }}>
        <Toolbar
          sx={{
            justifyContent: "flex-end",
            gap: 1,
            borderBottom: `1px solid ${tokens.border}`,
            bgcolor: "background.default",
          }}
        >
          <IconButton onClick={openNotifications}>
            <Badge badgeContent={unreadCount} color="primary">
              <NotificationsIcon />
            </Badge>
          </IconButton>
          <Menu
            anchorEl={notifAnchorEl}
            open={Boolean(notifAnchorEl)}
            onClose={() => setNotifAnchorEl(null)}
            PaperProps={{ sx: { width: 360, maxHeight: 420 } }}
          >
            <Box sx={{ px: 2, py: 1.25, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <Typography variant="subtitle2">Notifications</Typography>
              {unreadCount > 0 && (
                <Typography
                  variant="caption"
                  onClick={markAllRead}
                  sx={{ color: tokens.accent, cursor: "pointer" }}
                >
                  Mark all read
                </Typography>
              )}
            </Box>
            <Divider />
            {notifications.length === 0 && (
              <Box sx={{ px: 2, py: 3 }}>
                <Typography variant="body2" color="text.secondary">
                  You're all caught up.
                </Typography>
              </Box>
            )}
            {notifications.map((n) => (
              <MenuItem
                key={n.id}
                onClick={() => onNotificationClick(n)}
                sx={{
                  whiteSpace: "normal",
                  alignItems: "flex-start",
                  borderLeft: n.is_read ? "none" : `3px solid ${tokens.accent}`,
                  bgcolor: n.is_read ? "transparent" : tokens.accentDim,
                }}
              >
                <Box>
                  <Typography variant="body2" fontWeight={600}>
                    {n.title}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                    {n.message}
                  </Typography>
                </Box>
              </MenuItem>
            ))}
          </Menu>

          <IconButton onClick={(e) => setAnchorEl(e.currentTarget)}>
            <Avatar
              sx={{
                width: 32,
                height: 32,
                bgcolor: tokens.accentDim,
                color: tokens.accent,
                fontSize: "0.8rem",
                fontWeight: 700,
              }}
            >
              {initials}
            </Avatar>
          </IconButton>
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={() => setAnchorEl(null)}
          >
            <Box sx={{ px: 2, py: 1 }}>
              <Typography variant="body2" fontWeight={600}>
                {user?.first_name} {user?.last_name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {user?.role?.replace("_", " ")}
              </Typography>
            </Box>
            <MenuItem onClick={logout}>
              <ListItemIcon>
                <LogoutIcon fontSize="small" />
              </ListItemIcon>
              Log out
            </MenuItem>
          </Menu>
        </Toolbar>

        <Box sx={{ flexGrow: 1, p: { xs: 2, md: 4 } }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}
