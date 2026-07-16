import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  FormControlLabel,
  Paper,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import { api, extractErrorMessage } from "../api/client";
import { useAuth } from "../context/AuthContext";

const CAN_EDIT = ["company_admin", "platform_admin"];

export default function Settings() {
  const { user } = useAuth();
  const [settings, setSettings] = useState(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState("");

  const canEdit = CAN_EDIT.includes(user?.role);

  useEffect(() => {
    api.get("/settings").then((res) => setSettings(res.data.data));
  }, []);

  const update = (section, field) => (e) => {
    const value =
      e.target.type === "checkbox" ? e.target.checked : e.target.value;
    setSettings((prev) =>
      section
        ? { ...prev, [section]: { ...prev[section], [field]: value } }
        : { ...prev, [field]: value }
    );
  };

  const onSave = async () => {
    setSaving(true);
    setError("");
    setMessage(null);
    try {
      const res = await api.put("/settings", settings);
      setSettings(res.data.data);
      setMessage("Settings saved.");
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setSaving(false);
    }
  };

  if (!settings) return null;

  return (
    <Box sx={{ display: "grid", gap: 2, maxWidth: 640 }}>
      <Typography variant="h4">Settings</Typography>

      <Paper sx={{ p: 3, display: "grid", gap: 1 }}>
        <Typography variant="overline" color="text.secondary">
          Account
        </Typography>
        <Typography variant="body1">
          {user?.first_name} {user?.last_name}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {user?.email}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ textTransform: "capitalize" }}>
          Role: {user?.role?.replace("_", " ")}
        </Typography>
      </Paper>

      {error && <Alert severity="error">{error}</Alert>}
      {message && <Alert severity="success">{message}</Alert>}

      <Paper sx={{ p: 3, display: "grid", gap: 2 }}>
        <Typography variant="overline" color="text.secondary">
          Scanner defaults
        </Typography>
        <Box sx={{ display: "flex", gap: 2 }}>
          <TextField
            label="Max crawl depth"
            type="number"
            value={settings.scanner_defaults.max_depth}
            onChange={update("scanner_defaults", "max_depth")}
            disabled={!canEdit}
            fullWidth
          />
          <TextField
            label="Max pages"
            type="number"
            value={settings.scanner_defaults.max_pages}
            onChange={update("scanner_defaults", "max_pages")}
            disabled={!canEdit}
            fullWidth
          />
        </Box>
        <TextField
          label="Request delay (ms)"
          type="number"
          value={settings.scanner_defaults.request_delay_ms}
          onChange={update("scanner_defaults", "request_delay_ms")}
          disabled={!canEdit}
          fullWidth
        />
        <FormControlLabel
          control={
            <Switch
              checked={settings.scanner_defaults.enable_js_rendering}
              onChange={update("scanner_defaults", "enable_js_rendering")}
              disabled={!canEdit}
            />
          }
          label="Enable JS-rendered link discovery (requires Playwright installed on the server)"
        />
      </Paper>

      <Paper sx={{ p: 3, display: "grid", gap: 2 }}>
        <Typography variant="overline" color="text.secondary">
          Password policy
        </Typography>
        <TextField
          label="Minimum length"
          type="number"
          value={settings.password_policy.min_length}
          onChange={update("password_policy", "min_length")}
          disabled={!canEdit}
          fullWidth
        />
        {["require_uppercase", "require_lowercase", "require_number", "require_special_char"].map(
          (field) => (
            <FormControlLabel
              key={field}
              control={
                <Switch
                  checked={settings.password_policy[field]}
                  onChange={update("password_policy", field)}
                  disabled={!canEdit}
                />
              }
              label={field.replace("require_", "Require ").replace("_", " ")}
              sx={{ textTransform: "capitalize" }}
            />
          )
        )}
      </Paper>

      <Paper sx={{ p: 3, display: "grid", gap: 2 }}>
        <Typography variant="overline" color="text.secondary">
          Session
        </Typography>
        <TextField
          label="Session timeout (minutes)"
          type="number"
          value={settings.session_timeout_minutes}
          onChange={update(null, "session_timeout_minutes")}
          disabled={!canEdit}
          fullWidth
        />
      </Paper>

      <Paper sx={{ p: 3, display: "grid", gap: 2 }}>
        <Typography variant="overline" color="text.secondary">
          SMTP (for password reset emails)
        </Typography>
        <TextField
          label="Host"
          value={settings.smtp.host || ""}
          onChange={update("smtp", "host")}
          disabled={!canEdit}
          fullWidth
        />
        <Box sx={{ display: "flex", gap: 2 }}>
          <TextField
            label="Port"
            type="number"
            value={settings.smtp.port}
            onChange={update("smtp", "port")}
            disabled={!canEdit}
            fullWidth
          />
          <TextField
            label="From address"
            value={settings.smtp.from_address || ""}
            onChange={update("smtp", "from_address")}
            disabled={!canEdit}
            fullWidth
          />
        </Box>
      </Paper>

      <Paper sx={{ p: 3, display: "grid", gap: 2 }}>
        <Typography variant="overline" color="text.secondary">
          Report branding
        </Typography>
        <TextField
          label="Logo URL"
          value={settings.report_branding.logo_url || ""}
          onChange={update("report_branding", "logo_url")}
          disabled={!canEdit}
          fullWidth
        />
        <TextField
          label="Footer text"
          value={settings.report_branding.footer_text || ""}
          onChange={update("report_branding", "footer_text")}
          disabled={!canEdit}
          fullWidth
        />
      </Paper>

      {canEdit && (
        <Button variant="contained" size="large" onClick={onSave} disabled={saving}>
          {saving ? "Saving..." : "Save settings"}
        </Button>
      )}
      {!canEdit && (
        <Typography variant="caption" color="text.secondary">
          Only company administrators can change these settings.
        </Typography>
      )}
    </Box>
  );
}
