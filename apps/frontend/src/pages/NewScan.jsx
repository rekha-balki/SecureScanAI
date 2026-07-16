import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  MenuItem,
  Paper,
  TextField,
  Typography,
} from "@mui/material";
import { api, extractErrorMessage } from "../api/client";

const initialForm = {
  name: "",
  target_url: "",
  description: "",
  max_depth: 2,
  max_pages: 25,
  priority: "normal",
};

const initialAuth = {
  type: "none",
  bearer_token: "",
  cookie_name: "",
  cookie_value: "",
  login_url: "",
  username_field: "username",
  username: "",
  password_field: "password",
  password: "",
};

export default function NewScan() {
  const navigate = useNavigate();
  const [form, setForm] = useState(initialForm);
  const [auth, setAuth] = useState(initialAuth);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const update = (field) => (e) =>
    setForm((prev) => ({ ...prev, [field]: e.target.value }));

  const updateAuth = (field) => (e) =>
    setAuth((prev) => ({ ...prev, [field]: e.target.value }));

  const buildAuthConfig = () => {
    if (auth.type === "none") return null;

    if (auth.type === "bearer") {
      return { type: "bearer", bearer_token: auth.bearer_token };
    }

    if (auth.type === "cookie") {
      return {
        type: "cookie",
        cookies: auth.cookie_name ? { [auth.cookie_name]: auth.cookie_value } : {},
      };
    }

    if (auth.type === "form") {
      return {
        type: "form",
        login_url: auth.login_url,
        username_field: auth.username_field,
        username: auth.username,
        password_field: auth.password_field,
        password: auth.password,
      };
    }

    return null;
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const res = await api.post("/scans", {
        ...form,
        max_depth: Number(form.max_depth),
        max_pages: Number(form.max_pages),
        auth_config: buildAuthConfig(),
      });
      navigate(`/scans/${res.data.data.id}`);
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 640, display: "grid", gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          New Scan
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Only scan targets you are authorized to assess.
        </Typography>
      </Box>

      <Paper sx={{ p: 3 }}>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box component="form" onSubmit={onSubmit} sx={{ display: "grid", gap: 2 }}>
          <TextField
            label="Scan name"
            value={form.name}
            onChange={update("name")}
            required
            fullWidth
          />
          <TextField
            label="Target URL"
            placeholder="https://example.com"
            value={form.target_url}
            onChange={update("target_url")}
            required
            fullWidth
          />
          <TextField
            label="Description (optional)"
            value={form.description}
            onChange={update("description")}
            multiline
            minRows={2}
            fullWidth
          />
          <Box sx={{ display: "flex", gap: 2 }}>
            <TextField
              label="Max crawl depth"
              type="number"
              value={form.max_depth}
              onChange={update("max_depth")}
              inputProps={{ min: 0, max: 10 }}
              fullWidth
            />
            <TextField
              label="Max pages"
              type="number"
              value={form.max_pages}
              onChange={update("max_pages")}
              inputProps={{ min: 1, max: 500 }}
              fullWidth
            />
          </Box>
          <TextField
            select
            label="Priority"
            value={form.priority}
            onChange={update("priority")}
            fullWidth
          >
            {["critical", "high", "normal", "low"].map((p) => (
              <MenuItem key={p} value={p} sx={{ textTransform: "capitalize" }}>
                {p}
              </MenuItem>
            ))}
          </TextField>

          <Button type="submit" variant="contained" size="large" disabled={submitting}>
            {submitting ? "Queuing scan..." : "Start Scan"}
          </Button>
        </Box>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="subtitle1" sx={{ mb: 0.5 }}>
          Authentication (optional)
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Reach content behind a login. Credentials are sent to the backend
          and stored with the scan configuration to replay the session.
        </Typography>

        <Box sx={{ display: "grid", gap: 2 }}>
          <TextField
            select
            label="Authentication type"
            value={auth.type}
            onChange={updateAuth("type")}
            fullWidth
          >
            <MenuItem value="none">None</MenuItem>
            <MenuItem value="bearer">Bearer token</MenuItem>
            <MenuItem value="cookie">Session cookie</MenuItem>
            <MenuItem value="form">Form login</MenuItem>
          </TextField>

          {auth.type === "bearer" && (
            <TextField
              label="Bearer token"
              value={auth.bearer_token}
              onChange={updateAuth("bearer_token")}
              fullWidth
            />
          )}

          {auth.type === "cookie" && (
            <Box sx={{ display: "flex", gap: 2 }}>
              <TextField
                label="Cookie name"
                value={auth.cookie_name}
                onChange={updateAuth("cookie_name")}
                fullWidth
              />
              <TextField
                label="Cookie value"
                value={auth.cookie_value}
                onChange={updateAuth("cookie_value")}
                fullWidth
              />
            </Box>
          )}

          {auth.type === "form" && (
            <>
              <TextField
                label="Login URL"
                placeholder="https://example.com/login"
                value={auth.login_url}
                onChange={updateAuth("login_url")}
                fullWidth
              />
              <Box sx={{ display: "flex", gap: 2 }}>
                <TextField
                  label="Username field name"
                  value={auth.username_field}
                  onChange={updateAuth("username_field")}
                  fullWidth
                />
                <TextField
                  label="Username"
                  value={auth.username}
                  onChange={updateAuth("username")}
                  fullWidth
                />
              </Box>
              <Box sx={{ display: "flex", gap: 2 }}>
                <TextField
                  label="Password field name"
                  value={auth.password_field}
                  onChange={updateAuth("password_field")}
                  fullWidth
                />
                <TextField
                  label="Password"
                  type="password"
                  value={auth.password}
                  onChange={updateAuth("password")}
                  fullWidth
                />
              </Box>
            </>
          )}
        </Box>
      </Paper>
    </Box>
  );
}
