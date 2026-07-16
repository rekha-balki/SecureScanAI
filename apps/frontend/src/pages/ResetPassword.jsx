import { useState } from "react";
import { Link as RouterLink, useNavigate, useSearchParams } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Link,
  Paper,
  TextField,
  Typography,
} from "@mui/material";
import { api, extractErrorMessage } from "../api/client";
import { tokens } from "../theme";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [token, setToken] = useState(searchParams.get("token") || "");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await api.post("/auth/reset-password", { token, new_password: password });
      setDone(true);
      setTimeout(() => navigate("/login", { replace: true }), 2000);
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        px: 2,
      }}
    >
      <Paper sx={{ width: 400, p: 4, borderRadius: 3 }}>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          Set a new password
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Paste the reset token from your email and choose a new password.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {done ? (
          <Alert severity="success">
            Password updated. Redirecting you to sign in...
          </Alert>
        ) : (
          <Box component="form" onSubmit={onSubmit} sx={{ display: "grid", gap: 2 }}>
            <TextField
              label="Reset token"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              required
              fullWidth
              multiline
              maxRows={3}
            />
            <TextField
              label="New password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              helperText="At least 12 characters, with upper, lower, number, and a special character."
              required
              fullWidth
            />
            <Button type="submit" variant="contained" size="large" disabled={submitting}>
              {submitting ? "Updating..." : "Update password"}
            </Button>
          </Box>
        )}

        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          <Link component={RouterLink} to="/login" sx={{ color: tokens.accent }}>
            Back to sign in
          </Link>
        </Typography>
      </Paper>
    </Box>
  );
}
