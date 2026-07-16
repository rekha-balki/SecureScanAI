import { useState } from "react";
import { Link as RouterLink } from "react-router-dom";
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

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const res = await api.post("/auth/forgot-password", { email });
      setResult(res.data.data);
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
          Reset your password
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Enter your account email and we'll send you a reset link.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {result ? (
          <Box sx={{ display: "grid", gap: 2 }}>
            <Alert severity="success">{result.message}</Alert>
            {result.dev_reset_token && (
              <Alert severity="info" sx={{ wordBreak: "break-all" }}>
                Dev mode — no SMTP configured yet, so here's your reset link
                directly:{" "}
                <Link
                  component={RouterLink}
                  to={`/reset-password?token=${result.dev_reset_token}`}
                  sx={{ color: tokens.accent }}
                >
                  Reset password
                </Link>
              </Alert>
            )}
          </Box>
        ) : (
          <Box component="form" onSubmit={onSubmit} sx={{ display: "grid", gap: 2 }}>
            <TextField
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              fullWidth
            />
            <Button type="submit" variant="contained" size="large" disabled={submitting}>
              {submitting ? "Sending..." : "Send reset link"}
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
