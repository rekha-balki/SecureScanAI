import { useState } from "react";
import { Link as RouterLink, useNavigate } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Link,
  Paper,
  TextField,
  Typography,
} from "@mui/material";
import { useAuth } from "../context/AuthContext";
import { tokens } from "../theme";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    const result = await login(email, password);
    setSubmitting(false);
    if (result.ok) {
      navigate("/", { replace: true });
    } else {
      setError(result.message);
    }
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        position: "relative",
        overflow: "hidden",
        px: 2,
      }}
    >
      <Box
        sx={{
          position: "absolute",
          top: "50%",
          left: "50%",
          width: 640,
          height: 640,
          transform: "translate(-50%, -50%)",
          borderRadius: "50%",
          background: `conic-gradient(from 90deg, ${tokens.accent}22, transparent 30%)`,
          animation: "ssai-hero-sweep 9s linear infinite",
          "@media (prefers-reduced-motion: reduce)": { animation: "none" },
          "@keyframes ssai-hero-sweep": {
            from: { transform: "translate(-50%, -50%) rotate(0deg)" },
            to: { transform: "translate(-50%, -50%) rotate(360deg)" },
          },
        }}
      />

      <Paper
        elevation={0}
        sx={{
          width: 400,
          p: 4,
          borderRadius: 3,
          position: "relative",
          bgcolor: "rgba(17, 24, 38, 0.9)",
          backdropFilter: "blur(6px)",
        }}
      >
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          SecureScan AI
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Sign in to continue your security posture review.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box component="form" onSubmit={onSubmit} sx={{ display: "grid", gap: 2 }}>
          <TextField
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            fullWidth
          />
          <TextField
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            fullWidth
          />
          <Button type="submit" variant="contained" size="large" disabled={submitting}>
            {submitting ? "Signing in..." : "Sign in"}
          </Button>
          <Link
            component={RouterLink}
            to="/forgot-password"
            variant="body2"
            sx={{ color: tokens.textMuted, justifySelf: "start" }}
          >
            Forgot your password?
          </Link>
        </Box>

        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          New to SecureScan AI?{" "}
          <Link component={RouterLink} to="/register" sx={{ color: tokens.accent }}>
            Create an account
          </Link>
        </Typography>
      </Paper>
    </Box>
  );
}
