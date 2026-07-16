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

const initialForm = {
  first_name: "",
  last_name: "",
  email: "",
  password: "",
  company_name: "",
  mobile_number: "",
};

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState(initialForm);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const update = (field) => (e) =>
    setForm((prev) => ({ ...prev, [field]: e.target.value }));

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    const result = await register(form);
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
        px: 2,
        py: 4,
      }}
    >
      <Paper elevation={0} sx={{ width: 460, p: 4, borderRadius: 3 }}>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          Create your workspace
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          The first user in a new company becomes the Company Administrator.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box component="form" onSubmit={onSubmit} sx={{ display: "grid", gap: 2 }}>
          <Box sx={{ display: "flex", gap: 2 }}>
            <TextField
              label="First name"
              value={form.first_name}
              onChange={update("first_name")}
              required
              fullWidth
            />
            <TextField
              label="Last name"
              value={form.last_name}
              onChange={update("last_name")}
              required
              fullWidth
            />
          </Box>
          <TextField
            label="Company name"
            value={form.company_name}
            onChange={update("company_name")}
            required
            fullWidth
          />
          <TextField
            label="Email"
            type="email"
            value={form.email}
            onChange={update("email")}
            required
            fullWidth
          />
          <TextField
            label="Password"
            type="password"
            value={form.password}
            onChange={update("password")}
            helperText="At least 12 characters, with upper, lower, number, and a special character."
            required
            fullWidth
          />
          <TextField
            label="Mobile number (optional)"
            value={form.mobile_number}
            onChange={update("mobile_number")}
            fullWidth
          />
          <Button type="submit" variant="contained" size="large" disabled={submitting}>
            {submitting ? "Creating account..." : "Create account"}
          </Button>
        </Box>

        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          Already have an account?{" "}
          <Link component={RouterLink} to="/login" sx={{ color: tokens.accent }}>
            Sign in
          </Link>
        </Typography>
      </Paper>
    </Box>
  );
}
