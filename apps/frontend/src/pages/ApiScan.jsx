import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Chip,
  Paper,
  TextField,
  Typography,
} from "@mui/material";
import { api, extractErrorMessage } from "../api/client";
import { tokens } from "../theme";

const PLACEHOLDER = `curl 'https://api.example.com/v1/users/42' \\
  -H 'Authorization: Bearer eyJhbGciOi...' \\
  -H 'Content-Type: application/json'`;

export default function ApiScan() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [curlCommand, setCurlCommand] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const res = await api.post("/scans", {
        name: name || "API Scan",
        scan_type: "api",
        curl_command: curlCommand,
      });
      navigate(`/scans/${res.data.data.id}`);
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 720, display: "grid", gap: 3 }}>
      <Box>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          API Scan
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Paste a curl command (copied from your browser's DevTools, Postman, or
          written by hand). We'll execute it once, run a set of security checks
          against the response, and map anything relevant to India's DPDP Act.
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
            label="Scan name (optional)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Get User Profile endpoint"
            fullWidth
          />
          <TextField
            label="curl command"
            value={curlCommand}
            onChange={(e) => setCurlCommand(e.target.value)}
            placeholder={PLACEHOLDER}
            required
            fullWidth
            multiline
            minRows={6}
            sx={{
              "& textarea": {
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: "0.85rem",
              },
            }}
          />
          <Typography variant="caption" color="text.secondary">
            Supports -X, -H, -d/--data/--data-raw, -u, -b/--cookie, -G, --url,
            and a bare URL. Credentials in the command are stored with the scan
            so we can replay the request - only scan endpoints you're
            authorized to test.
          </Typography>

          <Button type="submit" variant="contained" size="large" disabled={submitting}>
            {submitting ? "Running scan..." : "Run API Scan"}
          </Button>
        </Box>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          What gets checked
        </Typography>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 2 }}>
          {[
            "Transport security (HTTPS/HSTS)",
            "Security headers",
            "Sensitive data exposure",
            "DPDP personal-data patterns",
            "Passive JWT inspection",
            "Verbose error disclosure",
            "CORS misconfiguration",
            "Risky HTTP methods",
            "Broken auth enforcement",
          ].map((label) => (
            <Chip key={label} label={label} size="small" sx={{ bgcolor: tokens.panelAlt }} />
          ))}
        </Box>
        <Typography variant="caption" color="text.secondary">
          This executes your request once, plus a small number of variants
          (e.g. the same request with credentials stripped, an OPTIONS probe,
          and a CORS probe with a test Origin header) - it does not fuzz
          parameters or send a high volume of traffic to the endpoint.
        </Typography>
      </Paper>
    </Box>
  );
}
