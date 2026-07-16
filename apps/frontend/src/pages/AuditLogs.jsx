import { useEffect, useState } from "react";
import {
  Box,
  Chip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { api } from "../api/client";

export default function AuditLogs() {
  const [logs, setLogs] = useState(null);

  useEffect(() => {
    api.get("/audit-logs").then((res) => setLogs(res.data.data));
  }, []);

  return (
    <Box sx={{ display: "grid", gap: 2 }}>
      <Typography variant="h4">Audit Logs</Typography>
      <Typography variant="body2" color="text.secondary">
        Every critical action across your organization, most recent first.
      </Typography>

      <Paper sx={{ p: 1 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Timestamp</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Target</TableCell>
              <TableCell>IP Address</TableCell>
              <TableCell>Result</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(logs || []).map((log) => (
              <TableRow key={log.id} hover>
                <TableCell sx={{ whiteSpace: "nowrap" }}>
                  {new Date(log.timestamp).toLocaleString()}
                </TableCell>
                <TableCell sx={{ textTransform: "capitalize" }}>
                  {log.action.replace(/_/g, " ")}
                </TableCell>
                <TableCell
                  sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: "0.78rem" }}
                >
                  {log.target || "—"}
                </TableCell>
                <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: "0.78rem" }}>
                  {log.ip_address || "—"}
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={log.result}
                    color={log.result === "success" ? "success" : "error"}
                  />
                </TableCell>
              </TableRow>
            ))}
            {logs && logs.length === 0 && (
              <TableRow>
                <TableCell colSpan={5}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                    No audit events recorded yet.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>
    </Box>
  );
}
