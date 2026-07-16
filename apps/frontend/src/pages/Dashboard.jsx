import { useEffect, useMemo, useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import {
  Box,
  Button,
  Grid,
  Link,
  Paper,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { api } from "../api/client";
import { tokens } from "../theme";

function KpiCard({ label, value, accentColor }) {
  return (
    <Paper sx={{ p: 2.5, height: "100%" }}>
      <Typography variant="caption" color="text.secondary" sx={{ letterSpacing: 0.5 }}>
        {label.toUpperCase()}
      </Typography>
      <Typography
        variant="h3"
        sx={{ mt: 0.5, color: accentColor || "text.primary", fontSize: "2rem" }}
      >
        {value}
      </Typography>
    </Paper>
  );
}

export default function Dashboard() {
  const [scans, setScans] = useState(null);
  const [severityCounts, setSeverityCounts] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const res = await api.get("/scans");
      const list = res.data.data;
      if (cancelled) return;
      setScans(list);

      const completed = list
        .filter((s) => s.status === "completed")
        .slice(0, 5);

      const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
      };

      await Promise.all(
        completed.map(async (scan) => {
          const findingsRes = await api.get(`/scans/${scan.id}/findings`);
          findingsRes.data.data.forEach((f) => {
            if (counts[f.severity] !== undefined) counts[f.severity] += 1;
          });
        })
      );

      if (!cancelled) setSeverityCounts(counts);
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const kpis = useMemo(() => {
    if (!scans) return null;
    return {
      total: scans.length,
      running: scans.filter((s) => ["running", "initializing", "queued"].includes(s.status)).length,
      completed: scans.filter((s) => s.status === "completed").length,
      findings: scans.reduce((sum, s) => sum + (s.findings_count || 0), 0),
    };
  }, [scans]);

  const pieData = useMemo(() => {
    if (!severityCounts) return [];
    return Object.entries(severityCounts)
      .filter(([, v]) => v > 0)
      .map(([severity, value]) => ({ name: severity, value }));
  }, [severityCounts]);

  return (
    <Box sx={{ display: "grid", gap: 3 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Box>
          <Typography variant="h4">Dashboard</Typography>
          <Typography variant="body2" color="text.secondary">
            Current security posture across your organization.
          </Typography>
        </Box>
        <Button component={RouterLink} to="/scans/new" variant="contained">
          New Scan
        </Button>
      </Box>

      <Grid container spacing={2}>
        {["Total Scans", "Running", "Completed", "Total Findings"].map((label, i) => (
          <Grid item xs={12} sm={6} md={3} key={label}>
            {kpis ? (
              <KpiCard
                label={label}
                value={[kpis.total, kpis.running, kpis.completed, kpis.findings][i]}
                accentColor={i === 1 ? tokens.accent : undefined}
              />
            ) : (
              <Skeleton variant="rounded" height={92} />
            )}
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={2}>
        <Grid item xs={12} md={5}>
          <Paper sx={{ p: 2.5, height: 320 }}>
            <Typography variant="h6" sx={{ mb: 1 }}>
              Severity Distribution
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Last 5 completed scans
            </Typography>
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                  >
                    {pieData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={tokens.severity[entry.name] || tokens.severity.informational}
                        stroke="none"
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: tokens.panelAlt,
                      border: `1px solid ${tokens.border}`,
                      borderRadius: 8,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <Box
                sx={{
                  height: 220,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Typography variant="body2" color="text.secondary">
                  {scans ? "No findings yet." : "Loading..."}
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        <Grid item xs={12} md={7}>
          <Paper sx={{ p: 2.5, height: 320, overflow: "auto" }}>
            <Typography variant="h6" sx={{ mb: 1.5 }}>
              Recent Activity
            </Typography>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Scan</TableCell>
                  <TableCell>Target</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="right">Findings</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(scans || []).slice(0, 6).map((scan) => (
                  <TableRow key={scan.id} hover>
                    <TableCell>
                      <Link component={RouterLink} to={`/scans/${scan.id}`}>
                        {scan.name}
                      </Link>
                    </TableCell>
                    <TableCell
                      sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: "0.78rem" }}
                    >
                      {scan.target_url}
                    </TableCell>
                    <TableCell sx={{ textTransform: "capitalize" }}>{scan.status}</TableCell>
                    <TableCell align="right">{scan.findings_count}</TableCell>
                  </TableRow>
                ))}
                {scans && scans.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4}>
                      <Typography variant="body2" color="text.secondary">
                        No scans yet. Start your first scan to see activity here.
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}
