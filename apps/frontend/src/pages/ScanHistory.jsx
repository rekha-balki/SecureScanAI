import { useEffect, useState } from "react";
import { Link as RouterLink, useNavigate } from "react-router-dom";
import {
  Box,
  Button,
  Chip,
  IconButton,
  Link,
  Menu,
  MenuItem,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import MoreVertIcon from "@mui/icons-material/MoreVertOutlined";
import { api } from "../api/client";

const STATUS_COLORS = {
  completed: "success",
  running: "info",
  queued: "default",
  initializing: "info",
  failed: "error",
  cancelled: "default",
  timed_out: "warning",
  paused: "warning",
};

const DELETABLE = ["completed", "cancelled"];

export default function ScanHistory() {
  const navigate = useNavigate();
  const [scans, setScans] = useState(null);
  const [menuAnchor, setMenuAnchor] = useState(null);
  const [menuScan, setMenuScan] = useState(null);

  const load = () => api.get("/scans").then((res) => setScans(res.data.data));

  useEffect(() => {
    load();
  }, []);

  const openMenu = (e, scan) => {
    setMenuAnchor(e.currentTarget);
    setMenuScan(scan);
  };

  const closeMenu = () => {
    setMenuAnchor(null);
    setMenuScan(null);
  };

  const onDelete = async () => {
    await api.delete(`/scans/${menuScan.id}`);
    closeMenu();
    load();
  };

  const onRerun = async () => {
    const res = await api.post(`/scans/${menuScan.id}/rerun`);
    closeMenu();
    navigate(`/scans/${res.data.data.id}`);
  };

  return (
    <Box sx={{ display: "grid", gap: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Typography variant="h4">Scan History</Typography>
        <Button component={RouterLink} to="/scans/new" variant="contained">
          New Scan
        </Button>
      </Box>

      <Paper sx={{ p: 1 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Target</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Pages</TableCell>
              <TableCell align="right">Findings</TableCell>
              <TableCell>Created</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(scans || []).map((scan) => (
              <TableRow key={scan.id} hover>
                <TableCell>
                  <Link component={RouterLink} to={`/scans/${scan.id}`}>
                    {scan.name}
                  </Link>
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    variant="outlined"
                    label={scan.scan_type === "api" ? "API" : "Web"}
                  />
                </TableCell>
                <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: "0.78rem" }}>
                  {scan.target_url}
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={scan.status.replace("_", " ")}
                    color={STATUS_COLORS[scan.status] || "default"}
                    sx={{ textTransform: "capitalize" }}
                  />
                </TableCell>
                <TableCell align="right">{scan.pages_crawled}</TableCell>
                <TableCell align="right">{scan.findings_count}</TableCell>
                <TableCell>{new Date(scan.created_at).toLocaleString()}</TableCell>
                <TableCell align="right">
                  <IconButton size="small" onClick={(e) => openMenu(e, scan)}>
                    <MoreVertIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
            {scans && scans.length === 0 && (
              <TableRow>
                <TableCell colSpan={8}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                    No scans yet.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      <Menu anchorEl={menuAnchor} open={Boolean(menuAnchor)} onClose={closeMenu}>
        <MenuItem onClick={onRerun}>Re-run</MenuItem>
        <MenuItem
          onClick={onDelete}
          disabled={menuScan && !DELETABLE.includes(menuScan.status)}
        >
          Delete
        </MenuItem>
      </Menu>
    </Box>
  );
}
