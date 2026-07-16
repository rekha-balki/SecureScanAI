import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Box,
  Button,
  Chip,
  LinearProgress,
  MenuItem,
  Paper,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  Typography,
} from "@mui/material";
import DownloadIcon from "@mui/icons-material/DownloadOutlined";
import ReplayIcon from "@mui/icons-material/ReplayOutlined";
import DeleteIcon from "@mui/icons-material/DeleteOutlined";
import { api } from "../api/client";
import SeverityBadge from "../components/SeverityBadge";

const IN_PROGRESS = ["queued", "initializing", "running"];
const DELETABLE = ["completed", "cancelled"];
const mono = { fontFamily: '"JetBrains Mono", monospace' };

export default function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [tab, setTab] = useState("findings");
  const intervalRef = useRef(null);

  const loadScan = async () => {
    const res = await api.get(`/scans/${scanId}`);
    setScan(res.data.data);
    return res.data.data;
  };

  const loadFindings = async () => {
    const res = await api.get(`/scans/${scanId}/findings`);
    setFindings(res.data.data);
  };

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      const current = await loadScan();
      if (!cancelled && !IN_PROGRESS.includes(current.status)) {
        await loadFindings();
      }
    }

    tick();
    intervalRef.current = setInterval(async () => {
      const current = await loadScan();
      if (IN_PROGRESS.includes(current.status)) return;
      await loadFindings();
      clearInterval(intervalRef.current);
    }, 3000);

    return () => {
      cancelled = true;
      clearInterval(intervalRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const downloadFile = async (path, filename) => {
    const res = await api.get(path, { responseType: "blob" });
    const url = window.URL.createObjectURL(new Blob([res.data]));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const onRerun = async () => {
    const res = await api.post(`/scans/${scanId}/rerun`);
    navigate(`/scans/${res.data.data.id}`);
  };

  const onDelete = async () => {
    await api.delete(`/scans/${scanId}`);
    navigate("/scans");
  };

  if (!scan) return null;

  const running = IN_PROGRESS.includes(scan.status);

  return (
    <Box sx={{ display: "grid", gap: 3 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <Box>
          <Typography variant="h4">{scan.name}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ ...mono, mt: 0.5 }}>
            {scan.target_url}
          </Typography>
        </Box>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
          <Chip label={scan.status.replace("_", " ")} sx={{ textTransform: "capitalize" }} />
          {scan.has_auth && <Chip label="Authenticated" color="info" size="small" />}
          <Button variant="outlined" startIcon={<ReplayIcon />} onClick={onRerun}>
            Re-run
          </Button>
          <Button
            variant="outlined"
            color="error"
            startIcon={<DeleteIcon />}
            onClick={onDelete}
            disabled={!DELETABLE.includes(scan.status)}
          >
            Delete
          </Button>
        </Box>
      </Box>

      {running && (
        <Paper sx={{ p: 2.5 }}>
          <Typography variant="body2" sx={{ mb: 1 }}>
            Scan in progress&hellip; pages crawled: {scan.pages_crawled}
          </Typography>
          <LinearProgress />
        </Paper>
      )}

      {scan.status === "failed" && scan.error_message && (
        <Paper sx={{ p: 2.5, borderColor: "error.main" }}>
          <Typography variant="body2" color="error">
            {scan.error_message}
          </Typography>
        </Paper>
      )}

      <Paper sx={{ p: 1 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ px: 1 }}>
          <Tab value="findings" label={`Findings ${findings.length ? `(${findings.length})` : ""}`} />
          {scan.scan_type === "web" && <Tab value="attack-surface" label="Attack Surface" />}
          {scan.scan_type === "api" && <Tab value="dpdp" label="DPDP Mapping" />}
          <Tab value="compliance" label="Compliance" />
          <Tab value="compare" label="Compare" />
        </Tabs>

        <Box sx={{ p: 2 }}>
          {tab === "findings" && (
            <FindingsTab scan={scan} findings={findings} running={running} downloadFile={downloadFile} />
          )}
          {tab === "attack-surface" && scan.scan_type === "web" && <AttackSurfaceTab scanId={scanId} />}
          {tab === "dpdp" && scan.scan_type === "api" && <DpdpTab scanId={scanId} />}
          {tab === "compliance" && <ComplianceTab scanId={scanId} />}
          {tab === "compare" && <CompareTab scanId={scanId} targetUrl={scan.target_url} />}
        </Box>
      </Paper>
    </Box>
  );
}

function FindingsTab({ scan, findings, running, downloadFile }) {
  return (
    <Box sx={{ display: "grid", gap: 2 }}>
      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
        <Button
          size="small"
          variant="outlined"
          startIcon={<DownloadIcon />}
          onClick={() => downloadFile(`/scans/${scan.id}/report`, `securescan-report-${scan.id}.pdf`)}
          disabled={scan.status !== "completed"}
        >
          PDF Report
        </Button>
        <Button
          size="small"
          variant="outlined"
          startIcon={<DownloadIcon />}
          onClick={() => downloadFile(`/scans/${scan.id}/export/json`, `securescan-${scan.id}.json`)}
          disabled={scan.status !== "completed"}
        >
          Export JSON
        </Button>
        <Button
          size="small"
          variant="outlined"
          startIcon={<DownloadIcon />}
          onClick={() => downloadFile(`/scans/${scan.id}/export/excel`, `securescan-${scan.id}.xlsx`)}
          disabled={scan.status !== "completed"}
        >
          Export Excel
        </Button>
      </Box>

      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Severity</TableCell>
            <TableCell>CVSS (est.)</TableCell>
            <TableCell>Category</TableCell>
            <TableCell>Description</TableCell>
            <TableCell>Affected URL</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {findings.map((f) => (
            <TableRow key={f.id} hover>
              <TableCell>
                <SeverityBadge severity={f.severity} />
              </TableCell>
              <TableCell sx={mono}>{f.cvss_score ?? "—"}</TableCell>
              <TableCell>{f.category}</TableCell>
              <TableCell sx={{ maxWidth: 340 }}>{f.description}</TableCell>
              <TableCell sx={{ ...mono, fontSize: "0.75rem" }}>{f.affected_url}</TableCell>
            </TableRow>
          ))}
          {!running && findings.length === 0 && (
            <TableRow>
              <TableCell colSpan={5}>
                <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                  No findings for this scan.
                </Typography>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </Box>
  );
}

function AttackSurfaceTab({ scanId }) {
  const [surface, setSurface] = useState(null);

  useEffect(() => {
    api.get(`/scans/${scanId}/attack-surface`).then((res) => setSurface(res.data.data));
  }, [scanId]);

  if (!surface) return null;

  return (
    <Box sx={{ display: "grid", gap: 3 }}>
      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Discovered URLs ({surface.urls.length})
        </Typography>
        <Box sx={{ maxHeight: 220, overflow: "auto" }}>
          {surface.urls.map((u, i) => (
            <Typography key={i} variant="body2" sx={{ ...mono, fontSize: "0.78rem" }}>
              [{u.status_code}] {u.url}
            </Typography>
          ))}
          {surface.urls.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No URLs recorded.
            </Typography>
          )}
        </Box>
      </Box>

      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Query Parameters ({surface.parameters.length})
        </Typography>
        <Box sx={{ maxHeight: 200, overflow: "auto" }}>
          {surface.parameters.map((p, i) => (
            <Typography key={i} variant="body2" sx={{ ...mono, fontSize: "0.78rem" }}>
              {p.name} — {p.path}
            </Typography>
          ))}
          {surface.parameters.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No query parameters discovered.
            </Typography>
          )}
        </Box>
      </Box>

      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Forms ({surface.forms.length})
        </Typography>
        <Box sx={{ maxHeight: 220, overflow: "auto" }}>
          {surface.forms.map((f, i) => (
            <Typography key={i} variant="body2" sx={{ ...mono, fontSize: "0.78rem" }}>
              [{f.method}] {f.action_url} — fields: {f.fields.join(", ") || "none"}
            </Typography>
          ))}
          {surface.forms.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No forms discovered.
            </Typography>
          )}
        </Box>
      </Box>
    </Box>
  );
}

function ComplianceTab({ scanId }) {
  const [report, setReport] = useState(null);

  useEffect(() => {
    api.get(`/scans/${scanId}/compliance-mapping`).then((res) => setReport(res.data.data));
  }, [scanId]);

  if (!report) return null;

  const frameworks = Object.entries(report.frameworks || {});

  return (
    <Box sx={{ display: "grid", gap: 2 }}>
      <Typography variant="caption" color="text.secondary">
        {report.disclaimer}
      </Typography>

      {frameworks.map(([framework, controls]) => (
        <Box key={framework}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            {framework}
          </Typography>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Control</TableCell>
                <TableCell>Description</TableCell>
                <TableCell align="right">Findings</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {controls.map((c) => (
                <TableRow key={c.control_id}>
                  <TableCell sx={mono}>{c.control_id}</TableCell>
                  <TableCell>{c.control_name}</TableCell>
                  <TableCell align="right">{c.finding_count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Box>
      ))}

      {frameworks.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          No findings map to a known compliance control yet.
        </Typography>
      )}
    </Box>
  );
}

function DpdpTab({ scanId }) {
  const [report, setReport] = useState(null);

  useEffect(() => {
    api.get(`/scans/${scanId}/dpdp-mapping`).then((res) => setReport(res.data.data));
  }, [scanId]);

  if (!report) return null;

  return (
    <Box sx={{ display: "grid", gap: 2 }}>
      <Typography variant="caption" color="text.secondary">
        {report.disclaimer}
      </Typography>

      {report.personal_data_finding_ids.length > 0 && (
        <Chip
          label={`${report.personal_data_finding_ids.length} finding(s) involve personal-data patterns`}
          color="error"
          size="small"
          sx={{ justifySelf: "start" }}
        />
      )}

      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Section</TableCell>
            <TableCell>Description</TableCell>
            <TableCell align="right">Findings</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {report.sections.map((s) => (
            <TableRow key={s.section}>
              <TableCell sx={mono}>{s.section}</TableCell>
              <TableCell>{s.description}</TableCell>
              <TableCell align="right">{s.finding_count}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {report.sections.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          No findings map to a DPDP provision yet.
        </Typography>
      )}
    </Box>
  );
}

function CompareTab({ scanId, targetUrl }) {
  const [priorScans, setPriorScans] = useState([]);
  const [baselineId, setBaselineId] = useState("");
  const [diff, setDiff] = useState(null);

  useEffect(() => {
    api.get("/scans").then((res) => {
      const candidates = res.data.data.filter(
        (s) => s.target_url === targetUrl && s.id !== scanId && s.status === "completed"
      );
      setPriorScans(candidates);
    });
  }, [scanId, targetUrl]);

  const runCompare = async (id) => {
    setBaselineId(id);
    if (!id) {
      setDiff(null);
      return;
    }
    const res = await api.get(`/scans/${scanId}/compare/${id}`);
    setDiff(res.data.data);
  };

  return (
    <Box sx={{ display: "grid", gap: 2 }}>
      <TextField
        select
        label="Compare against"
        value={baselineId}
        onChange={(e) => runCompare(e.target.value)}
        sx={{ maxWidth: 360 }}
      >
        <MenuItem value="">Select a prior scan of this target</MenuItem>
        {priorScans.map((s) => (
          <MenuItem key={s.id} value={s.id}>
            {s.name} — {new Date(s.created_at).toLocaleString()}
          </MenuItem>
        ))}
      </TextField>

      {priorScans.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          No other completed scans of this same target yet to compare against.
        </Typography>
      )}

      {diff && (
        <Box sx={{ display: "grid", gap: 2 }}>
          <Box sx={{ display: "flex", gap: 2 }}>
            <Chip label={`${diff.new_count} new`} color="error" size="small" />
            <Chip label={`${diff.fixed_count} fixed`} color="success" size="small" />
            <Chip label={`${diff.persistent_count} persistent`} size="small" />
          </Box>

          {["new", "fixed", "persistent"].map((bucket) =>
            diff[bucket].length > 0 ? (
              <Box key={bucket}>
                <Typography variant="subtitle2" sx={{ mb: 1, textTransform: "capitalize" }}>
                  {bucket} ({diff[bucket].length})
                </Typography>
                {diff[bucket].map((f) => (
                  <Box key={f.id} sx={{ display: "flex", gap: 1, alignItems: "center", mb: 0.5 }}>
                    <SeverityBadge severity={f.severity} />
                    <Typography variant="body2">{f.description}</Typography>
                  </Box>
                ))}
              </Box>
            ) : null
          )}
        </Box>
      )}
    </Box>
  );
}
