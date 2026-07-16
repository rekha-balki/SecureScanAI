import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { api, extractErrorMessage } from "../api/client";
import { useAuth } from "../context/AuthContext";

const ROLES = ["company_admin", "security_analyst", "developer", "auditor"];

const initialForm = {
  first_name: "",
  last_name: "",
  email: "",
  role: "security_analyst",
  password: "",
};

export default function Users() {
  const { user } = useAuth();
  const [users, setUsers] = useState(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(initialForm);
  const [error, setError] = useState("");

  const canManage = ["company_admin", "platform_admin"].includes(user?.role);

  const load = () => api.get("/users").then((res) => setUsers(res.data.data));

  useEffect(() => {
    load();
  }, []);

  const update = (field) => (e) =>
    setForm((prev) => ({ ...prev, [field]: e.target.value }));

  const onCreate = async () => {
    setError("");
    try {
      await api.post("/users", form);
      setOpen(false);
      setForm(initialForm);
      await load();
    } catch (err) {
      setError(extractErrorMessage(err));
    }
  };

  return (
    <Box sx={{ display: "grid", gap: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Typography variant="h4">Users</Typography>
        {canManage && (
          <Button variant="contained" onClick={() => setOpen(true)}>
            Add User
          </Button>
        )}
      </Box>

      <Paper sx={{ p: 1 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Email</TableCell>
              <TableCell>Role</TableCell>
              <TableCell>Status</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(users || []).map((u) => (
              <TableRow key={u.id} hover>
                <TableCell>
                  {u.first_name} {u.last_name}
                </TableCell>
                <TableCell>{u.email}</TableCell>
                <TableCell sx={{ textTransform: "capitalize" }}>
                  {u.role.replace("_", " ")}
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={u.is_active ? "Active" : "Disabled"}
                    color={u.is_active ? "success" : "default"}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>Add User</DialogTitle>
        <DialogContent sx={{ display: "grid", gap: 2, pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label="First name" value={form.first_name} onChange={update("first_name")} fullWidth />
          <TextField label="Last name" value={form.last_name} onChange={update("last_name")} fullWidth />
          <TextField label="Email" type="email" value={form.email} onChange={update("email")} fullWidth />
          <TextField select label="Role" value={form.role} onChange={update("role")} fullWidth>
            {ROLES.map((r) => (
              <MenuItem key={r} value={r} sx={{ textTransform: "capitalize" }}>
                {r.replace("_", " ")}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            label="Temporary password"
            type="password"
            value={form.password}
            onChange={update("password")}
            helperText="At least 12 characters, upper, lower, number, special character."
            fullWidth
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={onCreate}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
