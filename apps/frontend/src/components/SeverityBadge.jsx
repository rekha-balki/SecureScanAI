import { Chip } from "@mui/material";
import { tokens } from "../theme";

export default function SeverityBadge({ severity }) {
  const color = tokens.severity[severity] || tokens.severity.informational;

  return (
    <Chip
      label={severity?.toUpperCase()}
      size="small"
      sx={{
        bgcolor: `${color}22`,
        color,
        fontWeight: 700,
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: "0.7rem",
        letterSpacing: 0.5,
        border: `1px solid ${color}55`,
      }}
    />
  );
}
