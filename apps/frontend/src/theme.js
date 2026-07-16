import { createTheme } from "@mui/material/styles";

// ---------------------------------------------------------------------
// Design tokens
// Palette: deep-space slate with a single "radar teal" signature accent.
// Type: Space Grotesk (display) / Inter (UI) / JetBrains Mono (evidence,
// URLs, technical data - anything a security analyst needs to read
// character-for-character).
// ---------------------------------------------------------------------

export const tokens = {
  bg: "#0A0F1A",
  panel: "#111826",
  panelAlt: "#161F30",
  border: "#232D40",
  textPrimary: "#E7ECF5",
  textMuted: "#8B96A8",
  accent: "#22D3A6",
  accentDim: "#173B34",
  severity: {
    critical: "#F0475C",
    high: "#FF8A3D",
    medium: "#F5C242",
    low: "#4E9CFF",
    informational: "#7C8797",
  },
};

export const theme = createTheme({
  palette: {
    mode: "dark",
    background: {
      default: tokens.bg,
      paper: tokens.panel,
    },
    primary: {
      main: tokens.accent,
      contrastText: "#04120E",
    },
    text: {
      primary: tokens.textPrimary,
      secondary: tokens.textMuted,
    },
    divider: tokens.border,
  },
  typography: {
    fontFamily: '"Inter", system-ui, sans-serif',
    h1: { fontFamily: '"Space Grotesk", sans-serif', fontWeight: 700 },
    h2: { fontFamily: '"Space Grotesk", sans-serif', fontWeight: 700 },
    h3: { fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600 },
    h4: { fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600 },
    h5: { fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600 },
    h6: { fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600 },
    button: { textTransform: "none", fontWeight: 600 },
  },
  shape: { borderRadius: 10 },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          border: `1px solid ${tokens.border}`,
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: { borderRadius: 8 },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: { borderColor: tokens.border },
      },
    },
  },
});

export const mono = '"JetBrains Mono", ui-monospace, monospace';
