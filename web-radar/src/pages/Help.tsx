import { useState } from 'react';
import { HelpCircle, Info } from 'lucide-react';
import {
  Container,
  Typography,
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Button as MuiButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
} from '@mui/material';

function HelpPage() {
  const [aboutOpen, setAboutOpen] = useState(false);

  return (
    <Container maxWidth="xl">
      <Typography variant="h4" component="h1" gutterBottom sx={{ color: 'text.primary' }}>
        Help & Info
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 4 }}>
        Get help with using GhostLink
      </Typography>

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mb: 3 }}>
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <HelpCircle size={24} color="#00BCD4" />
            <Typography variant="h6" color="text.primary">Quick Start</Typography>
          </Box>
          <Accordion>
            <AccordionSummary>
              <Typography color="text.primary">How to scan for Wi‑Fi networks?</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography color="text.secondary">
                Go to the Scan page, click on Scan Networks, and select a target network.
                Make sure you have appropriate permissions.
              </Typography>
            </AccordionDetails>
          </Accordion>
          <Accordion>
            <AccordionSummary>
              <Typography color="text.primary">How to start an attack?</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography color="text.secondary">
                Select a target network, go to the Attack page, configure your settings,
                and click Start Attack.
              </Typography>
            </AccordionDetails>
          </Accordion>
          <Accordion>
            <AccordionSummary>
              <Typography color="text.primary">What are the attack profiles?</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography color="text.secondary">
                Preconfigured character sets for different scenarios: Numeric PINs (digits),
                Lowercase, Lower+Numeric, Alphanumeric, and Full Charset.
              </Typography>
            </AccordionDetails>
          </Accordion>
          <Accordion>
            <AccordionSummary>
              <Typography color="text.primary">Frequently Asked Questions (FAQ)</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography color="text.secondary">
                Always make sure you have explicit, written permission before testing any
                network that you don't own or operate.
              </Typography>
            </AccordionDetails>
          </Accordion>
        </Paper>

        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Info size={24} color="text.secondary" />
              <Typography variant="h6" color="text.primary">About GhostLink</Typography>
            </Box>
            <MuiButton variant="contained" onClick={() => setAboutOpen(true)}>
              Show About
            </MuiButton>
          </Box>
        </Paper>
      </Box>

      {/* About Dialog */}
      <Dialog open={aboutOpen} onClose={() => setAboutOpen(false)}>
        <DialogTitle>About GhostLink</DialogTitle>
        <DialogContent sx={{ textAlign: 'center', py: 3 }}>
          <Typography variant="h4" sx={{ fontWeight: 'bold', mb: 1, color: 'text.primary' }}>
            GhostLink
          </Typography>
          <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 1 }}>
            Version 1.0.0
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Wi‑Fi Security Testing Framework
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Developed for educational purposes and authorized security testing only.
          </Typography>
        </DialogContent>
        <DialogActions>
          <MuiButton onClick={() => setAboutOpen(false)}>Close</MuiButton>
        </DialogActions>
      </Dialog>
    </Container>
  );
}

export default HelpPage;
