import { Paper, Typography, Box } from '@mui/material';
import type { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  icon?: LucideIcon;
  color?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label, value, icon: Icon, color }) => {
  return (
    <Paper sx={{ p: 3, borderRadius: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        {Icon && <Icon size={32} color={color} />}
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            {label}
          </Typography>
          <Typography variant="h4" component="div">
            {value}
          </Typography>
        </Box>
      </Box>
    </Paper>
  );
};