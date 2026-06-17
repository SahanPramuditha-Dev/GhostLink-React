import { Box, Typography } from '@mui/material';
import type { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  message: string;
  subMessage?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon, message, subMessage }) => {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', py: 8 }}>
      <Icon size={64} color="rgba(255,255,255,0.3)" />
      <Typography variant="h6" sx={{ mt: 2 }}>
        {message}
      </Typography>
      {subMessage && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          {subMessage}
        </Typography>
      )}
    </Box>
  );
};