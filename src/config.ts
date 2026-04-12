import dotenv from 'dotenv';
dotenv.config();

export const CONFIG = {
  PORT:                         parseInt(process.env.PORT || '3001'),
  APP_DIR:                      process.env.APP_DIR || '/root/sharpedge',
  PM2_LOG_DIR:                  process.env.PM2_LOG_DIR || '/root/.pm2/logs',
  AUDIT_LOG_PATH:               process.env.AUDIT_LOG_PATH || '/root/mcp-audit.log',

  // Hard read limits — enforced at server level, not by judgment
  MAX_LOG_LINES:                50,
  MAX_FILE_LINES:               100,
  MAX_OUTPUT_CHARS:             3000,

  // Escape hatch rate limit
  MAX_CUSTOM_COMMANDS_PER_SESSION: 3,

  // Allowed PM2 process names — edit this list to match your setup
  ALLOWED_PROCESSES:            ['sharpedge-api', 'vps-mcp'],
};

// Derived — do not edit directly
export const ALLOWED_READ_DIRS = [CONFIG.APP_DIR, CONFIG.PM2_LOG_DIR];
