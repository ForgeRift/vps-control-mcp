module.exports = {
  apps: [
    {
      name:          'vps-mcp',
      script:        'dist/index.js',
      node_args:     '--experimental-specifier-resolution=node',
      env: {
        NODE_ENV: 'production',
      },
      watch:         false,
      autorestart:   true,
      max_restarts:  10,
      min_uptime:    '10s',
      restart_delay: 3000,
      // Give the SIGTERM handler and in-flight requests time to finish before
      // PM2 sends SIGKILL. Default is 1600ms which is too short. 8 seconds
      // allows clients to get their stale-session SSE restore on reconnect.
      kill_timeout:  8000,
    },
  ],
};
