module.exports = {
  apps: [
    {
      name:         'vps-mcp',
      script:       'dist/index.js',
      node_args:    '--experimental-specifier-resolution=node',
      env: {
        NODE_ENV: 'production',
      },
      watch:        false,
      autorestart:  true,
      max_restarts: 10,
      min_uptime:   '10s',
      restart_delay: 3000,
    },
  ],
};
