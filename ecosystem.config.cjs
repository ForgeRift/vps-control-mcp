module.exports = {
  apps: [
    {
      name:         'vps-mcp',
      script:       'dist/index.js',
      cwd:          '/root/vps-control-mcp',
      node_args:    '--experimental-specifier-resolution=node',
      env: {
        NODE_ENV: 'production',
      },
      error_file:   '/root/.pm2/logs/vps-mcp-error.log',
      out_file:     '/root/.pm2/logs/vps-mcp-out.log',
      watch:        false,
      autorestart:  true,
      max_restarts: 10,
      min_uptime:   '10s',
      restart_delay: 3000,
    },
  ],
};
