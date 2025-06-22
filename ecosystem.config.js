/**
 * PM2 Ecosystem Configuration for TradeStation Backend
 * This file configures PM2 for production deployment
 */

module.exports = {
  apps: [
    {
      name: 'tradestation-backend',
      script: 'server.js',
      instances: 'max', // Use all CPU cores
      exec_mode: 'cluster',
      env: {
        NODE_ENV: 'development',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      // Restart settings
      max_restarts: 10,
      min_uptime: '10s',
      restart_delay: 4000,
      
      // Memory and CPU limits
      max_memory_restart: '1G',
      
      // Logging
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      
      // Advanced settings
      watch: false, // Set to true for development
      ignore_watch: [
        'node_modules',
        'logs',
        'uploads',
        'backups'
      ],
      
      // Health monitoring
      health_check_grace_period: 3000,
      health_check_fatal_exceptions: true,
      
      // Auto restart on file changes (development only)
      watch_options: {
        followSymlinks: false,
        usePolling: false
      },
      
      // Environment variables
      env_file: '.env',
      
      // Graceful shutdown
      kill_timeout: 5000,
      listen_timeout: 8000,
      
      // Auto restart cron (restart every day at 3 AM)
      cron_restart: '0 3 * * *',
      
      // Merge logs
      merge_logs: true,
      
      // Time zone
      time: true,
      
      // Additional settings for production
      node_args: '--max-old-space-size=1024',
      
      // Source map support
      source_map_support: true,
      
      // Instance variables
      instance_var: 'INSTANCE_ID'
    }
  ],
  
  // Deployment configuration
  deploy: {
    production: {
      user: 'ubuntu',
      host: ['your-server-ip'],
      ref: 'origin/main',
      repo: 'https://github.com/your-username/tradestation-backend.git',
      path: '/var/www/tradestation-backend',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && npm run build && pm2 reload ecosystem.config.js --env production',
      'pre-setup': 'apt update && apt install git -y'
    },
    
    staging: {
      user: 'ubuntu',
      host: ['staging-server-ip'],
      ref: 'origin/develop',
      repo: 'https://github.com/your-username/tradestation-backend.git',
      path: '/var/www/tradestation-staging',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env staging',
      env: {
        NODE_ENV: 'staging',
        PORT: 3001
      }
    }
  },
  
  // Monitoring configuration
  pmx: {
    monitoring: {
      network: true,
      ports: true
    },
    actions: {
      restart: true
    },
    module_conf: {
      heap: {
        alert_threshold: 70.0,
        actions: ['restart']
      },
      event_loop_dump: {
        enable: true,
        filter: {
          type: ['libuv', 'userland']
        }
      }
    }
  }
};
